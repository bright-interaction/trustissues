package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

const privateSocketMode = 0o600

// listenPrivateSocket creates the application-owned private ingress. Merely
// reaching this listener is the transport admission signal, so its filesystem
// boundary is intentionally stricter than an ordinary local backend socket:
// the containing directory must be owned by this process and may not be
// writable by group or other users, and the socket itself is always 0600.
//
// An old socket left by a crash is removed only after proving all of the
// following: it is actually a socket (not a symlink or regular file), it is
// owned by this process's effective uid, and a stream connect fails with
// ECONNREFUSED. A live, foreign, or ambiguous socket is never unlinked.
func listenPrivateSocket(path string) (*net.UnixListener, error) {
	if path == "" {
		return nil, errors.New("private socket path is empty")
	}
	if err := validatePrivateSocketParent(filepath.Dir(path)); err != nil {
		return nil, err
	}

	if err := removeStalePrivateSocket(path); err != nil {
		return nil, err
	}

	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, fmt.Errorf("listen on private socket %q: %w", path, err)
	}
	// Be explicit even though ListenUnix listeners currently unlink on close by
	// default. Leaving a socket behind on an orderly deploy makes the next boot
	// depend on stale-socket recovery and obscures whether the prior exit was
	// clean.
	listener.SetUnlinkOnClose(true)

	if err := os.Chmod(path, privateSocketMode); err != nil {
		_ = listener.Close()
		return nil, fmt.Errorf("set private socket %q permissions to %04o: %w", path, privateSocketMode, err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		_ = listener.Close()
		return nil, fmt.Errorf("verify private socket %q: %w", path, err)
	}
	if info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != privateSocketMode {
		_ = listener.Close()
		return nil, fmt.Errorf("private socket %q has unsafe mode %v (want socket %04o)", path, info.Mode(), privateSocketMode)
	}
	return listener, nil
}

func validatePrivateSocketParent(dir string) error {
	dir = filepath.Clean(dir)
	if err := validatePrivateSocketSpelledAncestors(dir); err != nil {
		return err
	}
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return fmt.Errorf("resolve private socket directory %q: %w", dir, err)
	}
	dir = filepath.Clean(resolved)
	for current := dir; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil {
			return fmt.Errorf("inspect private socket directory ancestor %q: %w", current, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("private socket directory ancestor %q is a symlink", current)
		}
		if !info.IsDir() {
			return fmt.Errorf("private socket directory ancestor %q is not a directory", current)
		}

		if current == dir {
			// The connector and application meet in this directory. It must be
			// controlled by the application uid, not merely protected by a sticky
			// ancestor such as /tmp.
			if info.Mode().Perm()&0o022 != 0 {
				return fmt.Errorf("private socket directory %q is writable by group or other users (mode %04o)", dir, info.Mode().Perm())
			}
			uid, ok := fileOwnerUID(info)
			if !ok {
				return fmt.Errorf("cannot verify owner of private socket directory %q", dir)
			}
			if uid != uint32(os.Geteuid()) {
				return fmt.Errorf("private socket directory %q is owned by uid %d, want process uid %d", dir, uid, os.Geteuid())
			}
		} else if info.Mode().Perm()&0o022 != 0 && info.Mode()&os.ModeSticky == 0 {
			// A writable non-sticky ancestor lets another principal rename or
			// replace the checked subtree after validation. Sticky shared roots
			// such as /tmp remain usable; their unlink/rename rules protect a
			// child directory owned by this uid.
			return fmt.Errorf("private socket directory ancestor %q is writable by group or other users without the sticky bit (mode %04o)",
				current, info.Mode().Perm())
		}

		parent := filepath.Dir(current)
		if parent == current {
			return nil
		}
	}
}

// validatePrivateSocketSpelledAncestors checks the path as configured before
// EvalSymlinks canonicalizes it. macOS commonly spells /private/tmp as /tmp and
// Linux commonly spells /run as /var/run, so rejecting every symlink would make
// safe standard locations unusable. A symlink is accepted only when it belongs
// to root or this process and its containing chain is not replaceable through a
// writable non-sticky directory. The resolved target is validated separately
// above, including the strict ownership/mode rule on the actual leaf directory.
func validatePrivateSocketSpelledAncestors(dir string) error {
	for current := dir; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil {
			return fmt.Errorf("inspect configured private socket directory ancestor %q: %w", current, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			uid, ok := fileOwnerUID(info)
			if !ok {
				return fmt.Errorf("cannot verify owner of private socket directory symlink %q", current)
			}
			if uid != 0 && uid != uint32(os.Geteuid()) {
				return fmt.Errorf("private socket directory symlink %q is owned by uid %d, want root or process uid %d",
					current, uid, os.Geteuid())
			}
		} else {
			if !info.IsDir() {
				return fmt.Errorf("configured private socket directory ancestor %q is not a directory", current)
			}
			if current != dir && info.Mode().Perm()&0o022 != 0 && info.Mode()&os.ModeSticky == 0 {
				return fmt.Errorf("configured private socket directory ancestor %q is writable by group or other users without the sticky bit (mode %04o)",
					current, info.Mode().Perm())
			}
		}
		parent := filepath.Dir(current)
		if parent == current {
			return nil
		}
	}
}

func removeStalePrivateSocket(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect private socket %q: %w", path, err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("private socket path %q already exists and is not a Unix socket; refusing to replace it", path)
	}
	uid, ok := fileOwnerUID(info)
	if !ok {
		return fmt.Errorf("cannot verify owner of existing private socket %q", path)
	}
	if uid != uint32(os.Geteuid()) {
		return fmt.Errorf("existing private socket %q is owned by uid %d, want process uid %d; refusing to remove it", path, uid, os.Geteuid())
	}

	conn, dialErr := net.DialTimeout("unix", path, 250*time.Millisecond)
	if dialErr == nil {
		_ = conn.Close()
		return fmt.Errorf("private socket %q is already accepting connections; another instance may be running", path)
	}
	if errors.Is(dialErr, os.ErrNotExist) {
		// The path disappeared between Lstat and Dial. Let ListenUnix own the
		// final create decision rather than turning this benign race into a boot
		// failure.
		return nil
	}
	if !errors.Is(dialErr, syscall.ECONNREFUSED) {
		return fmt.Errorf("cannot prove existing private socket %q is stale (%v); refusing to remove it", path, dialErr)
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove stale private socket %q: %w", path, err)
	}
	return nil
}

func fileOwnerUID(info os.FileInfo) (uint32, bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return stat.Uid, true
}
