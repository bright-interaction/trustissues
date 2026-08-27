package main

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestPrivateSocketIsUserOnlyAndRemovedOnClose(t *testing.T) {
	path := filepath.Join(shortSocketTestDir(t), "private.sock")
	listener, err := listenPrivateSocket(path)
	if err != nil {
		skipIfUnixSocketDenied(t, err)
		t.Fatalf("listenPrivateSocket: %v", err)
	}

	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("lstat socket: %v", err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("mode = %v, want Unix socket", info.Mode())
	}
	if got := info.Mode().Perm(); got != privateSocketMode {
		t.Fatalf("socket mode = %04o, want %04o", got, privateSocketMode)
	}

	if err := listener.Close(); err != nil {
		t.Fatalf("close listener: %v", err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("socket remains after close: %v", err)
	}
}

func TestPrivateSocketRefusesToReplaceNonSocket(t *testing.T) {
	path := filepath.Join(shortSocketTestDir(t), "private.sock")
	if err := os.WriteFile(path, []byte("do not overwrite"), 0o600); err != nil {
		t.Fatalf("create sentinel: %v", err)
	}

	_, err := listenPrivateSocket(path)
	if err == nil || !strings.Contains(err.Error(), "refusing to replace") {
		t.Fatalf("listenPrivateSocket error = %v, want non-socket refusal", err)
	}
	got, readErr := os.ReadFile(path)
	if readErr != nil || string(got) != "do not overwrite" {
		t.Fatalf("sentinel changed: body=%q err=%v", got, readErr)
	}
}

func TestPrivateSocketRefusesLiveListener(t *testing.T) {
	path := filepath.Join(shortSocketTestDir(t), "private.sock")
	listener, err := listenPrivateSocket(path)
	if err != nil {
		skipIfUnixSocketDenied(t, err)
		t.Fatalf("first listen: %v", err)
	}
	defer listener.Close()

	_, err = listenPrivateSocket(path)
	if err == nil || !strings.Contains(err.Error(), "already accepting connections") {
		t.Fatalf("second listen error = %v, want live-listener refusal", err)
	}
}

func TestPrivateSocketRecoversOwnedStaleSocket(t *testing.T) {
	path := filepath.Join(shortSocketTestDir(t), "private.sock")
	stale, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		skipIfUnixSocketDenied(t, err)
		t.Fatalf("create stale listener: %v", err)
	}
	stale.SetUnlinkOnClose(false)
	if err := stale.Close(); err != nil {
		t.Fatalf("close stale listener: %v", err)
	}

	listener, err := listenPrivateSocket(path)
	if err != nil {
		t.Fatalf("recover stale socket: %v", err)
	}
	listener.Close()
}

func TestPrivateSocketRefusesWritableParentDirectory(t *testing.T) {
	dir := shortSocketTestDir(t)
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatalf("chmod temp dir: %v", err)
	}
	defer os.Chmod(dir, 0o700)

	_, err := listenPrivateSocket(filepath.Join(dir, "private.sock"))
	if err == nil || !strings.Contains(err.Error(), "writable by group or other") {
		t.Fatalf("listenPrivateSocket error = %v, want unsafe-parent refusal", err)
	}
}

func TestPrivateSocketRefusesWritableNonStickyAncestor(t *testing.T) {
	root := t.TempDir()
	shared := filepath.Join(root, "replaceable")
	if err := os.Mkdir(shared, 0o700); err != nil {
		t.Fatalf("mkdir writable ancestor: %v", err)
	}
	if err := os.Chmod(shared, 0o777); err != nil {
		t.Fatalf("chmod writable ancestor: %v", err)
	}
	owned := filepath.Join(shared, "owned")
	if err := os.Mkdir(owned, 0o700); err != nil {
		t.Fatalf("mkdir owned socket directory: %v", err)
	}

	_, err := listenPrivateSocket(filepath.Join(owned, "private.sock"))
	if err == nil || !strings.Contains(err.Error(), "ancestor") || !strings.Contains(err.Error(), "sticky") {
		t.Fatalf("listenPrivateSocket error = %v, want writable-ancestor refusal", err)
	}
}

func TestPrivateSocketAllowsOwnedSymlinkUnderSafeAncestor(t *testing.T) {
	root := shortSocketTestDir(t)
	realParent := filepath.Join(root, "real")
	if err := os.Mkdir(realParent, 0o700); err != nil {
		t.Fatalf("mkdir real parent: %v", err)
	}
	owned := filepath.Join(realParent, "owned")
	if err := os.Mkdir(owned, 0o700); err != nil {
		t.Fatalf("mkdir owned socket directory: %v", err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(realParent, link); err != nil {
		t.Fatalf("symlink parent: %v", err)
	}

	listener, err := listenPrivateSocket(filepath.Join(link, "owned", "private.sock"))
	if err != nil {
		skipIfUnixSocketDenied(t, err)
		t.Fatalf("listenPrivateSocket through owned safe symlink: %v", err)
	}
	listener.Close()
}

// macOS sockaddr_un paths are only 104 bytes while t.TempDir can itself be
// close to that under /private/var/folders. Use a short, independently-owned
// directory so these tests exercise our listener rather than the OS path cap.
func shortSocketTestDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "ti-private-")
	if err != nil {
		t.Fatalf("create short temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func skipIfUnixSocketDenied(t *testing.T, err error) {
	t.Helper()
	if errors.Is(err, syscall.EPERM) {
		t.Skip("test sandbox forbids binding Unix sockets")
	}
}
