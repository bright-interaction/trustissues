package handlers

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// TestProviderRegistryReducedSet guards the extraction contract: the registry
// carries external SaaS providers plus the two local generators, and none of
// dockyard's agent-dispatched internal:* providers.
func TestProviderRegistryReducedSet(t *testing.T) {
	if len(ProviderRegistry) == 0 {
		t.Fatal("provider registry is empty")
	}
	for name, p := range ProviderRegistry {
		if strings.HasPrefix(name, "internal:") {
			t.Fatalf("internal provider %q must not be registered in trustissues", name)
		}
		if p.Name() != name {
			t.Fatalf("registry key %q does not match provider name %q", name, p.Name())
		}
		if providerLabels[name] == "" {
			t.Errorf("provider %q has no label", name)
		}
	}
	for _, want := range []string{"cloudflare", "resend", "forgejo", "manual", "shared-secret", "generated-key-32"} {
		if _, ok := ProviderRegistry[want]; !ok {
			t.Errorf("expected provider %q in registry", want)
		}
	}
	for _, retired := range []string{"dockyard-shared-secret", "shield-key-32", "internal:postgres"} {
		if _, ok := ProviderRegistry[retired]; ok {
			t.Errorf("retired provider name %q must not be registered", retired)
		}
	}
}

func TestListProviders(t *testing.T) {
	infos := ListProviders()
	if len(infos) != len(ProviderRegistry) {
		t.Fatalf("ListProviders returned %d entries, registry has %d", len(infos), len(ProviderRegistry))
	}
	for _, info := range infos {
		if info.Name == "" || info.Label == "" {
			t.Errorf("provider info missing name/label: %+v", info)
		}
	}
}

func TestSharedSecretProviderRotate(t *testing.T) {
	p := &SharedSecretProvider{}
	v1, err := p.Rotate(context.Background(), "", nil)
	if err != nil {
		t.Fatalf("rotate failed: %v", err)
	}
	if len(v1) != 64 {
		t.Fatalf("expected 64 hex chars (32 bytes), got %d", len(v1))
	}
	for _, c := range v1 {
		if !strings.ContainsRune("0123456789abcdef", c) {
			t.Fatalf("non-hex char %q in %q", c, v1)
		}
	}
	v2, _ := p.Rotate(context.Background(), "", nil)
	if v1 == v2 {
		t.Fatal("two rotations produced the same value")
	}
}

func TestGeneratedKey32ProviderRotate(t *testing.T) {
	p := &GeneratedKey32Provider{}
	v1, err := p.Rotate(context.Background(), "", nil)
	if err != nil {
		t.Fatalf("rotate failed: %v", err)
	}
	if len(v1) != 32 {
		t.Fatalf("expected exactly 32 chars, got %d", len(v1))
	}
	if len([]byte(v1)) != 32 {
		t.Fatalf("expected 32 bytes for AES-256, got %d", len([]byte(v1)))
	}
	for _, c := range v1 {
		if !strings.ContainsRune("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", c) {
			t.Fatalf("non-alphanumeric char %q in %q", c, v1)
		}
	}
	v2, _ := p.Rotate(context.Background(), "", nil)
	if v1 == v2 {
		t.Fatal("two rotations produced the same value")
	}
}

func TestAppendRotationLog(t *testing.T) {
	entry := RotationLogEntry{Timestamp: "2026-07-20T00:00:00Z", Status: "success", Provider: "manual", Method: "auto"}

	out := AppendRotationLog("", entry)
	var log []RotationLogEntry
	if err := json.Unmarshal([]byte(out), &log); err != nil || len(log) != 1 {
		t.Fatalf("append to empty = %q (err %v)", out, err)
	}

	out = AppendRotationLog("[]", entry)
	if err := json.Unmarshal([]byte(out), &log); err != nil || len(log) != 1 {
		t.Fatalf("append to [] = %q (err %v)", out, err)
	}

	// Truncation: the log keeps only the most recent 50 entries.
	acc := ""
	for i := 0; i < 60; i++ {
		e := entry
		e.Error = string(rune('a' + i%26))
		acc = AppendRotationLog(acc, e)
	}
	if err := json.Unmarshal([]byte(acc), &log); err != nil {
		t.Fatalf("log not JSON after 60 appends: %v", err)
	}
	if len(log) != 50 {
		t.Fatalf("expected log capped at 50, got %d", len(log))
	}
}

func TestParseProviderMeta(t *testing.T) {
	if m := ParseProviderMeta(""); len(m) != 0 || m == nil {
		t.Fatalf("empty input should give empty non-nil map, got %v", m)
	}
	if m := ParseProviderMeta("{}"); len(m) != 0 || m == nil {
		t.Fatalf("{} should give empty non-nil map, got %v", m)
	}
	m := ParseProviderMeta(`{"instance":"https://git.example.com","key_id":"abc"}`)
	if m["instance"] != "https://git.example.com" || m["key_id"] != "abc" {
		t.Fatalf("parsed meta wrong: %v", m)
	}
}
