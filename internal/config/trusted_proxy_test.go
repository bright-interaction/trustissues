package config

import "testing"

// Empty is distinct from unset for this setting: it is the operator's explicit
// request to trust no socket peer with X-Forwarded-For or X-Forwarded-Proto.
func TestTrustedProxyPeersPreservesExplicitEmptySet(t *testing.T) {
	withBaseEnv(t)
	t.Setenv("TRUSTISSUES_TRUSTED_PROXY_PEERS", "")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if cfg.TrustedProxyPeers != "" {
		t.Fatalf("TrustedProxyPeers = %q, want explicit empty set", cfg.TrustedProxyPeers)
	}
}
