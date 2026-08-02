package handlers

import (
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// THE GUARD THAT IS SUPPOSED TO STOP ROUND 5.
//
// Four rounds of this audit stream reported the same defect with a different
// column name in it. Each fix closed the column that had just been used. The
// pattern is not a coincidence and it is not carelessness: a reviewer looking
// for "the field that chooses a host" finds destination_patterns and stops,
// because nothing else in the tree is SPELLED like a destination. datadog's
// "site" holds "datadoghq.eu" and becomes the host. grafana's "instance" holds
// "acme" and becomes the host. auth0's "tenant", supabase's "project_ref",
// zitadel's and forgejo's "instance" likewise.
//
// So the deliverable is not another point fix. It is a test that fails when a
// new host-influencing field appears and nobody has classified it. Modelled on
// TestHandRolledFixturesMatchTheRealSchema in schema_drift_test.go, which forces
// every new vault_entries column to be accounted for; the difference is that
// this one enumerates THREE real things (the columns, the provider registry, and
// the provider source itself) because a destination can be chosen in three
// places.

// egressClass is what one writable field can do to where a decrypted secret
// goes.
type egressClass int

const (
	// egressChoosesHost: writing this field can put a new host on the wire.
	// Every one of these must be gated by mayDirectSecretEgress at its write
	// site.
	egressChoosesHost egressClass = iota
	// egressTriggersDelivery: writing this field does not choose WHERE, but it
	// decides WHETHER or WHEN the secret is sent. Recorded separately rather
	// than lumped in with "neutral", because the difference matters and because
	// the residual it leaves is a documented one (DEFERRED (i)).
	egressTriggersDelivery
	// egressNeutral: cannot influence an outbound destination at all.
	egressNeutral
)

// vaultEntryEgressClass classifies EVERY column of vault_entries.
//
// A column missing from this map fails TestEveryVaultEntryColumnIsClassified,
// which is the whole point: adding a column is the moment to answer "can this
// move a secret", and answering it later has now cost four rounds.
var vaultEntryEgressClass = map[string]struct {
	class egressClass
	why   string
}{
	// ── chooses a host ──────────────────────────────────────────────────
	"destination_patterns": {egressChoosesHost,
		"the capability ceiling: /proxy delivers the decrypted secret to a host matched from here. " +
			"Gated in VaultHandler.Update by widenedDestinations + mayDirectSecretEgress (round 3)"},
	"provider": {egressChoosesHost,
		"selects the adapter, and every adapter has its own hosts. openai -> api.openai.com, " +
			"datadog -> api.<site>. Gated in VaultHandler.Update by authorityForEgressChange (round 4)"},
	"provider_meta": {egressChoosesHost,
		"holds site / instance / tenant / project_ref, each of which the adapter concatenates " +
			"into the host. THE round-4 blocker. Gated by authorityForEgressChange; the per-key " +
			"enumeration is providerEgress[...].metaKeys"},
	"rotation_targets": {egressChoosesHost,
		"webhook_url and forgejo instance are literal delivery destinations for the rotated " +
			"plaintext. THE round-5 blocker: this row already said 'chooses a host' while " +
			"VaultHandler.UpdateTargets wrote the column without asking anybody, which is why the " +
			"guard below now checks ENFORCEMENT rather than classification. Gated by " +
			"decideDeliveryEgress at the write and by targetStillAuthorized at delivery, both of " +
			"which resolve to mayDirectSecretEgress; the write goes through " +
			"setEntryRotationTargets in vault_egress_writes.go"},

	// ── triggers delivery without choosing where ────────────────────────
	"auto_rotate": {egressTriggersDelivery,
		"decides whether the scheduler picks this entry up. It cannot name a host, but it is what " +
			"makes a host that IS named get dialled with nobody watching. The residual (an API-key " +
			"caller who cannot unlock or rotate flips this and waits) is written up in DEFERRED (i)"},
	"rotation_interval_days": {egressTriggersDelivery, "when the scheduler considers the entry due"},
	"expires_at":             {egressTriggersDelivery, "feeds the expiry reminder, not a destination"},
	"last_rotated_at":        {egressTriggersDelivery, "with the interval, decides due-ness"},

	// ── neutral ─────────────────────────────────────────────────────────
	"id": {egressNeutral, "primary key"},
	"user_id": {egressNeutral,
		"never reaches a URL. It IS the input to mayDirectSecretEgress, so writing it transfers the " +
			"right to choose a destination, and there is exactly one writer: AdoptAndRenameVaultEntry, " +
			"reachable only by a collection MANAGER and only once the creator has left that collection " +
			"(managerMayAdoptOrphanedEntry). That is a deliberate, documented ownership transfer for a " +
			"stranded secret, not a redirect. Any second writer of this column has to be read as an " +
			"egress-authority change, not as bookkeeping"},
	"collection_id": {egressNeutral,
		"sharing scope, so it decides who holds manage. It cannot name a host, and manage alone no " +
			"longer carries the right to add one"},
	"name":                {egressNeutral, "lookup key for MCP and service identities, not a destination"},
	"encrypted_value":     {egressNeutral, "the secret itself, which is WHAT travels, not where to"},
	"nonce":               {egressNeutral, "AEAD nonce"},
	"encryption_version":  {egressNeutral, "key derivation version"},
	"category":            {egressNeutral, "display metadata"},
	"notes":               {egressNeutral, "display metadata"},
	"url":                 {egressNeutral, "browser-extension autofill match only. Nothing outbound reads it: it never reaches a provider call, a delivery target or the capability proxy"},
	"alias_url":           {egressNeutral, "second autofill match, same as url"},
	"url_bidx":            {egressNeutral, "blind index over url, for matching"},
	"alias_url_bidx":      {egressNeutral, "blind index over alias_url"},
	"username":            {egressNeutral, "autofill metadata"},
	"auto_login":          {egressNeutral, "extension behaviour, client side"},
	"custom_fields":       {egressNeutral, "user key/value pairs; no code path builds a URL from them"},
	"rotation_log":        {egressNeutral, "audit history, written by the server"},
	"last_rotation_error": {egressNeutral, "status text, written by the server"},
	"injection_spec": {egressNeutral,
		"decides HOW the secret is injected (which header, what format), never WHERE. Not writable " +
			"through PUT /api/vault/{id} at all: seedCapabilityDefaults is its only writer and it is " +
			"gated on mayDirectSecretEgress alongside the ceiling"},
	"created_at": {egressNeutral, "timestamp"},
	"updated_at": {egressNeutral, "timestamp, also the rotation compare-and-swap token"},
}

// vaultEntriesColumns reads the REAL columns out of the migrations, so this
// guard tracks the schema rather than a copy of it.
func vaultEntriesColumns(t *testing.T) []string {
	t.Helper()
	dir := filepath.Join("..", "database", "migrations")
	files, err := filepath.Glob(filepath.Join(dir, "*.sql"))
	if err != nil || len(files) == 0 {
		t.Fatalf("ABORT: no migrations found under %s (%v); this guard would be vacuous", dir, err)
	}
	sort.Strings(files)

	createRe := regexp.MustCompile(`(?is)CREATE\s+TABLE\s+vault_entries\s*\((.*?)\n\);`)
	alterRe := regexp.MustCompile(`(?i)ALTER\s+TABLE\s+vault_entries\s+ADD\s+COLUMN\s+([a-z_0-9]+)`)
	// Table-level constraints are not columns.
	constraintRe := regexp.MustCompile(`(?i)^(UNIQUE|PRIMARY|FOREIGN|CHECK|CONSTRAINT)\b`)

	var cols []string
	seen := map[string]bool{}
	add := func(c string) {
		if c != "" && !seen[c] {
			seen[c] = true
			cols = append(cols, c)
		}
	}
	for _, f := range files {
		src, rErr := os.ReadFile(f)
		if rErr != nil {
			t.Fatalf("read %s: %v", f, rErr)
		}
		text := string(src)
		// Only the Up section: a Down that drops the table must not add columns.
		if i := strings.Index(text, "-- +goose Down"); i >= 0 {
			text = text[:i]
		}
		if m := createRe.FindStringSubmatch(text); m != nil {
			for _, line := range strings.Split(m[1], "\n") {
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "--") || constraintRe.MatchString(line) {
					continue
				}
				add(strings.Fields(line)[0])
			}
		}
		for _, m := range alterRe.FindAllStringSubmatch(text, -1) {
			add(m[1])
		}
	}
	if len(cols) < 10 {
		t.Fatalf("ABORT: only parsed %d vault_entries columns (%v); the parser has stopped matching "+
			"the migrations and this guard is checking nothing", len(cols), cols)
	}
	return cols
}

// TestEveryVaultEntryColumnIsClassified is the column half of the guard.
//
// It fails in BOTH directions. An unclassified column is the round-5 hole. A
// classification with no column behind it is a rubber stamp that survived a
// rename, and a stale rubber stamp is how a reviewer concludes a field was
// considered when it was not.
func TestEveryVaultEntryColumnIsClassified(t *testing.T) {
	cols := vaultEntriesColumns(t)
	t.Logf("classified against %d real vault_entries columns", len(cols))

	real := map[string]bool{}
	for _, c := range cols {
		real[c] = true
		entry, ok := vaultEntryEgressClass[c]
		if !ok {
			t.Errorf("vault_entries.%s is not classified in vaultEntryEgressClass.\n"+
				"Answer one question and add a row: can a caller who writes this column influence the "+
				"HOST a decrypted secret is sent to, directly or after a template or a provider preset "+
				"expands it?\n"+
				"  yes -> egressChoosesHost, AND gate its write on mayDirectSecretEgress (see how "+
				"provider_meta is handled in VaultHandler.Update)\n"+
				"  it only decides whether/when delivery happens -> egressTriggersDelivery\n"+
				"  neither -> egressNeutral, and say why\n"+
				"This test exists because four consecutive audit rounds each closed one named column "+
				"while the next one sat here unclassified.", c)
			continue
		}
		if strings.TrimSpace(entry.why) == "" {
			t.Errorf("vault_entries.%s is classified with no reason; the reason is the part a "+
				"future reviewer reads", c)
		}
	}
	for c := range vaultEntryEgressClass {
		if !real[c] {
			t.Errorf("vaultEntryEgressClass classifies %q, which is not a vault_entries column any "+
				"more. Remove it or fix the name; a stale row reads as a considered decision", c)
		}
	}
}

// TestHostChoosingColumnsAreGatedAtTheirWriteSite is the other half of the
// column guard, and the one that would have caught round 4 at review time.
//
// It is NOT the one that would have caught round 5. This checks one named
// handler's one named condition, so it can only see the doors it was told
// about, and rotation_targets has its own route. The guard that answers the
// general question, for every host-choosing column and every write path
// including ones nobody has written yet, is
// TestEveryHostChoosingWriteGoesThroughTheChokepoint in
// egress_write_chokepoint_test.go. This one stays because it pins the SHAPE of
// the condition inside Update, which the chokepoint cannot see.
//
// A classification is a claim. This checks the claim against the handler: every
// column classified egressChoosesHost and writable through PUT /api/vault/{id}
// must appear in the condition that computes mayWidenEgress. Round 3's version
// of that condition read
//
//	if req.DestinationPatterns != nil || req.Provider != nil {
//
// and provider_meta, the column round 4 used, was simply not in it.
func TestHostChoosingColumnsAreGatedAtTheirWriteSite(t *testing.T) {
	src := readPackageFile(t, "vault.go")
	i := strings.Index(src, "mayWidenEgress := false")
	if i < 0 {
		t.Fatal("the mayWidenEgress computation is gone from VaultHandler.Update; if it was renamed, " +
			"rename it here too rather than deleting this guard")
	}
	end := strings.Index(src[i:], "\n\t}")
	if end < 0 {
		t.Fatal("could not find the end of the mayWidenEgress block")
	}
	block := src[i : i+end]

	// The JSON field on the Update request that carries each host-choosing
	// column. rotation_targets has its own route and its own gate, so it is not
	// part of this request body.
	writable := map[string]string{
		"destination_patterns": "req.DestinationPatterns",
		"provider":             "req.Provider",
		"provider_meta":        "req.ProviderMeta",
	}
	for col, field := range writable {
		if vaultEntryEgressClass[col].class != egressChoosesHost {
			t.Fatalf("%s is no longer classified egressChoosesHost; if that is deliberate, this "+
				"guard's premise changed and it is what has to be edited", col)
		}
		if !strings.Contains(block, field) {
			t.Errorf("%s is classified as choosing a host but %s does not appear in the "+
				"mayWidenEgress condition in VaultHandler.Update, so a write to it is not held to the "+
				"widening right. This is exactly the round-4 shape: the gate named the columns that "+
				"had already been attacked.", col, field)
		}
	}
}

// TestUpdateScheduleCannotWriteAHostChoosingField covers the OTHER route that
// writes the provider columns.
//
// PUT /api/vault/{id}/schedule calls UpdateVaultEntryProvider, which writes all
// three columns in one statement, and it is manage-gated with no widening check.
// It is safe today for one reason only: it carries the STORED provider and
// provider_meta forward verbatim and changes just auto_rotate. That is a
// property of six lines of code, not of the route, and a future edit adding
// "provider" to its request body would reopen round 4 through a door nobody is
// watching. Guard the property.
func TestUpdateScheduleCannotWriteAHostChoosingField(t *testing.T) {
	src := readPackageFile(t, "vault.go")
	body := functionBody(t, src, "func (h *VaultHandler) UpdateSchedule(")
	decl := strings.Index(body, "var req struct")
	if decl < 0 {
		t.Fatal("UpdateSchedule no longer decodes an anonymous request struct; re-point this guard")
	}
	end := strings.Index(body[decl:], "\n\t}")
	if end < 0 {
		t.Fatal("could not find the end of the UpdateSchedule request struct")
	}
	reqStruct := body[decl : decl+end]
	for _, forbidden := range []string{`json:"provider"`, `json:"provider_meta"`, `json:"destination_patterns"`} {
		if strings.Contains(reqStruct, forbidden) {
			t.Errorf("PUT /api/vault/{id}/schedule accepts %s. That route is manage-gated with no "+
				"widening check, so it would hand every accepted editor the destination-choosing "+
				"right that VaultHandler.Update refuses them. Route it through "+
				"authorityForEgressChange or keep it out of this body.", forbidden)
		}
	}
	// The positive half: it must still carry the stored values forward, or it is
	// silently clearing the provider on every schedule change.
	if !strings.Contains(body, "current.Provider") || !strings.Contains(body, "current.ProviderMeta") {
		t.Error("UpdateSchedule no longer writes back the STORED provider and provider_meta; either " +
			"it now takes them from the caller (the hole above) or it is wiping them")
	}
}

// TestEveryProviderDeclaresItsEgress enumerates the REAL ProviderRegistry.
//
// An adapter with no row in providerEgress cannot reach the network at all,
// because declaredProviderEgress returns an empty allowance and providerDo
// refuses one. That is the correct failure mode (fail closed), but it fails at
// RUN time, in whatever feature the new provider was written for. This turns it
// into a compile-adjacent failure with an explanation attached.
func TestEveryProviderDeclaresItsEgress(t *testing.T) {
	if len(ProviderRegistry) < 20 {
		t.Fatalf("ABORT: only %d providers registered; this guard is matching almost nothing", len(ProviderRegistry))
	}
	for name := range ProviderRegistry {
		decl, ok := providerEgress[name]
		if !ok {
			t.Errorf("provider %q is registered but has no row in providerEgress (egress_authority.go).\n"+
				"Write down every host it can dial and which provider_meta keys decide them. If it "+
				"never makes an outbound request, say so explicitly: an omission and a deliberate "+
				"'this one egresses nothing' must not look the same.", name)
			continue
		}
		if strings.TrimSpace(decl.why) == "" {
			t.Errorf("provider %q declares hosts with no reason recorded", name)
		}
		// A key listed as host-choosing but read nowhere is a rubber stamp; a key
		// read in the source and not listed is the round-4 hole. The second half
		// is what TestProviderRequestsStayInsideTheirDeclaredHosts proves
		// behaviourally, so this half only checks the cheap direction.
		for _, k := range decl.metaKeys {
			if !strings.Contains(readPackageFile(t, "vault_providers.go"), `meta["`+k+`"]`) {
				t.Errorf("provider %q declares provider_meta key %q as host-choosing, but no adapter "+
					"reads it. Remove it, or the write gate is refusing writes for no reason", name, k)
			}
		}
	}
	for name := range providerEgress {
		if _, ok := ProviderRegistry[name]; !ok {
			t.Errorf("providerEgress declares %q, which is not a registered provider. A stale row "+
				"reads as coverage that does not exist", name)
		}
	}
}

// TestCapabilityPresetPlaceholdersAreDeclaredHostKeys covers the preset table,
// which is the OTHER place a provider_meta value becomes a host.
//
// CapabilityDefaults seeds destination_patterns from a template. Three of them
// carry a {placeholder} that ExpandCapabilityDestinations fills from
// provider_meta, so the seeded ceiling host comes out of a column an editor can
// write. Those keys therefore have to be declared host-choosing, or the write
// gate lets the value through and the preset turns it into a host afterwards.
func TestCapabilityPresetPlaceholdersAreDeclaredHostKeys(t *testing.T) {
	if len(CapabilityDefaults) < 20 {
		t.Fatalf("ABORT: only %d capability presets; this guard is matching almost nothing", len(CapabilityDefaults))
	}
	placeholders := 0
	for provider, def := range CapabilityDefaults {
		// PER PROVIDER, not against the union of every provider's keys.
		//
		// An ablation caught this: dropping "instance" from grafana's metaKeys
		// left the guard green, because zitadel and forgejo also declare a key
		// called "instance" and a global set cannot tell whose it is. A key is
		// host-choosing FOR A PROVIDER; asking the question any other way answers
		// a different one.
		declaredKeys := map[string]bool{}
		for _, k := range providerEgress[provider].metaKeys {
			declaredKeys[k] = true
		}
		for _, pattern := range def.Destinations {
			host, _ := splitHostPath(pattern)
			for _, m := range tenantPlaceholderRe.FindAllStringSubmatch(host, -1) {
				placeholders++
				if !declaredKeys[m[1]] {
					t.Errorf("the %s preset expands {%s} from provider_meta into the HOST of a seeded "+
						"destination, but %q is not in providerEgress[that provider].metaKeys.\n"+
						"So a caller with manage can set it, the write gate sees no host change, and "+
						"seedCapabilityDefaults then turns it into a ceiling host. Add it to the "+
						"provider's metaKeys.", provider, m[1], m[1])
				}
			}
			if strings.Contains(host, "*") {
				t.Errorf("the %s preset ships a host wildcard (%q). destMatches refuses those at match "+
					"time, so it would seed a ceiling that silently allows nothing, and if that "+
					"refusal is ever relaxed it allows every sibling on the suffix",
					provider, pattern)
			}
		}
	}
	if placeholders == 0 {
		t.Fatal("ABORT: no tenant placeholders found in CapabilityDefaults; either the presets changed " +
			"shape or the regex stopped matching, and this guard is checking nothing")
	}
	t.Logf("checked %d tenant placeholders across %d presets", placeholders, len(CapabilityDefaults))
}

// providerMetaKeysInSource enumerates every provider_meta key any adapter reads,
// straight out of the REAL source. A new provider's new key is picked up
// automatically, which is what makes the behavioural guard below cover code
// nobody has written yet.
func providerMetaKeysInSource(t *testing.T) []string {
	t.Helper()
	src := readPackageFile(t, "vault_providers.go")
	re := regexp.MustCompile(`meta\["([a-z_0-9]+)"\]`)
	seen := map[string]bool{}
	var keys []string
	for _, m := range re.FindAllStringSubmatch(src, -1) {
		if !seen[m[1]] {
			seen[m[1]] = true
			keys = append(keys, m[1])
		}
	}
	if len(keys) < 10 {
		t.Fatalf("ABORT: only found %d provider_meta keys in vault_providers.go (%v); the regex has "+
			"stopped matching and the guard below would probe nothing", len(keys), keys)
	}
	sort.Strings(keys)
	return keys
}

// attackerValue is the sentinel every probe uses. It has to be usable as a DNS
// label, as a domain and as a path segment, because it is fed to keys of all
// three shapes.
const attackerValue = "attacker-controlled"

// adversarialMeta builds a provider_meta in which EVERY key an adapter reads is
// attacker-chosen.
//
// Keys the provider DECLARES as host-choosing get the shape the declaration
// understands, discovered by asking the declaration rather than by hardcoding:
// grafana's instance is a bare label, zitadel's instance is a whole URL, and a
// probe that guessed wrong would produce a nonsense URL and a meaningless
// result. Everything else gets a plain attacker domain, which is the case that
// matters: an UNDECLARED key that turns out to feed the host makes the request
// land somewhere the declaration does not cover, and providerDo refuses it.
func adversarialMeta(provider string, allKeys []string) map[string]string {
	meta := map[string]string{}
	for _, k := range allKeys {
		meta[k] = attackerValue + ".example"
	}
	decl := providerEgress[provider]
	for _, k := range decl.metaKeys {
		for _, candidate := range []string{
			attackerValue,
			attackerValue + ".example",
			"https://" + attackerValue + ".example",
		} {
			probe := map[string]string{}
			for pk, pv := range meta {
				probe[pk] = pv
			}
			probe[k] = candidate
			if !declaredProviderEgress(provider, probe).empty() {
				meta[k] = candidate
				break
			}
		}
	}
	return meta
}

// stubUpstream answers every request with a small, well-formed JSON object so
// adapters get far enough to make their SECOND call (backblaze's revoke,
// twilio's deferred delete) rather than bailing on a parse error.
//
// status is mutable because the adapters disagree about what success looks
// like: datadog, resend, sendgrid, twilio and forgejo want 201 on their mint,
// grafana and backblaze want 200, and an adapter that gets the wrong one
// returns early. An ablation found this the hard way: planting a host write-back
// in datadog's Rotate was MISSED, because the probe's fixed 200 made Rotate bail
// before it reached the planted line. A probe that never reaches an adapter's
// success path is not probing that adapter.
type stubUpstream struct {
	hits   *int
	status *int
}

func (s stubUpstream) RoundTrip(r *http.Request) (*http.Response, error) {
	if s.hits != nil {
		*s.hits++
	}
	body := `{"id":"x","key":"x","token":"x","sha1":"x","secret":"x","sid":"SKx","api_key":"x",` +
		`"api_key_id":"x","applicationKey":"x","applicationKeyId":"x","result":{"id":"x","value":"x"},` +
		`"data":{"id":"x","attributes":{"key":"x"}}}`
	code := 200
	if s.status != nil {
		code = *s.status
	}
	return &http.Response{
		StatusCode: code,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Request:    r,
	}, nil
}

// TestProviderRequestsStayInsideTheirDeclaredHosts IS the round-5 stopper.
//
// It drives every registered adapter, for real, with a provider_meta in which
// every key it reads is attacker-chosen, and asserts that nothing it dials
// falls outside the hosts declared for it. The classification tables above are
// claims about the code; this is the test that checks them against the code.
//
// Concretely, it is the test that would have failed the day datadog's Validate
// was written as "https://api."+meta["site"] with the provider still declared as
// a fixed vendor host. It needs no knowledge that "site" is special, and none
// that a provider added next year has a key called "region" or "shard" or
// "workspace": the key list comes out of the source and the host comes off the
// wire.
func TestProviderRequestsStayInsideTheirDeclaredHosts(t *testing.T) {
	allKeys := providerMetaKeysInSource(t)
	t.Logf("probing %d providers with %d attacker-controlled provider_meta keys",
		len(ProviderRegistry), len(allKeys))

	prev := providerHTTP
	hits, status := 0, 200
	providerHTTP = &http.Client{Transport: stubUpstream{hits: &hits, status: &status}}
	t.Cleanup(func() { providerHTTP = prev })

	names := make([]string, 0, len(ProviderRegistry))
	for n := range ProviderRegistry {
		names = append(names, n)
	}
	sort.Strings(names)

	for _, name := range names {
		p := ProviderRegistry[name]
		t.Run(name, func(t *testing.T) {
			declaredEmpty := providerEgress[name].hosts == nil
			var attempts []egressAttempt

			type providerOp struct {
				what string
				run  func(ctx context.Context, meta map[string]string)
			}
			ops := []providerOp{
				{"Rotate", func(ctx context.Context, meta map[string]string) {
					_, _ = p.Rotate(ctx, "THE-OPERATORS-DECRYPTED-SECRET", meta)
				}},
				{"Validate", func(ctx context.Context, meta map[string]string) {
					_, _ = p.Validate(ctx, "THE-OPERATORS-DECRYPTED-SECRET", meta)
				}},
			}

			// Both success codes, because the adapters disagree about which one
			// means success and a probe that never reaches an adapter's success
			// path cannot see what happens on it.
			for _, code := range []int{200, 201} {
				status = code
				for _, op := range ops {
					meta := adversarialMeta(name, allKeys)
					declaredBefore := declaredProviderEgress(name, meta).describe()
					// Exactly what production installs: the authority declared for
					// this provider, resolved against the same meta the adapter reads.
					ctx := withEgressRecorder(withProviderEgress(context.Background(), name, meta), &attempts)
					before := len(attempts)
					op.run(ctx, meta)

					// An adapter WRITES BACK into meta (twilio's key_sid,
					// backblaze's key_id) and revokeOldKeyAndPersistMeta then
					// persists it, with no authorization check anywhere: it is the
					// server recording its own work. So an adapter that wrote a
					// host-influencing key would move the entry's destination with
					// nobody's permission, from inside the rotation it was asked to
					// perform.
					if got := declaredProviderEgress(name, meta).describe(); got != declaredBefore {
						t.Errorf("%s.%s (upstream %d) changed its own entry's reachable hosts by "+
							"writing back into provider_meta: %s -> %s.\n"+
							"revokeOldKeyAndPersistMeta persists that map unconditionally, so this "+
							"moves the destination with no authority behind it",
							name, op.what, code, declaredBefore, got)
					}

					for _, a := range attempts[before:] {
						if !a.refused {
							continue
						}
						t.Errorf("%s.%s dialled %q, which is OUTSIDE the hosts declared for %q.\n"+
							"  declared: %s\n"+
							"  refusal:  %s\n\n"+
							"Either this adapter builds its host out of a provider_meta key that is not in "+
							"providerEgress[%q].metaKeys (the round-4 defect: a field that does not look "+
							"like a host still becomes one), or the declaration is out of date. Fix the "+
							"declaration AND check that the key is gated at its write site, because the "+
							"write gate compares declared host sets and cannot see a key it does not "+
							"know about.",
							name, op.what, a.host, name,
							declaredProviderEgress(name, meta).describe(), a.reason, name)
					}
				}
			}

			// Anti-vacuity, both directions. A provider that declares hosts but
			// never dialled means the probe stopped exercising it (a meta shape it
			// rejects, a signature change) and the loop above proved nothing. A
			// provider that declares nothing but DID try to dial is a new adapter
			// that egresses without a declaration.
			switch {
			case declaredEmpty && len(attempts) > 0:
				t.Errorf("%s is declared as making no outbound requests, but it attempted %d "+
					"(first: %q). Give it a providerEgress row naming the hosts it may reach",
					name, len(attempts), attempts[0].host)
			case !declaredEmpty && len(attempts) == 0:
				t.Errorf("%s declares hosts but neither Rotate nor Validate attempted a request, so "+
					"this guard checked nothing for it. The probe meta is probably no longer "+
					"acceptable to the adapter; fix adversarialMeta rather than deleting the case",
					name)
			}
		})
	}

	if hits == 0 {
		t.Fatal("ABORT: no request reached the stub upstream at all, so every provider was refused " +
			"or none was driven. Either way this guard is vacuous")
	}
	t.Logf("%d requests reached the stub upstream", hits)
}

// TestNoProviderCallBypassesTheEgressGate is the structural companion.
//
// providerDo is only a chokepoint while it is the ONLY caller of
// providerHTTP.Do. One direct call somewhere in this package is a door with no
// lock on it, and it would not fail any behavioural test: the request would
// simply succeed.
func TestNoProviderCallBypassesTheEgressGate(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	checked := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		checked++
		src, rErr := os.ReadFile(name)
		if rErr != nil {
			t.Fatalf("read %s: %v", name, rErr)
		}
		text := string(src)
		if name == "egress_authority.go" {
			// The one legitimate caller. Assert it IS there, so a refactor that
			// stops calling the client cannot leave this test passing over a
			// chokepoint that no longer forwards anything.
			if !strings.Contains(text, "providerHTTP.Do(req)") {
				t.Error("providerDo no longer forwards through providerHTTP; the chokepoint has been " +
					"disconnected from the client it is supposed to guard")
			}
			continue
		}
		if strings.Contains(text, "providerHTTP.Do(") {
			t.Errorf("%s calls providerHTTP.Do directly, going around providerDo and therefore around "+
				"the egress authority check. Call providerDo instead; if this call genuinely has no "+
				"secret to protect, it still needs to say which authority it runs under.", name)
		}
	}
	if checked < 10 {
		t.Fatalf("ABORT: only scanned %d source files; this guard is matching almost nothing", checked)
	}
}
