// Package privateaccess defines the collection policy that decides whether
// access through TrustIssues' optional private-network listener is required.
//
// It deliberately has no dependency on handlers or middleware. Both the
// collection API (which persists policy) and the ingress enforcement layer
// need to interpret the same values, and putting the vocabulary here prevents
// those security decisions from drifting apart.
package privateaccess

// Policy is the persisted private-network requirement for a collection.
type Policy string

const (
	// PolicyStandard leaves the collection on the ordinary authenticated HTTPS
	// surface. This is the compatibility default when no connector is enabled.
	PolicyStandard Policy = "standard"

	// PolicySensitivePrivate requires private ingress for sensitive actions such
	// as reveal, export, and rotation, while ordinary metadata access can remain
	// available through the public authenticated surface.
	PolicySensitivePrivate Policy = "sensitive_private"

	// PolicyFullyPrivate requires private ingress for every operation on the
	// collection.
	PolicyFullyPrivate Policy = "fully_private"
)

// Parse accepts only the values represented by the database CHECK constraint.
// It never supplies a default: callers must make omission semantics explicit.
func Parse(value string) (Policy, bool) {
	policy := Policy(value)
	switch policy {
	case PolicyStandard, PolicySensitivePrivate, PolicyFullyPrivate:
		return policy, true
	default:
		return "", false
	}
}

// ParseOrDefault is for create/import paths where an omitted policy must retain
// compatibility with collections created before private access existed.
func ParseOrDefault(value string) (Policy, bool) {
	if value == "" {
		return PolicyStandard, true
	}
	return Parse(value)
}
