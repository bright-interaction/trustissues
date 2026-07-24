package shield

import "context"

type sessionKey struct{}

// WithSession returns a derived context that carries s. Tool handlers
// retrieve it via SessionFromContext when they need to call Shield /
// Unshield directly on typed structs (preferred over the regex-based
// RedactString safety net the dispatcher applies).
func WithSession(ctx context.Context, s *Session) context.Context {
	return context.WithValue(ctx, sessionKey{}, s)
}

// SessionFromContext returns the Session attached by WithSession, or
// nil when the context has no Session (shield disabled, dev bypass, or
// caller forgot to wire the middleware). Handlers must guard against
// nil and pass through unmodified when shield is off.
func SessionFromContext(ctx context.Context) *Session {
	s, _ := ctx.Value(sessionKey{}).(*Session)
	return s
}
