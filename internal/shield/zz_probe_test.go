package shield

import (
	"context"
	"testing"
	"time"
)

func TestProbeIdentifiersStillTokenized(t *testing.T) {
	store := NewMemoryStore()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	s, err := NewSession(context.Background(), store, "probe", key, time.Hour, HintFull)
	if err != nil {
		t.Fatal(err)
	}
	cases := []string{
		"const rows = response.data.items",
		"if (user.email) { send(user.email) }",
		"log.Printf(\"%s\", user.name)",
		"cfg := config.host",
		"this.store.dispatch(action)",
		"return props.data",
		"err.name === 'AbortError'",
		"db.host and db.port",
		"payload.link and payload.click",
		"item.live, item.today, item.works",
		"json.Unmarshal(b, &v)",
		"strings.HasPrefix(s, p)",
		"console.error(e)",
		"res.json({ok:true})",
		"crm.example.com is the host",
	}
	for _, c := range cases {
		out, err := s.RedactString(context.Background(), c)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("%-45s -> %s", c, out)
	}
}
