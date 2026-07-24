package shield

import (
	"strings"
	"testing"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	key := []byte("01234567890123456789012345678901") // 32 bytes

	cases := []struct {
		name string
		in   string
	}{
		{"empty", ""},
		{"ascii", "anna@example.com"},
		{"unicode", "Anna Andersson åäö"},
		{"long", strings.Repeat("x", 1024)},
		{"newlines", "line1\nline2\r\nline3"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ct, err := encrypt(tc.in, key)
			if err != nil {
				t.Fatalf("encrypt: %v", err)
			}
			pt, err := decrypt(ct, key)
			if err != nil {
				t.Fatalf("decrypt: %v", err)
			}
			if pt != tc.in {
				t.Fatalf("round-trip mismatch: got %q want %q", pt, tc.in)
			}
			if tc.in != "" && ct == tc.in {
				t.Fatalf("ciphertext equals plaintext, encryption did nothing")
			}
		})
	}
}

func TestEncryptWrongKeySize(t *testing.T) {
	cases := [][]byte{
		nil,
		[]byte("short"),
		[]byte("12345678901234567890123456789012345"), // 35 bytes
	}
	for _, k := range cases {
		if _, err := encrypt("data", k); err == nil {
			t.Errorf("encrypt with key len=%d: expected error, got nil", len(k))
		}
	}
}

func TestDecryptDifferentKey(t *testing.T) {
	key1 := []byte("11111111111111111111111111111111")
	key2 := []byte("22222222222222222222222222222222")
	ct, err := encrypt("secret", key1)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if _, err := decrypt(ct, key2); err == nil {
		t.Fatal("decrypt with wrong key should fail")
	}
}

func TestNewTokenIDFormat(t *testing.T) {
	for i := 0; i < 100; i++ {
		id, err := newTokenID()
		if err != nil {
			t.Fatalf("newTokenID: %v", err)
		}
		if !strings.HasPrefix(id, "tok_") {
			t.Errorf("missing prefix: %q", id)
		}
		if len(id) != len("tok_")+8 {
			t.Errorf("wrong length: %q (len=%d)", id, len(id))
		}
	}
}
