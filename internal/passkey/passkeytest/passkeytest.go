// Package passkeytest is a software authenticator for tests: an ES256 key that answers the options of a
// ceremony the way a browser and an authenticator do (attestation "none"), with switches to misbehave.
package passkeytest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// Authenticator holds one credential.
type Authenticator struct {
	Key    *ecdsa.PrivateKey
	CredID []byte
	// Origin and RPID are what the browser and the authenticator put in their answer.
	Origin, RPID string
	// UV is the user verification flag of the answers; BE and BS the backup flags.
	UV, BE, BS bool
	// Count is the sign count of the last answer; each assertion adds one unless Frozen.
	Count  uint32
	Frozen bool
	handle []byte
}

// New returns an authenticator with a fresh key and credential id, user verifying, not synced.
func New(t testing.TB, origin, rpID string) *Authenticator {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := make([]byte, 32)
	_, _ = rand.Read(id)
	return &Authenticator{Key: key, CredID: id, Origin: origin, RPID: rpID, UV: true}
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func (a *Authenticator) flags(attested bool) byte {
	f := byte(0x01) // user present
	if a.UV {
		f |= 0x04
	}
	if a.BE {
		f |= 0x08
	}
	if a.BS {
		f |= 0x10
	}
	if attested {
		f |= 0x40
	}
	return f
}

func (a *Authenticator) clientData(typ, challenge string) []byte {
	b, _ := json.Marshal(map[string]any{"type": typ, "challenge": challenge, "origin": a.Origin, "crossOrigin": false})
	return b
}

// Create answers the creation options (the JSON the server sent) with the credential JSON.
func (a *Authenticator) Create(t testing.TB, options []byte) []byte {
	t.Helper()
	var o struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
			User      struct {
				ID string `json:"id"`
			} `json:"user"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(options, &o); err != nil {
		t.Fatal(err)
	}
	a.handle, _ = base64.RawURLEncoding.DecodeString(o.PublicKey.User.ID)

	rpHash := sha256.Sum256([]byte(a.RPID))
	auth := append([]byte{}, rpHash[:]...)
	auth = append(auth, a.flags(true))
	auth = binary.BigEndian.AppendUint32(auth, a.Count)
	auth = append(auth, make([]byte, 16)...) // aaguid
	auth = binary.BigEndian.AppendUint16(auth, uint16(len(a.CredID)))
	auth = append(auth, a.CredID...)
	x, y := a.Key.PublicKey.X.FillBytes(make([]byte, 32)), a.Key.PublicKey.Y.FillBytes(make([]byte, 32))
	cose, err := cbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: x, -3: y})
	if err != nil {
		t.Fatal(err)
	}
	auth = append(auth, cose...)
	att, err := cbor.Marshal(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": auth})
	if err != nil {
		t.Fatal(err)
	}
	out, _ := json.Marshal(map[string]any{
		"id": b64(a.CredID), "rawId": b64(a.CredID), "type": "public-key",
		"response": map[string]any{
			"attestationObject": b64(att),
			"clientDataJSON":    b64(a.clientData("webauthn.create", o.PublicKey.Challenge)),
			"transports":        []string{"internal"},
		},
	})
	return out
}

// Get answers the request options with the credential JSON; the user handle is the one of the registration.
func (a *Authenticator) Get(t testing.TB, options []byte) []byte {
	t.Helper()
	var o struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(options, &o); err != nil {
		t.Fatal(err)
	}
	if !a.Frozen {
		a.Count++
	}
	rpHash := sha256.Sum256([]byte(a.RPID))
	auth := append([]byte{}, rpHash[:]...)
	auth = append(auth, a.flags(false))
	auth = binary.BigEndian.AppendUint32(auth, a.Count)
	cd := a.clientData("webauthn.get", o.PublicKey.Challenge)
	cdHash := sha256.Sum256(cd)
	digest := sha256.Sum256(append(append([]byte{}, auth...), cdHash[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, a.Key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	out, _ := json.Marshal(map[string]any{
		"id": b64(a.CredID), "rawId": b64(a.CredID), "type": "public-key",
		"response": map[string]any{
			"authenticatorData": b64(auth), "clientDataJSON": b64(cd), "signature": b64(sig), "userHandle": b64(a.handle),
		},
	})
	return out
}
