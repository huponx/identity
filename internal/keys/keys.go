// Package keys loads the signing key and the retired keys that stay in the JWKS.
package keys

import (
	"crypto"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/huponx/gocommon/jwtx"
)

// Set is the current signer plus the public keys published in the JWKS.
type Set struct {
	Signer *jwtx.Signer
	// Public has every published key, the current one included.
	Public map[string]crypto.PublicKey
	JWKS   []byte
}

// Load reads the signing key file and, when previousDir is set, every *.pem in it (the file
// name without extension is the kid of the retired key).
func Load(keyFile, kid, previousDir string) (*Set, error) {
	raw, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("signing key: %w", err)
	}
	priv, err := jwtx.ParsePrivateKeyPEM(raw)
	if err != nil {
		return nil, fmt.Errorf("signing key %s: %w", keyFile, err)
	}
	signer, err := jwtx.NewSigner(priv, kid)
	if err != nil {
		return nil, err
	}
	s := &Set{Signer: signer, Public: map[string]crypto.PublicKey{kid: signer.Public()}}

	if previousDir != "" {
		files, err := filepath.Glob(filepath.Join(previousDir, "*.pem"))
		if err != nil {
			return nil, err
		}
		for _, f := range files {
			old := strings.TrimSuffix(filepath.Base(f), ".pem")
			if old == kid {
				continue
			}
			b, err := os.ReadFile(f)
			if err != nil {
				return nil, fmt.Errorf("previous key %s: %w", f, err)
			}
			k, err := jwtx.ParsePrivateKeyPEM(b)
			if err != nil {
				return nil, fmt.Errorf("previous key %s: %w", f, err)
			}
			s.Public[old] = k.Public()
		}
	}
	if s.JWKS, err = jwtx.MarshalJWKS(s.Public); err != nil {
		return nil, err
	}
	return s, nil
}
