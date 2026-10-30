// Verify an ML-DSA JWT against a trusted public JWK or JWKS file.
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	// Register the ML-DSA algorithms and AKP key support with jwx.
	_ "github.com/jwx-go/mldsa/v4"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jwt"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "Verification failed:", err)
		os.Exit(1)
	}
}

func run() error {
	tokenFile := flag.String("token", "-", "JWT file, or - to read standard input")
	keyFile := flag.String("jwks", "", "trusted public JWK or JWKS JSON file")
	issuer := flag.String("issuer", "", "expected issuer (optional)")
	audience := flag.String("audience", "", "expected audience (optional)")
	signatureOnly := flag.Bool("signature-only", false, "verify only the signature; skip all claim validation")
	flag.Parse()
	if *keyFile == "" || flag.NArg() != 0 {
		return errors.New("usage: go run . -jwks public.json [-token token.txt] [-issuer URL] [-audience CLIENT]")
	}
	if *signatureOnly && (*issuer != "" || *audience != "") {
		return errors.New("-signature-only cannot be combined with -issuer or -audience")
	}

	var encoded []byte
	var err error
	if *tokenFile == "-" {
		encoded, err = io.ReadAll(io.LimitReader(os.Stdin, 1<<20))
	} else {
		encoded, err = os.ReadFile(*tokenFile)
	}
	if err != nil {
		return fmt.Errorf("read JWT: %w", err)
	}
	encoded = bytes.TrimSpace(encoded)
	parts := strings.Split(string(encoded), ".")
	if len(parts) != 3 {
		return errors.New("expected a compact signed JWT with three segments")
	}
	var header struct {
		Algorithm string `json:"alg"`
		KeyID     string `json:"kid"`
	}
	protected, err := base64.RawURLEncoding.Strict().DecodeString(parts[0])
	if err != nil {
		return fmt.Errorf("decode protected header: %w", err)
	}
	if err := json.Unmarshal(protected, &header); err != nil {
		return fmt.Errorf("parse protected header: %w", err)
	}
	switch header.Algorithm {
	case "ML-DSA-44", "ML-DSA-65", "ML-DSA-87":
	default:
		return fmt.Errorf("algorithm %q is outside this verifier's ML-DSA allow-list", header.Algorithm)
	}
	if header.KeyID == "" {
		return errors.New("this verifier requires a kid in the protected header")
	}
	for _, segment := range parts {
		if _, err := base64.RawURLEncoding.Strict().DecodeString(segment); err != nil {
			return fmt.Errorf("JWT contains invalid base64url: %w", err)
		}
	}

	keyJSON, err := os.ReadFile(*keyFile)
	if err != nil {
		return fmt.Errorf("read public keys: %w", err)
	}
	selected, err := selectPublicKey(keyJSON, header.Algorithm, header.KeyID)
	if err != nil {
		return err
	}
	keys, err := jwk.Parse(selected)
	if err != nil {
		return fmt.Errorf("parse AKP public key: %w", err)
	}
	// Verify the signature first, so an expired captured JWT can still be
	// checked explicitly with -signature-only. No URLs from the JWT are fetched.
	token, err := jwt.Parse(encoded, jwt.WithKeySet(keys), jwt.WithValidate(false))
	if err != nil {
		return fmt.Errorf("signature: %w", err)
	}
	if !*signatureOnly {
		var options []jwt.ValidateOption
		if *issuer != "" {
			options = append(options, jwt.WithIssuer(*issuer))
		}
		if *audience != "" {
			options = append(options, jwt.WithAudience(*audience))
		}
		if err := jwt.Validate(token, options...); err != nil {
			return fmt.Errorf("signature valid, but claim validation failed: %w", err)
		}
	}
	fmt.Printf("Signature valid: alg=%s kid=%s\n", header.Algorithm, header.KeyID)
	if *signatureOnly {
		fmt.Println("Claims were not validated (-signature-only).")
	} else {
		fmt.Println("Standard time checks passed; issuer/audience checked when supplied.")
	}
	return nil
}

func selectPublicKey(data []byte, algorithm, kid string) ([]byte, error) {
	var document map[string]json.RawMessage
	if err := json.Unmarshal(data, &document); err != nil {
		return nil, fmt.Errorf("parse JWK/JWKS JSON: %w", err)
	}
	var candidates []map[string]any
	if raw, ok := document["keys"]; ok {
		if err := json.Unmarshal(raw, &candidates); err != nil {
			return nil, fmt.Errorf("parse JWKS keys: %w", err)
		}
	} else {
		var key map[string]any
		if err := json.Unmarshal(data, &key); err != nil {
			return nil, err
		}
		// A directly supplied public JWK may omit kid; it is the trusted key.
		if _, ok := key["kid"]; !ok {
			key["kid"] = kid
		}
		candidates = append(candidates, key)
	}
	var matching []map[string]any
	for _, key := range candidates {
		if key["kid"] != kid || key["alg"] != algorithm {
			continue
		}
		if key["kty"] != "AKP" {
			return nil, errors.New("matching ML-DSA key must have kty AKP")
		}
		if _, private := key["priv"]; private {
			return nil, errors.New("supply a public JWK; private key material is unnecessary")
		}
		public, ok := key["pub"].(string)
		if !ok || public == "" {
			return nil, errors.New("matching AKP key has no pub value")
		}
		matching = append(matching, key)
	}
	if len(matching) != 1 {
		return nil, fmt.Errorf("expected exactly one public key matching kid=%q alg=%q; found %d", kid, algorithm, len(matching))
	}
	return json.Marshal(map[string]any{"keys": matching})
}
