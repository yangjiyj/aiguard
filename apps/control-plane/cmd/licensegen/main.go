package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	entlicense "github.com/yangjiyj/aiguard/apps/control-plane/internal/license"
)

type envMap map[string]string

func main() {
	if err := run(os.Args[1:], environ(), os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string, env map[string]string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("licensegen", flag.ContinueOnError)
	fs.SetOutput(stderr)
	mode := fs.String("mode", "prod", "signing mode: prod or dev")
	generateDevKey := fs.Bool("generate-dev-key", false, "generate a dev-only signing key; only valid with --mode dev")
	customer := fs.String("customer", "JJDGuard Enterprise Trial", "customer display name")
	customerID := fs.String("customer-id", "", "stable customer id")
	licenseType := fs.String("type", "trial", "license type: trial or enterprise")
	edition := fs.String("edition", "enterprise", "edition name")
	days := fs.Int("days", entlicense.TrialWindowDays, "valid days from now")
	maxUsers := fs.Int("max-users", 25, "maximum users, 0 means unlimited")
	features := fs.String("features", "agent_audit,content_retention,ide_proxy,sensitive_data_guard,web_ai", "comma separated features")
	products := fs.String("products", entlicense.ProductJJDGuardEnterprise, "comma separated product ids")
	keyID := fs.String("key-id", "", "license signing key id")
	privateKeyText := fs.String("private-key", env["JJD_LICENSE_SIGNING_PRIVATE_KEY"], "base64 ed25519 private key")
	deploymentMode := fs.String("deployment-mode", "none", "deployment binding mode: none, optional, required")
	deploymentID := fs.String("deployment-id", "", "deployment binding id")
	deploymentFingerprints := fs.String("deployment-fingerprint", "", "comma separated scope:algorithm:value fingerprints")
	outPath := fs.String("out", "", "license output file path")
	publicKeyOut := fs.String("public-key-out", "", "public key output file path")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *outPath == "" {
		return fmt.Errorf("--out is required")
	}

	priv, pub, err := loadSigningKey(*privateKeyText, *mode, *generateDevKey)
	if err != nil {
		return err
	}
	if strings.TrimSpace(*keyID) == "" {
		return fmt.Errorf("--key-id is required")
	}

	now := time.Now().UTC().Truncate(time.Second)
	payload, err := buildPayloadV2(payloadOptions{
		customerDisplayName: strings.TrimSpace(*customer),
		customerID:          strings.TrimSpace(*customerID),
		licenseType:         strings.TrimSpace(*licenseType),
		edition:             strings.TrimSpace(*edition),
		days:                *days,
		maxUsers:            *maxUsers,
		features:            splitCSV(*features),
		products:            splitCSV(*products),
		deploymentMode:      strings.TrimSpace(*deploymentMode),
		deploymentID:        strings.TrimSpace(*deploymentID),
		fingerprints:        strings.TrimSpace(*deploymentFingerprints),
		now:                 now,
	})
	if err != nil {
		return err
	}
	file, err := entlicense.SignV2(payload, strings.TrimSpace(*keyID), priv)
	if err != nil {
		return fmt.Errorf("sign license: %w", err)
	}
	if err := writeJSON(*outPath, file); err != nil {
		return fmt.Errorf("write license: %w", err)
	}

	publicKey := base64.RawURLEncoding.EncodeToString(pub)
	if *publicKeyOut != "" {
		if err := os.MkdirAll(filepath.Dir(*publicKeyOut), 0o755); err != nil {
			return fmt.Errorf("create public key dir: %w", err)
		}
		if err := os.WriteFile(*publicKeyOut, []byte(publicKey+"\n"), 0o644); err != nil {
			return fmt.Errorf("write public key: %w", err)
		}
	}

	fmt.Fprintf(stdout, "license=%s\n", *outPath)
	fmt.Fprintf(stdout, "license_id=%s\n", file.Payload.LicenseID)
	fmt.Fprintf(stdout, "key_id=%s\n", file.KeyID)
	fmt.Fprintf(stdout, "expires_at=%s\n", file.Payload.ExpiresAt)
	fmt.Fprintf(stdout, "products=%s\n", strings.Join(file.Payload.Subject.Products, ","))
	fmt.Fprintf(stdout, "features=%s\n", strings.Join(file.Payload.Features, ","))
	fmt.Fprintf(stdout, "deployment_binding_mode=%s\n", file.Payload.DeploymentBinding.Mode)
	fmt.Fprintf(stdout, "public_key=%s\n", publicKey)
	return nil
}

type payloadOptions struct {
	customerDisplayName string
	customerID          string
	licenseType         string
	edition             string
	days                int
	maxUsers            int
	features            []string
	products            []string
	deploymentMode      string
	deploymentID        string
	fingerprints        string
	now                 time.Time
}

func buildPayloadV2(opts payloadOptions) (entlicense.PayloadV2, error) {
	if opts.customerID == "" {
		return entlicense.PayloadV2{}, fmt.Errorf("--customer-id is required")
	}
	if opts.customerDisplayName == "" {
		return entlicense.PayloadV2{}, fmt.Errorf("--customer is required")
	}
	if opts.days <= 0 {
		return entlicense.PayloadV2{}, fmt.Errorf("--days must be positive")
	}
	if opts.maxUsers < 0 {
		return entlicense.PayloadV2{}, fmt.Errorf("--max-users must be >= 0")
	}
	features := normalizeList(opts.features)
	products := normalizeList(opts.products)
	if len(features) == 0 {
		return entlicense.PayloadV2{}, fmt.Errorf("--features is required")
	}
	if len(products) == 0 {
		return entlicense.PayloadV2{}, fmt.Errorf("--products is required")
	}
	binding, err := parseDeploymentBinding(opts.deploymentMode, opts.deploymentID, opts.fingerprints)
	if err != nil {
		return entlicense.PayloadV2{}, err
	}
	now := opts.now.UTC().Truncate(time.Second)
	return entlicense.PayloadV2{
		SchemaVersion: entlicense.SchemaVersionV2,
		LicenseID:     fmt.Sprintf("lic_v2_%s_%d", sanitize(opts.licenseType), now.Unix()),
		Customer: entlicense.CustomerV2{
			ID:          opts.customerID,
			DisplayName: opts.customerDisplayName,
		},
		Subject: entlicense.SubjectV2{
			DisplayName: "JJDGuard Enterprise License",
			Products:    products,
		},
		Edition:           opts.edition,
		IssuedAt:          now.Format(time.RFC3339),
		NotBefore:         now.Add(-time.Minute).Format(time.RFC3339),
		ExpiresAt:         now.Add(time.Duration(opts.days) * 24 * time.Hour).Format(time.RFC3339),
		MaxUsers:          opts.maxUsers,
		Features:          features,
		DeploymentBinding: binding,
		GracePolicy: entlicense.GracePolicy{
			ExpiryGraceDays:            7,
			ClockRollbackGraceHours:    24,
			OfflineRevocationStaleDays: 30,
		},
		RevocationInfo: entlicense.RevocationInfo{Mode: "none"},
		Issuer:         "huoxianbao-license-authority-prod",
	}, nil
}

func parseDeploymentBinding(mode, bindingID, rawFingerprints string) (entlicense.DeploymentBinding, error) {
	mode = strings.TrimSpace(mode)
	if mode == "" {
		mode = "none"
	}
	binding := entlicense.DeploymentBinding{Mode: mode}
	switch mode {
	case "none":
		return binding, nil
	case "optional", "required":
	default:
		return binding, fmt.Errorf("--deployment-mode must be none, optional, or required")
	}
	if bindingID == "" {
		return binding, fmt.Errorf("--deployment-id is required when deployment binding is enabled")
	}
	fingerprints, err := parseFingerprints(rawFingerprints)
	if err != nil {
		return binding, err
	}
	if len(fingerprints) == 0 {
		return binding, fmt.Errorf("--deployment-fingerprint is required when deployment binding is enabled")
	}
	binding.BindingID = bindingID
	binding.Fingerprints = fingerprints
	return binding, nil
}

func parseFingerprints(raw string) ([]entlicense.Fingerprint, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	parts := strings.Split(raw, ",")
	out := make([]entlicense.Fingerprint, 0, len(parts))
	for _, part := range parts {
		fields := strings.Split(strings.TrimSpace(part), ":")
		if len(fields) != 3 {
			return nil, fmt.Errorf("deployment fingerprint must use scope:algorithm:value")
		}
		out = append(out, entlicense.Fingerprint{
			Scope:     strings.TrimSpace(fields[0]),
			Algorithm: strings.TrimSpace(fields[1]),
			Value:     strings.TrimSpace(fields[2]),
		})
	}
	return out, nil
}

func loadSigningKey(raw, mode string, generateDevKey bool) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	raw = strings.TrimSpace(raw)
	mode = strings.TrimSpace(mode)
	if mode == "" {
		mode = "prod"
	}
	if raw == "" {
		if mode == "dev" && generateDevKey {
			pub, priv, err := ed25519.GenerateKey(nil)
			return priv, pub, err
		}
		return nil, nil, fmt.Errorf("private key is required in production mode")
	}
	key, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, nil, fmt.Errorf("decode private key: %w", err)
	}
	if len(key) != ed25519.PrivateKeySize {
		return nil, nil, fmt.Errorf("private key must be %d bytes after base64 decode", ed25519.PrivateKeySize)
	}
	priv := ed25519.PrivateKey(key)
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return nil, nil, fmt.Errorf("derive public key")
	}
	return priv, pub, nil
}

func writeJSON(path string, v interface{}) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

func splitCSV(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func normalizeList(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func sanitize(raw string) string {
	raw = strings.ToLower(strings.TrimSpace(raw))
	raw = strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			return r
		}
		return '_'
	}, raw)
	raw = strings.Trim(raw, "_")
	if raw == "" {
		return "license"
	}
	return raw
}

func environ() map[string]string {
	out := map[string]string{}
	for _, item := range os.Environ() {
		key, value, ok := strings.Cut(item, "=")
		if ok {
			out[key] = value
		}
	}
	return out
}
