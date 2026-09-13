package vault

import (
	"context"
	"fmt"
	"sort"
	"strings"

	providerv1 "github.com/certpilot/certpilot-gateway-sdk/pb/provider/v1"
)

// roleKeyUsage translates a Vault role's key_usage list into this contract's
// vocabulary.
//
// Vault's names are the Go x509 constant names without the package prefix
// (DigitalSignature, KeyEncipherment, ...); the contract's are the RFC 5280
// field names in lowerCamelCase, matching the casing every other gateway and
// the template store use. An empty role list is significant on Vault's side
// — it means "no key usage constraint", not "no keys usable" — and is passed
// through as empty rather than guessed at.
func roleKeyUsage(role *roleData) []string {
	out := make([]string, 0, len(role.KeyUsage))
	for _, v := range role.KeyUsage {
		if mapped, ok := vaultKeyUsageNames[strings.ToLower(v)]; ok {
			out = append(out, mapped)
		}
		// An unrecognised name is dropped rather than passed through
		// verbatim: this list is compared against a template's declared
		// key_usage, which is drawn from the same fixed vocabulary, and a
		// name from Vault that does not appear in it can never match
		// anything the template could have said.
	}
	sort.Strings(out)
	return out
}

var vaultKeyUsageNames = map[string]string{
	"digitalsignature":  "digitalSignature",
	"keyencipherment":   "keyEncipherment",
	"keyagreement":      "keyAgreement",
	"keycertsign":       "keyCertSign",
	"crlsign":           "cRLSign",
	"dataencipherment":  "dataEncipherment",
	"contentcommitment": "contentCommitment",
	"nonrepudiation":    "contentCommitment", // Vault's older alias for the same bit
	"encipheronly":      "encipherOnly",
	"decipheronly":      "decipherOnly",
}

// roleExtendedKeyUsage translates a role's four EKU flags into this
// contract's vocabulary. Vault's ext_key_usage (arbitrary Go x509.ExtKeyUsage
// names or OIDs) is intentionally not read here: it is a role escape hatch
// for purposes this vocabulary has no name for, and guessing at a mapping
// would be worse than the honest "not represented" that leaving it out gives.
func roleExtendedKeyUsage(role *roleData) []string {
	var out []string
	if role.ServerFlag {
		out = append(out, "serverAuth")
	}
	if role.ClientFlag {
		out = append(out, "clientAuth")
	}
	if role.CodeSigningFlag {
		out = append(out, "codeSigning")
	}
	if role.EmailProtectionFlag {
		out = append(out, "emailProtection")
	}
	sort.Strings(out)
	return out
}

// DescribeProfile reports what a Vault role's own configuration will produce,
// which is definite: these fields decide the certificate's key usage and
// extended key usage entirely, before a request is ever sent, and nothing in
// an issue or sign request body can change that — see the comment on
// roleData for how that was confirmed.
func (p *Provider) DescribeProfile(
	ctx context.Context, req *providerv1.DescribeProfileRequest,
) (*providerv1.DescribeProfileResponse, error) {
	cfg, err := p.config(req.ProviderConfig)
	if err != nil {
		return nil, err
	}
	roleCfg := cfg.WithRole(req.CaProfile)
	ctx, cancel := deadline(ctx, roleCfg)
	defer cancel()

	role, err := p.readRole(ctx, roleCfg)
	if err != nil {
		return nil, p.translate(err)
	}

	return &providerv1.DescribeProfileResponse{
		IsDefinite:       true,
		KeyUsage:         roleKeyUsage(role),
		ExtendedKeyUsage: roleExtendedKeyUsage(role),
	}, nil
}

// checkKeyUsageAgainstRole refuses a declared key usage or extended key usage
// the selected role cannot produce, reading the role rather than sending the
// request and hoping — see the comment on roleData.
//
// Subset, not equality: a template may declare fewer usages than a shared
// role would produce for every certificate it issues, and that is the
// template being more specific than the role, not a conflict with it.
func (p *Provider) checkKeyUsageAgainstRole(
	ctx context.Context, cfg *Config, wantKeyUsage, wantEKU []string,
) error {
	if len(wantKeyUsage) == 0 && len(wantEKU) == 0 {
		return nil
	}
	role, err := p.readRole(ctx, cfg)
	if err != nil {
		return fmt.Errorf(
			"a key usage or extended key usage was declared, and role %q could not be read to check it: %w",
			cfg.Role, err)
	}

	haveKU := roleKeyUsage(role)
	if missing := notIn(wantKeyUsage, haveKU); len(missing) > 0 {
		return fmt.Errorf(
			"role %q produces key usage %s and cannot produce %s",
			cfg.Role, describeOrNone(haveKU), strings.Join(missing, ", "))
	}
	haveEKU := roleExtendedKeyUsage(role)
	if missing := notIn(wantEKU, haveEKU); len(missing) > 0 {
		return fmt.Errorf(
			"role %q produces extended key usage %s (server_flag=%v client_flag=%v code_signing_flag=%v email_protection_flag=%v) and cannot produce %s",
			cfg.Role, describeOrNone(haveEKU),
			role.ServerFlag, role.ClientFlag, role.CodeSigningFlag, role.EmailProtectionFlag,
			strings.Join(missing, ", "))
	}
	return nil
}

func describeOrNone(names []string) string {
	if len(names) == 0 {
		return "none"
	}
	return strings.Join(names, ", ")
}
