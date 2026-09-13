package vault

import (
	"context"
	"reflect"
	"testing"
	"time"
)

// TestRoleKeyUsageTranslatesVaultsNames.
func TestRoleKeyUsageTranslatesVaultsNames(t *testing.T) {
	role := &roleData{KeyUsage: []string{"DigitalSignature", "KeyCertSign", "CRLSign"}}
	got := roleKeyUsage(role)
	want := []string{"cRLSign", "digitalSignature", "keyCertSign"} // sorted
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// TestRoleKeyUsageOfNoConstraintIsEmpty. Vault's own meaning for an empty
// key_usage list is "no constraint", and this must not be confused with "the
// certificate can carry no key usage at all" — represented the same way, as
// an empty slice, but the two attach at different points: this file is a
// description of what will be produced, and empty here just means nothing
// was declared to check.
func TestRoleKeyUsageOfNoConstraintIsEmpty(t *testing.T) {
	if got := roleKeyUsage(&roleData{}); len(got) != 0 {
		t.Errorf("expected no key usage from an empty role list, got %v", got)
	}
}

// TestRoleKeyUsageDropsWhatItCannotName. A Vault key_usage entry this
// vocabulary has no word for must not silently pass as some other name, and
// must not be invented — it disappears, which is the honest answer for
// something that cannot be compared to a template's declared list at all.
func TestRoleKeyUsageDropsWhatItCannotName(t *testing.T) {
	role := &roleData{KeyUsage: []string{"DigitalSignature", "SomethingVaultInventsLater"}}
	got := roleKeyUsage(role)
	if len(got) != 1 || got[0] != "digitalSignature" {
		t.Errorf("expected only the recognised name to survive, got %v", got)
	}
}

// TestRoleExtendedKeyUsageReadsTheFourFlags.
func TestRoleExtendedKeyUsageReadsTheFourFlags(t *testing.T) {
	cases := []struct {
		name string
		role roleData
		want []string
	}{
		{"all off", roleData{}, nil},
		{"server only", roleData{ServerFlag: true}, []string{"serverAuth"}},
		{"server and client", roleData{ServerFlag: true, ClientFlag: true},
			[]string{"clientAuth", "serverAuth"}},
		{"every flag", roleData{ServerFlag: true, ClientFlag: true, CodeSigningFlag: true, EmailProtectionFlag: true},
			[]string{"clientAuth", "codeSigning", "emailProtection", "serverAuth"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := roleExtendedKeyUsage(&c.role)
			if len(got) == 0 && len(c.want) == 0 {
				return
			}
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("got %v, want %v", got, c.want)
			}
		})
	}
}

// TestCheckKeyUsageAgainstRoleAllowsASubset. A template may declare fewer
// usages than the role produces for every certificate — that is the template
// being more specific, not a conflict.
func TestCheckKeyUsageAgainstRoleAllowsASubset(t *testing.T) {
	fake := newFakeVault(t, 365*24*time.Hour)
	fake.addRole("mesh", map[string]any{
		"server_flag": true, "client_flag": true,
		"key_usage": []string{"DigitalSignature", "KeyEncipherment"},
	})
	p := NewProvider(Options{})
	cfg, err := p.config(fake.configFor("mesh"))
	if err != nil {
		t.Fatalf("config: %v", err)
	}

	if err := p.checkKeyUsageAgainstRole(context.Background(), cfg,
		[]string{"digitalSignature"}, []string{"serverAuth"}); err != nil {
		t.Errorf("a subset of what the role produces must be accepted: %v", err)
	}
}

// TestCheckKeyUsageAgainstRoleRefusesWhatTheRoleCannotProduce.
func TestCheckKeyUsageAgainstRoleRefusesWhatTheRoleCannotProduce(t *testing.T) {
	fake := newFakeVault(t, 365*24*time.Hour)
	fake.addRole("server-only", map[string]any{"server_flag": true, "client_flag": false})
	p := NewProvider(Options{})
	cfg, err := p.config(fake.configFor("server-only"))
	if err != nil {
		t.Fatalf("config: %v", err)
	}

	err = p.checkKeyUsageAgainstRole(context.Background(), cfg, nil, []string{"clientAuth"})
	if err == nil {
		t.Fatal("declaring an EKU the role's flags do not set must be refused")
	}
}

// TestCheckKeyUsageAgainstRoleSkipsWhenNothingDeclared. A template naming no
// key usage at all has nothing to check, and reading the role for no reason
// costs a Vault round trip on every issuance that does not need one. No fake
// server is set up at all: a network call here would fail this test, which
// is exactly the assertion.
func TestCheckKeyUsageAgainstRoleSkipsWhenNothingDeclared(t *testing.T) {
	p := &Provider{}
	if err := p.checkKeyUsageAgainstRole(context.Background(), &Config{Role: "whatever", Address: "http://127.0.0.1:1"}, nil, nil); err != nil {
		t.Errorf("nothing declared should need no role read and refuse nothing: %v", err)
	}
}
