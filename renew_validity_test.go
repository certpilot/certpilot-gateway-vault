package vault

import (
	"context"
	"testing"
	"time"

	providerv1 "github.com/certpilot/certpilot-gateway-sdk/pb/provider/v1"
	"github.com/certpilot/certpilot-gateway-sdk/x509util"
)

// certpilot/certpilot#102, measured against a real Vault 2.0.3 in #107: a
// certificate issued for 90 days renewed into 32, because a renewal carried no
// lifetime and Vault applied the role's default TTL. The core now restates the
// lifetime on every renewal, and it is sent to Vault as the ttl, exactly as on
// issuance.
func TestARenewalAsksVaultForTheLifetimeTheCoreAskedFor(t *testing.T) {
	fake := newFakeVault(t, 365*24*time.Hour)
	p := NewProvider(Options{})
	ctx := context.Background()

	issued, err := p.IssueCertificate(ctx, &providerv1.IssueCertificateRequest{
		Domains:        []string{"api.example.com"},
		ValidityDays:   90,
		ProviderConfig: fake.config(),
	})
	if err != nil {
		t.Fatalf("issuing: %v", err)
	}
	renewed, err := p.RenewCertificate(ctx, &providerv1.RenewCertificateRequest{
		ProviderCertificateId: issued.ProviderCertificateId,
		CurrentCertificatePem: issued.Certificate.CertificatePem,
		ValidityDays:          90,
		ProviderConfig:        fake.config(),
	})
	if err != nil {
		t.Fatalf("renewing: %v", err)
	}

	for name, pemBytes := range map[string][]byte{
		"issued":  issued.Certificate.CertificatePem,
		"renewed": renewed.Certificate.CertificatePem,
	} {
		info, err := x509util.ParseCertificatePEM(pemBytes)
		if err != nil {
			t.Fatalf("parsing the %s certificate: %v", name, err)
		}
		if got := info.NotAfter.Sub(info.NotBefore); got < 89*24*time.Hour || got > 91*24*time.Hour {
			t.Errorf("the %s certificate lasts %v; 90 days were asked for", name, got.Round(time.Hour))
		}
	}
}
