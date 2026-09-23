package consoleui

import (
	"strings"
	"testing"

	"github.com/bstone108/Decentralized-RMM/internal/desktop"
	"github.com/bstone108/Decentralized-RMM/internal/enroll"
	"github.com/bstone108/Decentralized-RMM/internal/identity"
)

func TestPresenterShowsEnrollmentPolicy(t *testing.T) {
	issuer, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := enroll.Issue(issuer, enroll.Spec{
		OrgID: "acme", AllowedCIDRs: []string{"10.0.0.0/8"},
		BootstrapPeers: []enroll.BootstrapPeer{{NodeID: issuer.Public.NodeID, Address: "10.0.0.1:1", Kind: "configured"}},
		DesktopMode:    desktop.ModeUnattended,
	})
	if err != nil {
		t.Fatal(err)
	}
	rec := &Recorder{}
	title, body := EnrollmentPolicy(bundle.Manifest)
	if err := rec.ShowPolicy(title, body); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rec.LastBody, "identity-signed") || !strings.Contains(rec.LastBody, "unattended") {
		t.Fatalf("%s", rec.LastBody)
	}
}
