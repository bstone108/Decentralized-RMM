package pack

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/bstone108/Decentralized-RMM/internal/desktop"
	"github.com/bstone108/Decentralized-RMM/internal/enroll"
	"github.com/bstone108/Decentralized-RMM/internal/identity"
)

func TestBuildVerifyAndRefuseSecrets(t *testing.T) {
	pub, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	res, err := Build(out, Request{
		GOOS:        runtime.GOOS,
		GOARCH:      runtime.GOARCH,
		AgentBinary: []byte("fake-agent-binary"),
		Publisher:   pub,
		Spec: enroll.Spec{
			OrgID:          "acme",
			AllowedCIDRs:   []string{"10.0.0.0/8"},
			BootstrapPeers: []enroll.BootstrapPeer{{NodeID: pub.Public.NodeID, Address: "10.0.0.9:7946", Kind: "configured"}},
			DesktopMode:    desktop.ModeUnattended,
			MaxUses:        1,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyIndependent(res.Dir); err != nil {
		t.Fatal(err)
	}
	policy, _ := os.ReadFile(res.PolicyPath)
	if len(policy) == 0 {
		t.Fatal("policy visibility required")
	}
	if _, err := os.Stat(filepath.Join(res.Dir, "enrollment.token")); err != nil {
		t.Fatal(err)
	}
	if err := ScanForbidden(res.Dir, pub); err != nil {
		t.Fatal(err)
	}
}

func TestConfigurableUsesUniqueGrantsAndNoSecrets(t *testing.T) {
	pub, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	base := enroll.Spec{
		OrgID:          "acme",
		AllowedCIDRs:   []string{"10.0.0.0/8"},
		BootstrapPeers: []enroll.BootstrapPeer{{NodeID: pub.Public.NodeID, Address: "10.0.0.9:7946", Kind: "configured"}},
	}
	modes := []enroll.AllowedUses{
		{Mode: enroll.UseExactlyOne, Count: 1},
		{Mode: enroll.UseFinite, Count: 7},
		{Mode: enroll.UseUnlimited},
	}
	seen := map[string]bool{}
	for _, uses := range modes {
		spec := base
		spec.AllowedUses = uses
		res, err := Build(t.TempDir(), Request{
			GOOS: runtime.GOOS, GOARCH: runtime.GOARCH,
			AgentBinary: []byte("fake-agent-binary"), Publisher: pub, Spec: spec,
		})
		if err != nil {
			t.Fatal(uses, err)
		}
		if res.GrantID == "" || seen[res.GrantID] {
			t.Fatalf("unique grant id required: %s", res.GrantID)
		}
		seen[res.GrantID] = true
		if err := VerifyIndependent(res.Dir); err != nil {
			t.Fatal(err)
		}
		if err := ScanForbidden(res.Dir, pub); err != nil {
			t.Fatal(err)
		}
		policy, err := os.ReadFile(res.PolicyPath)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(policy, []byte(uses.PolicyLine())) {
			t.Fatalf("POLICY.txt missing %q in %s", uses.PolicyLine(), policy)
		}
	}
}

func TestWindowsAndDarwinTrees(t *testing.T) {
	pub, _ := identity.Generate()
	spec := enroll.Spec{
		OrgID: "x", AllowedCIDRs: []string{"10.0.0.0/8"},
		BootstrapPeers: []enroll.BootstrapPeer{{NodeID: "rmm1:a", Address: "10.1.1.1:1", Kind: "configured"}},
	}
	for _, osname := range []string{"windows", "darwin"} {
		res, err := Build(t.TempDir(), Request{GOOS: osname, GOARCH: "amd64", AgentBinary: []byte("bin"), Publisher: pub, Spec: spec})
		if err != nil {
			t.Fatal(osname, err)
		}
		if err := VerifyIndependent(res.Dir); err != nil {
			t.Fatal(osname, err)
		}
	}
}
