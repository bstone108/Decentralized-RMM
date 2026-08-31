package pack

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/bstone108/Decentralized-RMM/internal/enroll"
	"github.com/bstone108/Decentralized-RMM/internal/identity"
	"github.com/bstone108/Decentralized-RMM/internal/store"
)

type Request struct {
	GOOS          string
	GOARCH        string
	AgentBinary   []byte
	ConsoleBinary []byte
	Publisher     identity.Private
	Spec          enroll.Spec
	Ledger        store.Store // issuer ledger; private keys are never packed
}

type Result struct {
	Dir            string
	GrantID        string
	ManifestPath   string
	TokenPath      string
	PolicyPath     string
	AgentSHA256    string
	ManifestSHA256 string
}

func Build(outDir string, req Request) (Result, error) {
	if req.GOOS == "" {
		req.GOOS = runtime.GOOS
	}
	if req.GOARCH == "" {
		req.GOARCH = runtime.GOARCH
	}
	if len(req.AgentBinary) == 0 {
		return Result{}, fmt.Errorf("agent binary is required")
	}
	req.Spec.TargetOS = []string{req.GOOS}
	req.Spec.TargetArch = []string{req.GOARCH}
	bundle, err := enroll.Issue(req.Publisher, req.Spec)
	if err != nil {
		return Result{}, err
	}
	if req.Ledger != nil {
		if err := enroll.RegisterGrant(req.Ledger, bundle.Manifest); err != nil {
			return Result{}, err
		}
	}
	dir := filepath.Join(outDir, req.GOOS+"-"+req.GOARCH)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return Result{}, err
	}
	agentName := "rmm-agent"
	if req.GOOS == "windows" {
		agentName += ".exe"
	}
	if err := os.WriteFile(filepath.Join(dir, agentName), req.AgentBinary, 0o755); err != nil {
		return Result{}, err
	}
	if len(req.ConsoleBinary) > 0 {
		cname := "rmm-console"
		if req.GOOS == "windows" {
			cname += ".exe"
		}
		if err := os.WriteFile(filepath.Join(dir, cname), req.ConsoleBinary, 0o755); err != nil {
			return Result{}, err
		}
	}
	manRaw, err := json.MarshalIndent(bundle.Manifest, "", "  ")
	if err != nil {
		return Result{}, err
	}
	if err := os.WriteFile(filepath.Join(dir, "enrollment.manifest.json"), manRaw, 0o644); err != nil {
		return Result{}, err
	}
	if err := os.WriteFile(filepath.Join(dir, "enrollment.token"), []byte(enroll.TokenEncode(bundle.Token)+"\n"), 0o600); err != nil {
		return Result{}, err
	}
	if err := os.WriteFile(filepath.Join(dir, "POLICY.txt"), []byte(enroll.PolicyText(bundle.Manifest)), 0o644); err != nil {
		return Result{}, err
	}
	if err := writeNative(dir, req.GOOS, agentName); err != nil {
		return Result{}, err
	}
	if err := ScanForbidden(dir, req.Publisher); err != nil {
		return Result{}, err
	}
	agentSum := sha256.Sum256(req.AgentBinary)
	manSum := sha256.Sum256(manRaw)
	return Result{
		Dir:            dir,
		GrantID:        bundle.Manifest.Grant(),
		ManifestPath:   filepath.Join(dir, "enrollment.manifest.json"),
		TokenPath:      filepath.Join(dir, "enrollment.token"),
		PolicyPath:     filepath.Join(dir, "POLICY.txt"),
		AgentSHA256:    hex.EncodeToString(agentSum[:]),
		ManifestSHA256: hex.EncodeToString(manSum[:]),
	}, nil
}

func VerifyIndependent(dir string) error {
	manRaw, err := os.ReadFile(filepath.Join(dir, "enrollment.manifest.json"))
	if err != nil {
		return err
	}
	var m enroll.Manifest
	if err := json.Unmarshal(manRaw, &m); err != nil {
		return err
	}
	if _, err := enroll.Verify(m); err != nil {
		return fmt.Errorf("manifest: %w", err)
	}
	tokRaw, err := os.ReadFile(filepath.Join(dir, "enrollment.token"))
	if err != nil {
		return err
	}
	token, err := enroll.TokenDecode(strings.TrimSpace(string(tokRaw)))
	if err != nil {
		return err
	}
	if err := enroll.VerifyToken(m, token); err != nil {
		return err
	}
	policy, err := os.ReadFile(filepath.Join(dir, "POLICY.txt"))
	if err != nil {
		return err
	}
	if !bytes.Contains(policy, []byte("identity-signed")) {
		return fmt.Errorf("POLICY.txt missing identity-signed enrollment text")
	}
	return nil
}

func ScanForbidden(dir string, publisher identity.Private) error {
	seed := publisher.SeedBase64()
	return filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		lower := bytes.ToLower(raw)
		if bytes.Contains(lower, []byte(`"seed"`)) || bytes.Contains(raw, []byte(seed)) {
			return fmt.Errorf("%s would embed reusable private key material", path)
		}
		if bytes.Contains(lower, []byte(`"password"`)) {
			return fmt.Errorf("%s would embed a password", path)
		}
		if bytes.Contains(raw, []byte("0.0.0.0/0")) || bytes.Contains(raw, []byte("::/0")) {
			return fmt.Errorf("%s grants unrestricted network access", path)
		}
		return nil
	})
}

func writeNative(dir, goos, agentName string) error {
	switch goos {
	case "linux":
		unit := `[Unit]
Description=Decentralized-RMM platform agent
After=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/rmm-agent listen --data /var/lib/rmm --addr 127.0.0.1:7946
Restart=on-failure

[Install]
WantedBy=multi-user.target
`
		if err := os.WriteFile(filepath.Join(dir, "rmm-agent.service"), []byte(unit), 0o644); err != nil {
			return err
		}
		sh := `#!/bin/sh
set -eu
DIR=$(cd "$(dirname "$0")" && pwd)
echo "Enrollment policy:"
cat "$DIR/POLICY.txt"
install -m 0755 "$DIR/` + agentName + `" /usr/local/bin/rmm-agent
install -m 0644 "$DIR/rmm-agent.service" /etc/systemd/system/rmm-agent.service
		install -d -m 0700 /var/lib/rmm
		install -m 0644 "$DIR/enrollment.manifest.json" /var/lib/rmm/enrollment.manifest.json
		install -m 0600 "$DIR/enrollment.token" /var/lib/rmm/enrollment.token
		install -m 0644 "$DIR/POLICY.txt" /var/lib/rmm/POLICY.txt
		echo "Verify independently: rmm-pack verify --dir $DIR"
`
		return os.WriteFile(filepath.Join(dir, "install.sh"), []byte(sh), 0o755)
	case "darwin":
		plist := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>io.rmm.agent</string>
  <key>ProgramArguments</key><array>
    <string>/usr/local/bin/rmm-agent</string><string>listen</string>
    <string>--data</string><string>/var/lib/rmm</string>
  </array>
  <key>RunAtLoad</key><true/>
</dict></plist>
`
		if err := os.WriteFile(filepath.Join(dir, "io.rmm.agent.plist"), []byte(plist), 0o644); err != nil {
			return err
		}
		sh := `#!/bin/sh
set -eu
DIR=$(cd "$(dirname "$0")" && pwd)
cat "$DIR/POLICY.txt"
install -m 0755 "$DIR/` + agentName + `" /usr/local/bin/rmm-agent
install -m 0644 "$DIR/io.rmm.agent.plist" /Library/LaunchDaemons/io.rmm.agent.plist
install -d -m 0700 /var/lib/rmm
install -m 0644 "$DIR/enrollment.manifest.json" /var/lib/rmm/enrollment.manifest.json
install -m 0600 "$DIR/enrollment.token" /var/lib/rmm/enrollment.token
install -m 0644 "$DIR/POLICY.txt" /var/lib/rmm/POLICY.txt
`
		return os.WriteFile(filepath.Join(dir, "install.sh"), []byte(sh), 0o755)
	case "windows":
		ps := `$Dir = Split-Path -Parent $MyInvocation.MyCommand.Path
Get-Content "$Dir\POLICY.txt"
New-Item -ItemType Directory -Force -Path "$env:ProgramFiles\Decentralized-RMM" | Out-Null
New-Item -ItemType Directory -Force -Path "$env:ProgramData\rmm" | Out-Null
Copy-Item "$Dir\` + agentName + `" "$env:ProgramFiles\Decentralized-RMM\rmm-agent.exe"
Copy-Item "$Dir\enrollment.manifest.json" "$env:ProgramData\rmm\enrollment.manifest.json"
Copy-Item "$Dir\enrollment.token" "$env:ProgramData\rmm\enrollment.token"
Copy-Item "$Dir\POLICY.txt" "$env:ProgramData\rmm\POLICY.txt"
sc.exe create RMMAgent binPath= "$env:ProgramFiles\Decentralized-RMM\rmm-agent.exe listen --data $env:ProgramData\rmm"
`
		return os.WriteFile(filepath.Join(dir, "install.ps1"), []byte(ps), 0o644)
	default:
		return fmt.Errorf("unsupported installer os %s", goos)
	}
}
