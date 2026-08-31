package localpeer

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Advertisement is a same-computer presence hint. Discovery still grants
// nothing: a console must verify the advertised identity in its trust store
// before opening a local authenticated session.
type Advertisement struct {
	NodeID       string    `json:"nodeID"`
	PublicKey    string    `json:"publicKey"`
	BoxPublicKey string    `json:"boxPublicKey,omitempty"`
	Role         string    `json:"role"`
	ListenAddr   string    `json:"listenAddr"`
	WrittenAt    time.Time `json:"writtenAt"`
}

func Path(dataDir string) string {
	return filepath.Join(dataDir, "local.advertise.json")
}

func Write(dataDir string, adv Advertisement) error {
	if adv.Role != "agent" {
		return fmt.Errorf("only a platform agent may advertise local mesh presence")
	}
	if adv.NodeID == "" || adv.PublicKey == "" || adv.ListenAddr == "" {
		return fmt.Errorf("advertisement requires identity and listen address")
	}
	adv.WrittenAt = time.Now().UTC()
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(adv, "", "  ")
	if err != nil {
		return err
	}
	tmp := Path(dataDir) + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	_ = os.Chmod(tmp, 0o600)
	if err := os.Rename(tmp, Path(dataDir)); err != nil {
		return err
	}
	return os.Chmod(Path(dataDir), 0o600)
}

func Read(dataDir string) (Advertisement, bool, error) {
	raw, err := os.ReadFile(Path(dataDir))
	if os.IsNotExist(err) {
		return Advertisement{}, false, nil
	}
	if err != nil {
		return Advertisement{}, false, err
	}
	var adv Advertisement
	if err := json.Unmarshal(raw, &adv); err != nil {
		return Advertisement{}, false, err
	}
	if adv.Role != "agent" {
		return Advertisement{}, false, fmt.Errorf("ignoring non-agent local advertisement")
	}
	return adv, true, nil
}

func Remove(dataDir string) error {
	err := os.Remove(Path(dataDir))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

func DataDirFromStorePath(storePath string) string {
	return filepath.Dir(storePath)
}
