package update

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// RemoteAsset is a candidate release file. It is not trusted until Verify.
type RemoteAsset struct {
	Name      string
	URL       string
	GOOS      string
	GOARCH    string
	Component Component
}

type Source interface {
	List(ctx context.Context) ([]RemoteAsset, error)
	Fetch(ctx context.Context, url string) ([]byte, error)
}

// GitHubSource lists GitHub Release assets. Recipients still verify publisher
// signature, hash, version policy, OS/arch, and expiry independently.
type GitHubSource struct {
	Owner  string
	Repo   string
	Tag    string // empty = latest
	Client *http.Client
}

func (g GitHubSource) client() *http.Client {
	if g.Client != nil {
		return g.Client
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (g GitHubSource) List(ctx context.Context) ([]RemoteAsset, error) {
	path := fmt.Sprintf("https://api.github.com/repos/%s/%s/releases/latest", g.Owner, g.Repo)
	if g.Tag != "" {
		path = fmt.Sprintf("https://api.github.com/repos/%s/%s/releases/tags/%s", g.Owner, g.Repo, g.Tag)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := g.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github release status %s", resp.Status)
	}
	var body struct {
		Assets []struct {
			Name string `json:"name"`
			URL  string `json:"browser_download_url"`
		} `json:"assets"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, err
	}
	var out []RemoteAsset
	for _, a := range body.Assets {
		if !strings.HasSuffix(a.Name, ".rmm-artifact") {
			continue
		}
		comp, goos, goarch, ok := parseAssetName(strings.TrimSuffix(a.Name, ".rmm-artifact"))
		if !ok {
			continue
		}
		out = append(out, RemoteAsset{Name: a.Name, URL: a.URL, Component: comp, GOOS: goos, GOARCH: goarch})
	}
	return out, nil
}

func (g GitHubSource) Fetch(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := g.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download status %s", resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 64<<20))
}

func parseAssetName(name string) (Component, string, string, bool) {
	// rmm-agent-linux-amd64
	parts := strings.Split(name, "-")
	if len(parts) < 4 {
		return "", "", "", false
	}
	goarch := parts[len(parts)-1]
	goos := parts[len(parts)-2]
	comp := Component(strings.Join(parts[:len(parts)-2], "-"))
	switch comp {
	case ComponentAgent, ComponentConsole, ComponentPack:
	default:
		return "", "", "", false
	}
	return comp, goos, goarch, true
}

type MemorySource struct {
	Assets map[string][]byte
	ListFn func() []RemoteAsset
}

func (m MemorySource) List(ctx context.Context) ([]RemoteAsset, error) {
	_ = ctx
	if m.ListFn != nil {
		return m.ListFn(), nil
	}
	return nil, nil
}

func (m MemorySource) Fetch(ctx context.Context, url string) ([]byte, error) {
	_ = ctx
	b, ok := m.Assets[url]
	if !ok {
		return nil, fmt.Errorf("missing %s", url)
	}
	return append([]byte(nil), b...), nil
}
