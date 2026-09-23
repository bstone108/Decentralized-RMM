package node

import (
	"fmt"

	"github.com/bstone108/Decentralized-RMM/internal/enroll"
	"github.com/bstone108/Decentralized-RMM/internal/mesh"
	"github.com/bstone108/Decentralized-RMM/internal/protocol"
	"github.com/bstone108/Decentralized-RMM/internal/update"
)

func (n *Node) artifactOffer() *protocol.ArtifactOffer {
	arts, err := n.updateCache.List()
	if err != nil {
		return &protocol.ArtifactOffer{}
	}
	out := make([]protocol.ArtifactMeta, 0, len(arts))
	for _, a := range arts {
		out = append(out, protocol.ArtifactMeta{
			Component:       string(a.Component),
			Version:         a.Version,
			GOOS:            a.GOOS,
			GOARCH:          a.GOARCH,
			SHA256:          a.SHA256,
			Size:            a.Size,
			PublisherNodeID: a.PublisherNodeID,
		})
	}
	return &protocol.ArtifactOffer{Artifacts: out}
}

func (n *Node) serveArtifactRequest(sess *mesh.Session, req protocol.ArtifactRequest) error {
	env, ok, err := n.updateCache.Get(update.Component(req.Component), req.Version, req.GOOS, req.GOARCH)
	if err != nil {
		return err
	}
	if !ok {
		return sess.Send(protocol.Message{Type: protocol.TypeError, Error: &protocol.Error{
			Code: "artifact_not_found", Message: "no independently verified artifact in cache",
		}})
	}
	return update.SendEnvelope(sess, env)
}

// PullArtifact copies a cached signed artifact from a trusted peer, then
// independently verifies publisher signature, hash, and expiry. Foreign OS
// artifacts may be cached; they are never applied here.
func (n *Node) PullArtifact(sess *mesh.Session, req protocol.ArtifactRequest, trustedPublisher string) error {
	if trustedPublisher == "" {
		if pub, ok, err := enroll.LoadPublisher(n.Store); err != nil {
			return err
		} else if ok {
			trustedPublisher = pub
		}
	}
	if trustedPublisher == "" {
		return fmt.Errorf("trusted release publisher is required; peers cannot introduce untrusted updates")
	}
	env, err := update.RecvEnvelope(sess, req)
	if err != nil {
		return err
	}
	return update.AcceptFromPeer(n.updateCache, env, trustedPublisher)
}
