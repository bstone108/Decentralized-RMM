package update

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/bstone108/Decentralized-RMM/internal/protocol"
)

const ChunkSize = 64 * 1024

type sender interface {
	Send(protocol.Message) error
}

type recver interface {
	Send(protocol.Message) error
	Recv() (protocol.Message, error)
}

func SendEnvelope(s sender, env Envelope) error {
	raw, err := json.Marshal(env)
	if err != nil {
		return err
	}
	total := len(raw)
	for off := 0; off < total; off += ChunkSize {
		end := off + ChunkSize
		if end > total {
			end = total
		}
		chunk := protocol.ArtifactChunk{
			Component: string(env.Artifact.Component),
			Version:   env.Artifact.Version,
			GOOS:      env.Artifact.GOOS,
			GOARCH:    env.Artifact.GOARCH,
			SHA256:    env.Artifact.SHA256,
			Offset:    off,
			Total:     total,
			Data:      raw[off:end],
			Last:      end == total,
		}
		if err := s.Send(protocol.Message{Type: protocol.TypeArtifactChunk, ArtifactChunk: &chunk}); err != nil {
			return err
		}
	}
	return nil
}

func RecvEnvelope(s recver, req protocol.ArtifactRequest) (Envelope, error) {
	if err := s.Send(protocol.Message{Type: protocol.TypeArtifactRequest, ArtifactRequest: &req}); err != nil {
		return Envelope{}, err
	}
	var buf bytes.Buffer
	var total int
	var sha string
	for {
		msg, err := s.Recv()
		if err != nil {
			return Envelope{}, err
		}
		if msg.Type == protocol.TypeError && msg.Error != nil {
			return Envelope{}, fmt.Errorf("peer: %s: %s", msg.Error.Code, msg.Error.Message)
		}
		if msg.Type != protocol.TypeArtifactChunk || msg.ArtifactChunk == nil {
			return Envelope{}, fmt.Errorf("expected artifact_chunk, got %s", msg.Type)
		}
		c := msg.ArtifactChunk
		if sha == "" {
			sha = c.SHA256
			total = c.Total
		}
		if c.SHA256 != sha || c.Offset != buf.Len() {
			return Envelope{}, fmt.Errorf("artifact chunk mismatch")
		}
		if _, err := buf.Write(c.Data); err != nil {
			return Envelope{}, err
		}
		if c.Last {
			break
		}
	}
	if buf.Len() != total {
		return Envelope{}, fmt.Errorf("artifact size %d != declared %d", buf.Len(), total)
	}
	var env Envelope
	if err := json.Unmarshal(buf.Bytes(), &env); err != nil {
		return Envelope{}, err
	}
	if env.Artifact.SHA256 != sha {
		return Envelope{}, fmt.Errorf("envelope hash does not match chunk declaration")
	}
	return env, nil
}
