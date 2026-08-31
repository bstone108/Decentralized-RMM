package node

import (
	"fmt"

	"github.com/bstone108/Decentralized-RMM/internal/enroll"
	"github.com/bstone108/Decentralized-RMM/internal/mesh"
	"github.com/bstone108/Decentralized-RMM/internal/protocol"
	"github.com/bstone108/Decentralized-RMM/internal/store"
)

func (n *Node) RevokeGrant(grantID, reason string) (enroll.RevocationNotice, error) {
	notice, err := enroll.SignRevocation(n.ID, grantID, reason)
	if err != nil {
		return enroll.RevocationNotice{}, err
	}
	if err := enroll.ApplyRevocation(n.Store, nil, notice); err != nil {
		return enroll.RevocationNotice{}, err
	}
	return notice, nil
}

func (n *Node) PublishRevocation(sess *mesh.Session, notice enroll.RevocationNotice) error {
	if err := sess.Send(protocol.Message{Type: protocol.TypeEnrollmentRevoke, EnrollmentRevoke: &notice}); err != nil {
		return err
	}
	msg, err := sess.Recv()
	if err != nil {
		return err
	}
	if msg.Type == protocol.TypeError && msg.Error != nil {
		return fmt.Errorf("peer: %s: %s", msg.Error.Code, msg.Error.Message)
	}
	if msg.Type != protocol.TypeEnrollmentRevoke {
		return fmt.Errorf("expected enrollment_revoke ack, got %s", msg.Type)
	}
	return nil
}

func (n *Node) RecordReportedUse(rec enroll.UseReceipt) error {
	uses := enroll.AllowedUses{Mode: rec.Mode, Count: rec.AllowedCount}
	var meta struct {
		AllowedUses enroll.AllowedUses `json:"allowedUses"`
	}
	ok, err := store.GetJSON(n.Store, store.Key(store.PrefixEnroll, "grant", rec.GrantID, "meta"), &meta)
	if err != nil {
		return err
	}
	if ok && meta.AllowedUses.Mode != "" {
		uses = meta.AllowedUses
	}
	return enroll.RecordLedgerUse(n.Store, rec, uses)
}
