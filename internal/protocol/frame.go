package protocol

import (
	"encoding/binary"
	"fmt"
	"io"
)

const MaxMessageBytes = 1 << 20

func WriteFrame(w io.Writer, payload []byte) error {
	if len(payload) > MaxMessageBytes {
		return fmt.Errorf("frame exceeds %d bytes", MaxMessageBytes)
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

func ReadFrame(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > MaxMessageBytes {
		return nil, fmt.Errorf("frame length %d exceeds max", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}
