package verify

import (
	"errors"
	"io"

	"github.com/LennardGeissler/blindbucket/internal/crypto/stream"
)

// SegmentChain decrypts the segments of a multipart object in order.
//
// Each part is its own segment and must be decrypted as one: a DecryptReader
// decides whether a chunk is the segment's last by looking one byte ahead, so
// feeding it the concatenation directly would make every part but the last fail
// authentication. Bounding each part to its exact ciphertext size is what puts
// the end of the stream where the format says it is.
type SegmentChain struct {
	src    io.Reader
	dek    []byte
	layout *Layout

	idx int
	cur *stream.DecryptReader
	err error
}

// NewSegmentChain opens the first part. src is the object's whole ciphertext.
func NewSegmentChain(src io.Reader, dek []byte, layout *Layout) (*SegmentChain, error) {
	c := &SegmentChain{src: src, dek: dek, layout: layout}
	if err := c.open(); err != nil {
		return nil, err
	}
	return c, nil
}

// VerifyFirst authenticates the first chunk of the first part, before the caller
// commits to a status line. See docs/adr/ADR-004-fail-closed.md.
func (c *SegmentChain) VerifyFirst() error {
	if c.cur == nil {
		return c.err
	}
	return c.cur.VerifyFirst()
}

// open starts the segment at c.idx.
func (c *SegmentChain) open() error {
	part := c.layout.Parts[c.idx]
	reader, err := stream.NewDecryptReader(
		io.LimitReader(c.src, c.layout.Sealed[c.idx]),
		c.dek,
		// The part number is demanded, not merely read: a provider that serves
		// part 7 where part 3 belongs fails here, because the index is
		// authenticated in the segment header.
		stream.SegmentParams{Log2ChunkSize: c.layout.Log2C, Multipart: true, Index: part.Number},
	)
	if err != nil {
		c.err = err
		return err
	}
	if err := c.layout.CheckSalt(c.idx, reader.Salt()); err != nil {
		_ = reader.Close()
		c.err = err
		return err
	}
	c.cur = reader
	return nil
}

func (c *SegmentChain) Read(p []byte) (int, error) {
	for {
		if c.err != nil {
			return 0, c.err
		}
		n, err := c.cur.Read(p)
		if n > 0 {
			return n, nil
		}
		if !errors.Is(err, io.EOF) {
			if err != nil {
				c.err = err
			}
			return 0, err
		}
		_ = c.cur.Close()
		c.cur = nil
		c.idx++
		if c.idx >= len(c.layout.Parts) {
			c.err = io.EOF
			return 0, io.EOF
		}
		if err := c.open(); err != nil {
			return 0, err
		}
	}
}

// Close releases the part being read.
func (c *SegmentChain) Close() error {
	if c.cur != nil {
		_ = c.cur.Close()
		c.cur = nil
	}
	return nil
}
