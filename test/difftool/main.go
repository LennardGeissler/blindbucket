// Command difftool is the Go half of the differential test against the Python
// reference decoder in ref/python.
//
// It speaks newline-delimited JSON so that a hundred thousand inputs cost one
// process rather than a hundred thousand. Two modes:
//
//	difftool -gen N     write N valid segments, varying in size, chunk size and
//	                    part number, as seed material for the mutator
//	difftool            read inputs on stdin, write one verdict per line
//
// and the same two for the object name mapping of FORMAT.md section 15:
//
//	difftool -names N       write N object keys with where the mapping puts them
//	difftool -names-decode  read stored keys on stdin, write one verdict per line
//
// A verdict is deliberately coarse -- accepted with this plaintext hash, or
// rejected -- because that is the whole of what the two implementations have to
// agree on. Error *messages* are not part of the format and are not compared.
package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/LennardGeissler/blindbucket/internal/crypto/stream"
)

// input is one segment to decode, with the expectation a caller would hold.
type input struct {
	DEK       string `json:"dek"`
	Data      string `json:"data"`
	Multipart bool   `json:"multipart"`
	Index     uint32 `json:"index"`
}

// verdict is what one decoder made of it.
type verdict struct {
	OK     bool   `json:"ok"`
	SHA256 string `json:"sha256,omitempty"`
	Err    string `json:"err,omitempty"`
}

func main() {
	generate := flag.Int("gen", 0, "emit this many valid segments instead of decoding")
	genNames := flag.Int("names", 0, "emit this many mapped object keys instead of decoding")
	decNames := flag.Bool("names-decode", false, "read stored keys on stdin and reverse them")
	flag.Parse()

	var err error
	switch {
	case *genNames > 0:
		err = emitNameSeeds(*genNames, os.Stdout)
	case *decNames:
		err = decryptNameStream(os.Stdin, os.Stdout)
	case *generate > 0:
		err = emitSeeds(*generate, os.Stdout)
	default:
		err = decodeStream(os.Stdin, os.Stdout)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "difftool:", err)
		os.Exit(1)
	}
}

// decodeStream answers one verdict per input line.
func decodeStream(r io.Reader, w io.Writer) error {
	in := bufio.NewScanner(r)
	// Segments at the largest chunk size run to megabytes, and the hex encoding
	// doubles that.
	in.Buffer(make([]byte, 0, 1<<20), 64<<20)
	out := bufio.NewWriter(w)
	defer func() { _ = out.Flush() }()

	encoder := json.NewEncoder(out)
	for in.Scan() {
		line := in.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var req input
		if err := json.Unmarshal(line, &req); err != nil {
			return fmt.Errorf("parsing an input: %w", err)
		}
		if err := encoder.Encode(decodeOne(req)); err != nil {
			return err
		}
	}
	return in.Err()
}

// decodeOne runs the Go decoder over one input.
func decodeOne(req input) verdict {
	dek, err := hex.DecodeString(req.DEK)
	if err != nil {
		return verdict{Err: "bad dek hex"}
	}
	data, err := hex.DecodeString(req.Data)
	if err != nil {
		return verdict{Err: "bad data hex"}
	}

	// AnyChunkSize: the segment states its own chunk size, and the reference
	// decoder reads it the same way. The multipart flag and index are the
	// caller's expectation, which both sides apply identically.
	want := stream.SegmentParams{
		Log2ChunkSize: stream.AnyChunkSize,
		Multipart:     req.Multipart,
		Index:         req.Index,
	}
	reader, err := stream.NewDecryptReader(bytes.NewReader(data), dek, want)
	if err != nil {
		return verdict{Err: err.Error()}
	}
	defer func() { _ = reader.Close() }()

	sum := sha256.New()
	if _, err := io.Copy(sum, reader); err != nil {
		return verdict{Err: err.Error()}
	}
	return verdict{OK: true, SHA256: hex.EncodeToString(sum.Sum(nil))}
}

// seedShape is one point in the space of valid segments worth mutating.
type seedShape struct {
	plain     int
	log2C     uint8
	multipart bool
	index     uint32
}

// seedShapes covers the sizes where an encoder's final-chunk handling either
// works or does not, at the smallest, default and largest chunk sizes, and both
// ends of the part-number range. Mutating a segment is only interesting if the
// segment was interesting to begin with.
func seedShapes() []seedShape {
	var shapes []seedShape
	for _, log2C := range []uint8{12, 16, 20} {
		chunk := 1 << log2C
		for _, plain := range []int{0, 1, chunk - 1, chunk, chunk + 1, 2*chunk + 1} {
			shapes = append(shapes, seedShape{plain: plain, log2C: log2C})
		}
	}
	shapes = append(shapes,
		seedShape{plain: 4097, log2C: 12, multipart: true, index: 1},
		seedShape{plain: 1, log2C: 12, multipart: true, index: 10000},
		seedShape{plain: 1 << 16, log2C: 16, multipart: true, index: 5000},
	)
	return shapes
}

// emitSeeds writes valid segments for the mutator to work from.
func emitSeeds(count int, w io.Writer) error {
	out := bufio.NewWriter(w)
	defer func() { _ = out.Flush() }()
	encoder := json.NewEncoder(out)

	shapes := seedShapes()
	for i := range count {
		shape := shapes[i%len(shapes)]

		dek := make([]byte, 32)
		if _, err := rand.Read(dek); err != nil {
			return err
		}
		plain := make([]byte, shape.plain)
		if _, err := rand.Read(plain); err != nil {
			return err
		}

		var sealed bytes.Buffer
		ew, err := stream.NewEncryptWriter(&sealed, dek, stream.SegmentParams{
			Log2ChunkSize: shape.log2C,
			Multipart:     shape.multipart,
			Index:         shape.index,
		})
		if err != nil {
			return fmt.Errorf("building an encoder for %+v: %w", shape, err)
		}
		if _, err := ew.Write(plain); err != nil {
			return fmt.Errorf("encoding %+v: %w", shape, err)
		}
		if err := ew.Close(); err != nil {
			return fmt.Errorf("closing %+v: %w", shape, err)
		}

		if err := encoder.Encode(input{
			DEK:       hex.EncodeToString(dek),
			Data:      hex.EncodeToString(sealed.Bytes()),
			Multipart: shape.multipart,
			Index:     shape.index,
		}); err != nil {
			return err
		}
	}
	return nil
}
