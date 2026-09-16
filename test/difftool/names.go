package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"strings"

	"github.com/LennardGeissler/blindbucket/internal/crypto/names"
)

// nameSeed is one plaintext key and where the Go implementation maps it.
type nameSeed struct {
	NameKey string `json:"name_key"`
	Plain   string `json:"plain"`
	Stored  string `json:"stored"`
}

// nameInput is one stored key to reverse.
type nameInput struct {
	NameKey string `json:"name_key"`
	Stored  string `json:"stored"`
}

// nameVerdict is what one implementation made of it. Coarse on purpose: the two
// have to agree on accepted-with-this-key or rejected, and nothing else. Error
// messages are not part of the format.
type nameVerdict struct {
	OK    bool   `json:"ok"`
	Plain string `json:"plain,omitempty"`
	Err   string `json:"err,omitempty"`
}

// nameSegmentAlphabet is what segments are built from: ASCII that S3 keys carry
// without escaping, plus a few multi-byte runes, because the length prefixes of
// the synthetic IV count bytes and an implementation that counts runes would
// agree on ASCII and diverge here.
var nameSegmentAlphabet = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJ0123456789-_.() äöüßéя漢")

func randInt(n int) int {
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		panic(err)
	}
	return int(v.Int64())
}

// randomKey builds a plaintext key whose shape varies over the things the
// mapping treats specially: segment count, empty segments, and the separators at
// either end.
func randomKey() string {
	segments := 1 + randInt(5)
	parts := make([]string, segments)
	for i := range parts {
		// An empty segment now and then: "a//b" and "a/b" are different S3 keys
		// and must map differently.
		if randInt(12) == 0 {
			parts[i] = ""
			continue
		}
		length := 1 + randInt(12)
		var sb strings.Builder
		for range length {
			sb.WriteRune(nameSegmentAlphabet[randInt(len(nameSegmentAlphabet))])
		}
		parts[i] = sb.String()
	}
	key := strings.Join(parts, "/")
	switch randInt(10) {
	case 0:
		key = "/" + key
	case 1:
		key += "/"
	}
	return key
}

// emitNameSeeds writes count mapped keys as seed material.
func emitNameSeeds(count int, w io.Writer) error {
	out := bufio.NewWriter(w)
	defer func() { _ = out.Flush() }()
	encoder := json.NewEncoder(out)

	for range count {
		key := make([]byte, names.KeySize)
		if _, err := rand.Read(key); err != nil {
			return err
		}
		enc, err := names.New(key)
		if err != nil {
			return err
		}
		plain := randomKey()
		stored, err := enc.EncryptKey(plain)
		if err != nil {
			// Too long once encrypted: a legitimate refusal, not a seed.
			continue
		}
		if err := encoder.Encode(nameSeed{
			NameKey: hex.EncodeToString(key), Plain: plain, Stored: stored,
		}); err != nil {
			return err
		}
	}
	return nil
}

// decryptNameStream answers one verdict per stored key on stdin.
func decryptNameStream(r io.Reader, w io.Writer) error {
	in := bufio.NewScanner(r)
	in.Buffer(make([]byte, 0, 1<<16), 1<<20)
	out := bufio.NewWriter(w)
	defer func() { _ = out.Flush() }()

	encoder := json.NewEncoder(out)
	for in.Scan() {
		line := in.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var req nameInput
		if err := json.Unmarshal(line, &req); err != nil {
			return fmt.Errorf("parsing an input: %w", err)
		}
		if err := encoder.Encode(decryptNameOne(req)); err != nil {
			return err
		}
	}
	return in.Err()
}

func decryptNameOne(req nameInput) nameVerdict {
	key, err := hex.DecodeString(req.NameKey)
	if err != nil {
		return nameVerdict{Err: "bad name key hex"}
	}
	enc, err := names.New(key)
	if err != nil {
		return nameVerdict{Err: err.Error()}
	}
	plain, err := enc.DecryptKey(req.Stored)
	if err != nil {
		return nameVerdict{Err: err.Error()}
	}
	return nameVerdict{OK: true, Plain: plain}
}
