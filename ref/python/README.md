# Independent reference decoder

A second implementation of the blindbucket wire format, in Python, written from
[`docs/FORMAT.md`](../../docs/FORMAT.md).

It exists to answer one question the Go implementation cannot answer about
itself: **is the specification sufficient to implement from, or does it only look
that way to someone who already knows the answer?** A format document that is
merely a description of one codebase is worth much less than one an outsider can
build against, and the difference is invisible until somebody tries.

```sh
pip install cryptography

python3 test_vectors.py                  # the normative known-answer vectors
python3 test_names_vectors.py            # the same, for the object name mapping
python3 difftest.py --count 100000       # against the Go decoder
python3 difftest_names.py --count 100000 # the same, for the name mapping

python3 blindbucket_ref.py file --kek <hex> encrypted.bb > plain
python3 blindbucket_ref.py segment --dek <hex> segment.bin > plain
python3 names_ref.py encrypt --name-key <hex> a/b/c.txt
```

## What it covers

Sections 1 to 6 and 9 of the format, in `blindbucket_ref.py`: the segment header
and its validation rules, subkey derivation, chunk nonces and the final-flag
rule, the chunk length rules, DEK unwrapping with both associated-data
encodings, and the local `BBF1` file envelope. It decodes; it does not encode,
because a decoder is what the comparison needs and an encoder would double the
surface for no extra evidence.

**Section 15, the object name mapping, in `names_ref.py`** — where that reasoning
inverts, so it implements **both** directions. The mapping is deterministic, so
the specification fixes the *stored* key exactly: reproducing it character for
character is the check, and that takes an encoder.

It also matters more than the rest. Everywhere else the format calls a
construction; here it composes one. ADR-015 chose to build the SIV paradigm from
standard parts — HMAC-SHA256 as the PRF, AES-CTR under the synthetic IV — rather
than depend on a Go library with no release tags whose last commit is from 2018.
That is a defensible choice only if the composition is checked by something other
than the code implementing it, and this is that something.

The multipart manifest (§10) and the upload token (§11) are not implemented. They
are coordination structures rather than content format, and the interesting
property there — the lifecycle rules — is checked by the TLA+ model in
[`spec/tla/`](../../spec/tla/) instead.

## How it is checked

**Known-answer vectors.** §13 makes the ten segment vectors in
[`testdata/vectors/`](../../testdata/vectors/) a normative part of the
specification, and §15.6 does the same for the fifteen name-mapping vectors. The
reference decoder opens all ten segments to exactly their recorded plaintext, and
reproduces all fifteen stored keys character for character.

**Differential fuzzing.** `difftest.py` generates valid segments with the Go
encoder, mutates them, and feeds every result to both decoders. The only thing
they have to agree on is the verdict — accepted with this plaintext, or rejected.
Error messages are not part of the format and are not compared.

The mutations are weighted towards inputs that are *nearly* valid, because that
is where two decoders disagree: bit flips, truncations biased to chunk and tag
boundaries, extensions past the final chunk, targeted edits to each header field
§5.2 requires a decoder to validate, a wrong key, a wrong expectation, and byte
swaps inside the body. Uniformly random input would spend its entire budget being
rejected at the magic and prove nothing.

Last full run: **100 000 inputs, 0 disagreements** — 8 945 accepted by both with
identical plaintext, 91 055 rejected by both. The nightly CI job runs 250 000 with
a fresh seed.

`difftest_names.py` does the same for the name mapping, in both directions: every
generated object key must map to the same stored key in both implementations, and
mutated stored keys — a flipped character, a truncated segment, two segments
swapped, a non-canonical base32 spelling — must be accepted or rejected the same
way by both. The swap case is the interesting one: both halves decrypt, and only
the position binding of §15.4 catches it.

Last full run: **5 000 keys mapped identically, and 100 000 stored keys with 0
disagreements** — 18 841 accepted by both with the same object key, 81 159
rejected by both. The nightly CI job runs 250 000 with a fresh seed.

## What it found

One thing, and it is the reason the exercise was worth doing. §5.2 states the
final-chunk rule in streaming terms — "look ahead exactly one byte past the
chunk's ciphertext" — and says nothing about how a decoder holding the whole
segment in memory should apply it. The natural reading is a length comparison,
and there are two of them: a chunk is the last when *at most* `C + 16` bytes
remain, or when *fewer than* `C + 16` do.

Taking the second produces a decoder that is correct for every input whose
plaintext is not an exact multiple of the chunk size, and wrong for every input
whose plaintext is. Measured against the vectors, with the comparison written the
wrong way:

```
empty                        accepts
single byte                  accepts
one byte short of a chunk    accepts
exactly one chunk            REJECTS (chunk 0 failed authentication)
one byte past a chunk        accepts
two chunks and one byte      accepts
```

Five of six pass. A file whose size happens to be a multiple of 64 KiB fails. The
specification now says which comparison is meant, in §4.4 and §5.2, and names the
vector that catches it.

## An honest limit on the independence claim

The strongest version of this artifact is written by someone who has never seen
the Go implementation. This one was not: it was written from `FORMAT.md`, with
the document as the only reference for every rule, but by an author who had read
the Go code beforehand and cannot unsee it.

So take the evidence for what it is. The differential test is unaffected — a
disagreement is a disagreement whoever wrote the two sides, and the 100 000
inputs mean what they say. The vectors are unaffected for the same reason. What
is weakened is the softer claim: that a fresh reader would arrive at the same
decoder from the document alone. The §5.2 ambiguity above is some evidence that
the document is now specific enough, since it was found by reading it rather than
by remembering the code — but a genuinely independent implementation would test
that better, and remains worth having.
