package audit

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/LennardGeissler/blindbucket/internal/crypto/names"
)

// Defaults for a Writer that does not configure them.
const (
	// DefaultCheckpointEvery is how many entries pass before the chain is
	// signed and flushed to disk.
	DefaultCheckpointEvery = 256
	// DefaultCheckpointInterval bounds the same thing in time, for a gateway
	// that is quiet rather than busy. Together they bound the truncation window
	// of ADR-016 from both sides.
	DefaultCheckpointInterval = 30 * time.Second
	// DefaultRotateBytes is the size at which a log file is closed and a new one
	// started. Opening a log verifies it from the beginning, so this is what
	// keeps startup bounded.
	DefaultRotateBytes = 128 << 20
)

// ErrBroken reports a writer that failed to append and has not recovered.
//
// It is sticky by design: a log with a hole in it cannot be repaired by the next
// write succeeding, so the gateway is told to stop rather than allowed to carry
// on with a record that is quietly incomplete.
var ErrBroken = errors.New("audit: the log is broken; requests are refused until it is fixed")

// ErrWrongKey reports a log opened with a key other than the one that wrote it.
var ErrWrongKey = errors.New("audit: this log was written by a different audit key")

// Event is one request as the gateway hands it over.
//
// Bucket and Key are plaintext here and are encrypted by the writer; nothing
// outside this package has to remember to do it.
type Event struct {
	Time      time.Time
	Op        string
	Bucket    string
	Key       string
	Client    string
	Principal string
	RequestID string
	Status    int
	Code      string
	KID       string
	Bytes     int64
}

// Config configures a Writer.
type Config struct {
	// Path is the log file. It is created if absent and continued if present.
	Path string
	// Chain names this chain. Empty generates a fresh id, which is the normal
	// case: a chain is one file, not one deployment.
	Chain string
	// Signer signs checkpoints. Required.
	Signer ed25519.PrivateKey
	// NameKey encrypts bucket and object names. Required.
	NameKey []byte

	CheckpointEvery    int
	CheckpointInterval time.Duration
	RotateBytes        int64

	// Now is the clock, overridable so that checkpoint intervals and rotation
	// can be tested without sleeping.
	Now func() time.Time
}

// Writer appends to one hash-chained, periodically signed log file.
//
// Every exported method is safe for concurrent use: appends are serialised by a
// mutex, because a chain is by definition a sequence and two goroutines hashing
// against the same predecessor would produce two records claiming the same
// position. The serialised section -- two name encryptions, one SHA-256 and a
// buffered write -- measures 3.6 us against a gateway overhead of 0.13 ms per
// request, which is why ADR-016 rejected a background writer. See
// BenchmarkAppend.
type Writer struct {
	mu     sync.Mutex
	file   *os.File
	buf    *bufio.Writer
	chain  string
	seq    uint64
	hash   string
	size   int64
	dirty  bool
	sinceC int
	lastC  time.Time
	broken error

	path        string
	signer      ed25519.PrivateKey
	pub         string
	coder       *nameCoder
	every       int
	interval    time.Duration
	rotateBytes int64
	now         func() time.Time

	done      chan struct{}
	wg        sync.WaitGroup
	closeOnce sync.Once
	closeErr  error
}

// Open opens or continues a log.
//
// An existing file is verified from its head before a byte is appended to it.
// That costs a sequential read and a SHA-256 pass -- fast, but linear in the
// file, which is what RotateBytes is for. The alternative, trusting the last
// line and continuing from it, would let a gateway extend a chain that had
// already been tampered with and sign the result at its next checkpoint.
func Open(cfg Config) (*Writer, error) {
	switch {
	case cfg.Path == "":
		return nil, errors.New("audit: a log path is required")
	case len(cfg.Signer) != ed25519.PrivateKeySize:
		return nil, errors.New("audit: a signing key is required")
	}
	coder, err := newNameCoder(cfg.NameKey)
	if err != nil {
		return nil, err
	}
	pub, ok := cfg.Signer.Public().(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("audit: the signing key has no Ed25519 public key")
	}

	w := &Writer{
		path:        cfg.Path,
		signer:      cfg.Signer,
		pub:         base64.StdEncoding.EncodeToString(pub),
		coder:       coder,
		every:       orDefaultInt(cfg.CheckpointEvery, DefaultCheckpointEvery),
		interval:    orDefaultDuration(cfg.CheckpointInterval, DefaultCheckpointInterval),
		rotateBytes: orDefaultInt64(cfg.RotateBytes, DefaultRotateBytes),
		now:         cfg.Now,
		done:        make(chan struct{}),
	}
	if w.now == nil {
		w.now = time.Now
	}
	if err := w.openFile(cfg.Chain, pub); err != nil {
		return nil, err
	}

	w.lastC = w.now()
	if w.interval > 0 {
		w.wg.Add(1)
		go w.checkpointLoop()
	}
	return w, nil
}

// openFile opens the log and either continues its chain or starts one.
func (w *Writer) openFile(chain string, pub ed25519.PublicKey) error {
	if dir := filepath.Dir(w.path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	// 0600: a log names which credential touched which object. It is less
	// sensitive than a keyring and more sensitive than a metric.
	//nolint:gosec // the path comes from the operator's configuration.
	file, err := os.OpenFile(w.path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return err
	}

	if info.Size() > 0 {
		result, err := Verify(file, VerifyOptions{PublicKey: pub})
		if err != nil {
			_ = file.Close()
			return fmt.Errorf("audit: refusing to continue %s: %w", w.path, err)
		}
		// A final record cut off mid-write is what a crash between checkpoints
		// looks like. Continuing past it would append a valid record after an
		// invalid one and leave the file permanently unverifiable, so the torn
		// bytes are cut back to the last intact record -- which is a truncation,
		// visible as one, and inside the window a checkpoint already bounds.
		if result.TornTail {
			if err := file.Truncate(result.IntactBytes); err != nil {
				_ = file.Close()
				return err
			}
		}
		if _, err := file.Seek(result.IntactBytes, io.SeekStart); err != nil {
			_ = file.Close()
			return err
		}
		w.file = file
		w.chain, w.seq, w.hash, w.size = result.Chain, result.Entries, result.FinalHash, result.IntactBytes
		w.buf = bufio.NewWriter(file)
		return nil
	}

	w.file = file
	w.buf = bufio.NewWriter(file)
	return w.writeHead(chain, "", "")
}

// writeHead starts a chain, optionally linked to the file before it.
func (w *Writer) writeHead(chain, prevChain, prevHash string) error {
	if chain == "" {
		var b [8]byte
		if _, err := rand.Read(b[:]); err != nil {
			return err
		}
		chain = hex.EncodeToString(b[:])
	}
	head := &Head{
		Version:   Version,
		Chain:     chain,
		Opened:    w.now().UTC().Format(timeFormat),
		PublicKey: w.pub,
		PrevChain: prevChain,
		PrevHash:  prevHash,
	}
	hash, err := head.chainHashOf()
	if err != nil {
		return err
	}
	head.Hash = hash

	line, err := marshalLine(Record{Type: TypeHead, Head: head})
	if err != nil {
		return err
	}
	n, err := w.buf.Write(line)
	if err != nil {
		return err
	}
	w.chain, w.seq, w.hash = chain, 0, hash
	w.size = int64(n)
	return w.sync()
}

// Chain reports the id of the chain currently being written.
func (w *Writer) Chain() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.chain
}

// Err reports a sticky append failure, or nil.
//
// The gateway calls this before serving, not after: an entry records an outcome
// and can only be written once the request is over, so there is nothing left to
// withhold by then. Refusing the *next* request is the strongest fail-closed
// behaviour the ordering allows, and it costs exactly one unrecorded request.
func (w *Writer) Err() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.broken
}

// Append records one served request.
func (w *Writer) Append(ev Event) error {
	bucket, key, err := w.coder.encode(ev.Bucket, ev.Key)
	if err != nil {
		return err
	}

	w.mu.Lock()
	defer w.mu.Unlock()
	if w.broken != nil {
		return w.broken
	}

	when := ev.Time
	if when.IsZero() {
		when = w.now()
	}
	entry := &Entry{
		Seq:       w.seq + 1,
		Time:      when.UTC().Format(timeFormat),
		Op:        ev.Op,
		Bucket:    bucket,
		Key:       key,
		Client:    ev.Client,
		Principal: clean(ev.Principal),
		RequestID: ev.RequestID,
		Status:    ev.Status,
		Code:      ev.Code,
		KID:       ev.KID,
		// Clamped here rather than in the hash. If the two disagreed, the value
		// written and the value covered would differ, and an independent
		// verifier reading only docs/FORMAT.md section 14 would have to be told
		// about it. Negative is not a byte count anyway.
		Bytes: max(ev.Bytes, 0),
	}
	hash, err := entry.chainHashOf(w.chain, w.hash)
	if err != nil {
		return w.fail(err)
	}
	entry.Hash = hash

	line, err := marshalLine(Record{Type: TypeEntry, Entry: entry})
	if err != nil {
		return w.fail(err)
	}
	n, err := w.buf.Write(line)
	if err != nil {
		return w.fail(err)
	}

	w.seq, w.hash, w.dirty = entry.Seq, hash, true
	w.size += int64(n)
	w.sinceC++

	if w.every > 0 && w.sinceC >= w.every {
		return w.checkpointLocked()
	}
	return nil
}

// Checkpoint signs the chain where it stands and flushes it to disk.
func (w *Writer) Checkpoint() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.broken != nil {
		return w.broken
	}
	if !w.dirty {
		return nil
	}
	return w.checkpointLocked()
}

func (w *Writer) checkpointLocked() error {
	point := &Checkpoint{
		Seq:  w.seq,
		Time: w.now().UTC().Format(timeFormat),
		Hash: w.hash,
	}
	msg, err := point.signedMessage(w.chain)
	if err != nil {
		return w.fail(err)
	}
	point.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(w.signer, msg))

	line, err := marshalLine(Record{Type: TypeCheckpoint, Checkpoint: point})
	if err != nil {
		return w.fail(err)
	}
	n, err := w.buf.Write(line)
	if err != nil {
		return w.fail(err)
	}
	w.size += int64(n)
	if err := w.sync(); err != nil {
		return w.fail(err)
	}
	w.sinceC, w.dirty, w.lastC = 0, false, w.now()

	if w.rotateBytes > 0 && w.size >= w.rotateBytes {
		return w.rotateLocked()
	}
	return nil
}

// sync flushes the buffer and the file.
//
// fsync happens at a checkpoint and nowhere else. Entries written since the last
// one can be lost to a host crash, which is a durability property and not an
// integrity one: the chain makes the loss visible as a truncation rather than
// leaving a plausible-looking gap.
func (w *Writer) sync() error {
	if err := w.buf.Flush(); err != nil {
		return err
	}
	return w.file.Sync()
}

// rotateLocked closes the current file and starts a new one linked to it.
//
// The new head records the previous chain's id and final hash, so the sequence
// of files stays one chain: a verifier handed all of them checks the links, and
// a missing file in the middle is a break rather than a gap nobody notices.
func (w *Writer) rotateLocked() error {
	prevChain, prevHash := w.chain, w.hash
	if err := w.file.Close(); err != nil {
		return w.fail(err)
	}

	archived, err := w.archiveName()
	if err != nil {
		return w.fail(err)
	}
	if err := os.Rename(w.path, archived); err != nil {
		return w.fail(err)
	}
	//nolint:gosec // the path comes from the operator's configuration.
	file, err := os.OpenFile(w.path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return w.fail(err)
	}
	w.file, w.buf = file, bufio.NewWriter(file)
	if err := w.writeHead("", prevChain, prevHash); err != nil {
		return w.fail(err)
	}
	w.sinceC, w.dirty = 0, false
	return nil
}

// archiveSuffix is the timestamp a rotated file is renamed with. Nanoseconds,
// so that names sort chronologically and two rotations in the same second do not
// land on one name.
const archiveSuffix = "20060102T150405.000000000Z"

// archiveName picks a name for the file being rotated out that does not already
// exist.
//
// Never overwriting is the point. A rotation that renamed over an existing
// archive would destroy a signed log file to make room for another, and would do
// it silently -- and a log that deletes its own history under load is not one
// anybody should trust. The counter covers a clock that stands still, which is
// the case a nanosecond stamp alone does not.
func (w *Writer) archiveName() (string, error) {
	base := w.path + "." + w.now().UTC().Format(archiveSuffix)
	for i := range 1000 {
		candidate := base
		if i > 0 {
			candidate = fmt.Sprintf("%s-%d", base, i)
		}
		if _, err := os.Stat(candidate); errors.Is(err, os.ErrNotExist) {
			return candidate, nil
		} else if err != nil {
			return "", err
		}
	}
	return "", fmt.Errorf("audit: cannot find an unused name to rotate %s to", w.path)
}

// fail marks the writer broken and returns why.
func (w *Writer) fail(err error) error {
	if w.broken == nil {
		w.broken = fmt.Errorf("%w: %w", ErrBroken, err)
	}
	return w.broken
}

// checkpointLoop signs the chain on a timer, for a gateway too quiet to reach
// the entry count.
func (w *Writer) checkpointLoop() {
	defer w.wg.Done()
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()
	for {
		select {
		case <-w.done:
			return
		case <-ticker.C:
			_ = w.Checkpoint()
		}
	}
}

// Close writes a final checkpoint and closes the file.
//
// It is idempotent and returns the same error each time. A gateway shutting down
// has more than one path that wants to be sure the log is closed, and the one
// that runs second must not be the one that panics.
func (w *Writer) Close() error {
	w.closeOnce.Do(func() {
		close(w.done)
		w.wg.Wait()

		w.mu.Lock()
		defer w.mu.Unlock()
		// The final checkpoint is what signs everything written since the last
		// one. Without it a clean shutdown would leave the tail of the log
		// chained but unsigned, which is the one case it costs nothing to avoid.
		if w.broken == nil && w.dirty {
			w.closeErr = w.checkpointLocked()
		}
		if err := w.buf.Flush(); err != nil && w.closeErr == nil {
			w.closeErr = err
		}
		if err := w.file.Close(); err != nil && w.closeErr == nil {
			w.closeErr = err
		}
	})
	return w.closeErr
}

// ReadHead parses the head record at the start of a log, and nothing else.
//
// It exists so that a sequence of rotated files can be put in order by following
// what each head says it continues, rather than by trusting their filenames. A
// filename is not evidence; PrevChain is covered by the head's own hash.
func ReadHead(r io.Reader) (*Head, error) {
	line, err := bufio.NewReader(io.LimitReader(r, maxLine)).ReadBytes('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	record, err := parseLine(bytes.TrimRight(line, "\n"))
	if err != nil {
		return nil, err
	}
	if record.Type != TypeHead {
		return nil, fmt.Errorf("%w: the log does not begin with a head record", ErrMalformed)
	}
	return record.Head, nil
}

// nameCoder maps bucket and object names into and out of a log entry.
type nameCoder struct {
	enc *names.Encrypter
	key []byte
}

// digestPrefix marks a name recorded as an irreversible digest rather than as
// ciphertext.
//
// It cannot collide with an encrypted name: those are base32 over the uppercase
// alphabet A-Z2-7 joined by "/", in which a lowercase letter cannot appear.
const digestPrefix = "h:"

// digestInfo domain-separates the fallback digest from every other use of the
// name key.
const digestInfo = "blindbucket/v1/audit-name-digest"

func newNameCoder(nameKey []byte) (*nameCoder, error) {
	enc, err := names.New(nameKey)
	if err != nil {
		return nil, err
	}
	return &nameCoder{enc: enc, key: append([]byte(nil), nameKey...)}, nil
}

// encode encrypts a bucket and key for the log.
func (n *nameCoder) encode(bucket, key string) (string, string, error) {
	encBucket, err := n.encodeOne(bucket)
	if err != nil {
		return "", "", err
	}
	encKey, err := n.encodeOne(key)
	if err != nil {
		return "", "", err
	}
	return encBucket, encKey, nil
}

// encodeOne encrypts one name, falling back to a digest for a name too long to
// encrypt.
//
// The fallback exists because S3 allows a 1024-byte key while the per-segment
// encryption of ADR-015 grows one past that, so a legal key can have no
// encrypted form that is itself a legal key. Refusing to log such a request
// would let a client silence the audit log by choosing a long enough name, which
// is worse than logging a name that cannot be read back.
//
// Where the threshold sits depends on the key's shape rather than on one
// multiplier: 624 bytes for a key that is one long segment, 128 for a path of
// four-character segments, because the 16-byte IV is charged per segment. Deep
// paths therefore reach the digest much earlier than the flat 1.6x this comment
// used to quote would suggest. BenchmarkKeyExpansion measures it; ADR-017
// records why the old figure was wrong.
func (n *nameCoder) encodeOne(name string) (string, error) {
	if name == "" {
		return "", nil
	}
	encrypted, err := n.enc.EncryptKey(name)
	switch {
	case err == nil:
		return encrypted, nil
	case errors.Is(err, names.ErrTooLong):
		return n.digest(name), nil
	default:
		return "", err
	}
}

// digest is the irreversible fallback: keyed, so it reveals nothing without the
// keyring, and deterministic, so repeated access to one name is still visible as
// repeated access to one name.
func (n *nameCoder) digest(name string) string {
	mac := hmac.New(sha256.New, n.key)
	_, _ = mac.Write([]byte(digestInfo))
	_, _ = mac.Write([]byte(name))
	return digestPrefix + hex.EncodeToString(mac.Sum(nil))
}

// Decode reverses encode for display. A digested name cannot be reversed and is
// returned as it stands.
func (n *nameCoder) decode(name string) (string, bool) {
	switch {
	case name == "":
		return "", true
	case len(name) >= len(digestPrefix) && name[:len(digestPrefix)] == digestPrefix:
		return name, false
	}
	plain, err := n.enc.DecryptKey(name)
	if err != nil {
		return name, false
	}
	return plain, true
}

// clean bounds and sanitises a field that came from an unauthenticated request.
//
// Principal is the access key id a rejected caller claimed, which is
// attacker-controlled: unbounded, and free to contain newlines that would let
// one forged request render as two log records. JSON escaping already stops the
// second, but a log is read by things that are not JSON parsers.
func clean(s string) string {
	const maxPrincipal = 128
	if len(s) > maxPrincipal {
		s = s[:maxPrincipal]
	}
	out := make([]rune, 0, len(s))
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			r = '.'
		}
		out = append(out, r)
	}
	return string(out)
}

func orDefaultInt(v, fallback int) int {
	if v == 0 {
		return fallback
	}
	return v
}

func orDefaultInt64(v, fallback int64) int64 {
	if v == 0 {
		return fallback
	}
	return v
}

func orDefaultDuration(v, fallback time.Duration) time.Duration {
	if v == 0 {
		return fallback
	}
	return v
}
