package octokey

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"github.com/ConradIrwin/mrsa"
	"github.com/octokey/octokey-go/buffer"
	"io"
	"math/big"
	"strings"
)

// A PartialKey is a triple (E, N, D) where E is the public exponent,
// N is the modulus, and D is a part of the mRSA private key.
type PartialKey mrsa.PrivateKey

const (
	HEADER     = "-----BEGIN MRSA PRIVATE KEY-----"
	FOOTER     = "-----END MRSA PRIVATE KEY-----"
	KEY_TYPE   = "octokey-mrsa"
	EXPONENT   = 65537
	BIT_LENGTH = 2048
)

var (
	ErrPartialKeyFormat        = errors.New("octokey/partial_key: invalid input")
	ErrPartialKeyWrongExponent = errors.New("octokey/partial_key: invalid exponent")
)

// GeneratePartialKey generates two new PartialKeys that can be used
// together to perform mRSA operations.
func GeneratePartialKey() (*PartialKey, *PartialKey, error) {

	k, err := rsa.GenerateKey(rand.Reader, BIT_LENGTH)

	if err != nil {
		return nil, nil, err
	}

	d1, d2, err := mrsa.SplitPrivateKey(k)

	if err != nil {
		return nil, nil, err
	}

	return (*PartialKey)(d1), (*PartialKey)(d2), nil
}

// NewPartialKey reads a PartialKey from its string representation
func NewPartialKey(text string) (*PartialKey, error) {

	text = strings.TrimSpace(text)

	if !strings.HasPrefix(text, HEADER) {
		return nil, ErrPartialKeyFormat
	}
	text = strings.TrimPrefix(text, HEADER)

	if !strings.HasSuffix(text, FOOTER) {
		return nil, ErrPartialKeyFormat
	}
	text = strings.TrimSuffix(text, FOOTER)

	split := strings.Split(text, "\n\n")
	if len(split) > 2 {
		return nil, ErrPartialKeyFormat
	}

	base64 := strings.TrimSpace(split[len(split)-1])

	b := buffer.NewBuffer(base64)

	t := b.ScanString()
	e := b.ScanMPInt()
	n := b.ScanMPInt()
	d := b.ScanMPInt()
	b.ScanEof()

	if b.Error != nil {
		return nil, b.Error
	}

	if t != KEY_TYPE {
		return nil, ErrPartialKeyFormat
	}

	if e.Cmp(big.NewInt(EXPONENT)) != 0 {
		return nil, ErrPartialKeyWrongExponent
	}

	if d.Cmp(n) > 0 {
		println("Oops d")
		return nil, ErrPartialKeyWrongExponent
	}

	k := new(PartialKey)
	k.E = EXPONENT
	k.N = n
	k.D = d

	return k, nil
}

// PartialDecrypt runs partial mRSA decryption on a number. You will need to finalize the
// signature once you have run Sign with all parts of the key.
func (k *PartialKey) PartialDecrypt(c *big.Int) (*big.Int, error) {
	mrsaKey := mrsa.PrivateKey(*k)
	return mrsaKey.PartialDecrypt(c)
}

// Format gives you the partial key in the canonical representation including
// ----BEGIN/END headers.
func (k *PartialKey) String() string {
	b := new(buffer.Buffer)
	k.WriteBuffer(b)
	if b.Error != nil {
		panic(errors.New("invalid partial key: " + b.Error.Error()))
	}

	return HEADER + "\n" + lineWrap(b.String(), 64) + FOOTER + "\n"
}

// lineWrap wraps text at a given width. Used for formatting base64 buffers.
func lineWrap(s string, w int) string {
	r := strings.NewReader(s)
	l := make([]byte, w)
	b := bytes.NewBuffer(make([]byte, 0, len(s)*65/64))

	for {
		n, err := r.Read(l)

		if err == io.EOF {
			break
		}
		if err != nil {
			// Would indicate a bug in StringReader
			panic(err)
		}

		b.Write(l[:n])
		b.WriteString("\n")
	}

	return string(b.Bytes())
}
// WriteBuffer writes the PartialKey to a buffer
func (k *PartialKey) WriteBuffer(b *buffer.Buffer) {
	b.AddString(KEY_TYPE)
	b.AddMPInt(big.NewInt(int64(k.E)))
	b.AddMPInt(k.N)
	b.AddMPInt(k.D)
}
