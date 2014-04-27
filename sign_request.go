package octokey

import (
	"errors"
	"github.com/octokey/octokey-go/buffer"
	"math/big"
	"strings"
)

// A SignRequest represents a request to perform a partial mRSA sign, and also
// the result of that computation.  It is represented as a Buffer of
// ("ssh-rsa" // || E || N || M) where E is the public exponent (MPint 65537)
// N is the modulus (a 2048 bit MPint), and M is the message (a 2048 bit MPInt
// strictly less than N)
type SignRequest struct {
	Key *PublicKey
	M   *big.Int
}

const (
	SIGN_REQUEST_HEADER = "-----BEGIN MRSA PARTIAL SIGN-----"
	SIGN_REQUEST_FOOTER = "-----END MRSA PARTIAL SIGN-----"
)

var (
	ErrSignRequestFormat = errors.New("escrow/signing_request: invalid format")
)

// NewSignRequest reads a sign request from a string.
func NewSignRequest(text string) (*SignRequest, error) {

	text = strings.TrimSpace(text)

	if !strings.HasPrefix(text, SIGN_REQUEST_HEADER) {
		return nil, ErrSignRequestFormat
	}
	text = strings.TrimPrefix(text, SIGN_REQUEST_HEADER)

	if !strings.HasSuffix(text, SIGN_REQUEST_FOOTER) {
		return nil, ErrSignRequestFormat
	}
	text = strings.TrimSuffix(text, SIGN_REQUEST_FOOTER)

	split := strings.Split(text, "\n\n")
	if len(split) > 2 {
		return nil, ErrSignRequestFormat
	}

	base64 := split[len(split)-1]

	b := buffer.NewBuffer(base64)
	request := new(SignRequest)
	err := request.ReadBuffer(b)
	if err != nil {
		return nil, err
	}
	b.ScanEof()

	if b.Error != nil {
		return nil, b.Error
	}

	return request, nil
}

// ReadBuffer reads a SignRequest from a buffer.
func (request *SignRequest) ReadBuffer(b *buffer.Buffer) error {

	publicKey := new(PublicKey)
	err := publicKey.ReadBuffer(b)
	if err != nil {
		return err
	}

	msg := b.ScanMPInt()

	if msg.Cmp(publicKey.N) >= 0 {
		return errors.New("cannot sign message > N")
	}

	request.Key = publicKey
	request.M = msg

	return nil
}

// Sign partially signs the request with the given key.
func (request *SignRequest) Sign(key *PartialKey) error {

	m, err := key.PartialDecrypt(request.M)

	if err != nil {
		return err
	}

	request.M = m

	return nil
}

// String produces the line-wrapped base-64 version of the challenge,
// suitable for being passed to NewSignRequest()
func (request *SignRequest) String() string {
	b := new(buffer.Buffer)

	request.WriteBuffer(b)

	if b.Error != nil {
		panic(errors.New("invalid sign request: " + b.Error.Error()))
	}

	return SIGN_REQUEST_HEADER + "\n" + lineWrap(b.String(), 64) + SIGN_REQUEST_FOOTER + "\n"
}

func (request *SignRequest) WriteBuffer(b *buffer.Buffer) {
	request.Key.WriteBuffer(b)
	b.AddMPInt(request.M)
}
