package octokey

import (
	"errors"
	"github.com/octokey/octokey-go/buffer"
	"math/big"
	"strings"
)

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

	buff := buffer.NewBuffer(base64)

	publicKey := new(PublicKey)
	err := publicKey.ReadBuffer(buff)
	if err != nil {
		return nil, err
	}

	msg := buff.ScanMPInt()
	buff.ScanEof()

	if buff.Error != nil {
		return nil, buff.Error
	}

	request := new(SignRequest)
	request.Key = publicKey
	request.M = msg

	return request, nil
}

func (request *SignRequest) Sign(key *PartialKey) error {

	m, err := key.Sign(request.M)

	if err != nil {
		return err
	}

	request.M = m

	return nil
}

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
