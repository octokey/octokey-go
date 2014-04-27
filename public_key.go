package octokey

import (
	"errors"
	"github.com/ConradIrwin/mrsa"
	"github.com/octokey/octokey-go/buffer"
	"math/big"
	"strings"
)

type PublicKey mrsa.PublicKey

const PUBLIC_KEY_TYPE = "ssh-rsa"
const SSH_RSA_MINIMUM_MODULUS_SIZE = 768

var (
	ErrPublicKeyFormat = errors.New("octokey/public_key: invalid input")
)

func NewPublicKey(text string) (*PublicKey, error) {

	text = strings.TrimSpace(text)

	if !strings.HasPrefix(text, PUBLIC_KEY_TYPE) {
		return nil, ErrPublicKeyFormat
	}

	text = strings.TrimSpace(strings.TrimPrefix(text, PUBLIC_KEY_TYPE))

	b := buffer.NewBuffer(text)
	k := &PublicKey{}

	err := k.ReadBuffer(b)
	if err != nil {
		return nil, err
	}

	b.ScanEof()

	if b.Error != nil {
		return nil, b.Error
	}

	return k, nil
}

func (p *PublicKey) WriteBuffer(b *buffer.Buffer) {
	b.AddString(PUBLIC_KEY_TYPE)
	b.AddMPInt(big.NewInt(int64(p.E)))
	b.AddMPInt(p.N)
}

func (p *PublicKey) ReadBuffer(b *buffer.Buffer) error {

	t := b.ScanString()
	e := b.ScanMPInt()
	n := b.ScanMPInt()

	if t != PUBLIC_KEY_TYPE {
		return ErrPublicKeyFormat
	}

	if e.Cmp(big.NewInt(EXPONENT)) != 0 {
		return ErrPublicKeyFormat
	}

	p.E = EXPONENT
	p.N = n

	return nil
}

func (p *PublicKey) String() string {
	b := new(buffer.Buffer)

	p.WriteBuffer(b)

	if b.Error != nil {
		panic(errors.New("invalid public key: " + b.Error.Error()))
	}

	return PUBLIC_KEY_TYPE + " " + b.String() + "\n"
}
