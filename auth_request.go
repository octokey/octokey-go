package octokey

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"github.com/octokey/octokey-go/buffer"
)

type Signer interface {
	SignPKCS1v15(hash crypto.Hash, hashed []byte) (s []byte, err error)
	PublicKey() *rsa.PublicKey
	Username() string
}

type AuthRequest struct {
	ChallengeBuffer  *buffer.Buffer
	RequestUrl       string
	Username         string
	ServiceName      string
	AuthMethod       string
	SigningAlgorithm string
	PublicKey        *rsa.PublicKey
	SignatureBuffer  *buffer.Buffer
}

const SERVICE_NAME = "octokey-auth"

const AUTH_METHOD = "publickey"

const SIGNING_ALGORITHM = "ssh-rsa"

func (O *Octokey) SignChallenge(challenge string, requestUrl string, signer Signer) (string, error) {
	a := AuthRequest{
		ChallengeBuffer:  buffer.NewBuffer(challenge),
		RequestUrl:       requestUrl,
		Username:         signer.Username(),
		ServiceName:      SERVICE_NAME,
		AuthMethod:       AUTH_METHOD,
		SigningAlgorithm: SIGNING_ALGORITHM,
	}

	return a.Sign(signer)
}

func (a *AuthRequest) Sign(s Signer) (string, error) {
	a.PublicKey = s.PublicKey()

	b := a.unsignedBuffer()

	h := sha1.New()
	h.Write(b.Raw())
	digest := h.Sum(nil)

	sig, err := s.SignPKCS1v15(crypto.SHA1, digest)

	if err != nil {
		return "", err
	}

	b.AddVarBytes(sig)

	if b.Error != nil {
		return "", b.Error
	}

	return b.String(), nil
}

func (a *AuthRequest) unsignedBuffer() *buffer.Buffer {
	b := buffer.Buffer{}
	b.AddBuffer(a.ChallengeBuffer)
	b.AddString(a.RequestUrl)
	b.AddString(a.Username)
	b.AddString(a.ServiceName)
	b.AddString(a.AuthMethod)
	b.AddString(a.SigningAlgorithm)
	//	b.AddVarBytes(publicKeyBytes(a.PublicKey))
	panic("todo")
	return &b
}
