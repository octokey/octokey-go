package octokey

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"errors"
	"github.com/octokey/octokey-go/buffer"
	"net"
	"time"
)

const (
	// Which version of challenges is supported
	CHALLENGE_VERSION = 3
	// How many bytes of random data should be included
	RANDOM_SIZE = 32
	// Hash algorithm to use in the HMAC
	HMAC_ALGORITHM = "sha1"
	// The maximum age of a valid challenge (seconds)
	MAX_AGE = 5 * 60
	// The minimum age of a valid challenge (seconds)
	MIN_AGE = -30
)

type Challenge struct {
	O         *Octokey
	Version   uint8
	Timestamp time.Time
	ClientIp  net.IP
	Random    []byte
	Digest    []byte
	Errors    []error
}

func (O *Octokey) NewChallenge(clientIp net.IP) (string, error) {

	random := make([]byte, RANDOM_SIZE)
	_, err := rand.Read(random)
	if err != nil {
		return "", err
	}

	challenge := Challenge{O: O}
	challenge.Version = CHALLENGE_VERSION
	challenge.Timestamp = now()
	challenge.ClientIp = clientIp
	challenge.Random = random
	challenge.Digest = challenge.expectedDigest()

	return challenge.String(), nil
}

func (O *Octokey) ValidateChallenge(s string, clientIp net.IP) error {

	challenge := Challenge{O: O}
	challenge.ReadFrom(s, clientIp)

	if len(challenge.Errors) > 0 {
		return errors.New("octokey/challenge: invalid challenge")
	}

	return nil
}

// String returns the challenge in Base64 format
func (c *Challenge) String() string {
	return c.signedBuffer().String()
}

func (c *Challenge) ReadFrom(s string, clientIp net.IP) {
	b := buffer.NewBuffer(s)
	currentTime := now()

	c.Version = b.ScanUint8()
	c.Timestamp = b.ScanTimestamp()
	c.ClientIp = b.ScanIP()
	c.Random = b.ScanVarBytes()
	c.Digest = b.ScanVarBytes()
	b.ScanEof()

	if b.Error != nil {
		c.Errors = append(c.Errors, b.Error)
		return
	}

	if c.Version != CHALLENGE_VERSION {
		c.Errors = append(c.Errors, errors.New("octokey/challenge: version mismatch"))
		return
	}

	if currentTime.Unix()+MAX_AGE < c.Timestamp.Unix() {
		c.Errors = append(c.Errors, errors.New("octokey/challenge: challenge too new"))
	}

	if currentTime.Unix()+MIN_AGE > c.Timestamp.Unix() {
		c.Errors = append(c.Errors, errors.New("octokey/challenge: challenge too old"))
	}

	if !c.ClientIp.Equal(clientIp) {
		c.Errors = append(c.Errors, errors.New("octokey/challenge: challenge IP mismatch"))
	}

	if len(c.Random) != RANDOM_SIZE {
		c.Errors = append(c.Errors, errors.New("octokey/challenge: challenge random mismatch"))
	}

	if !hmac.Equal(c.Digest, c.expectedDigest()) {
		c.Errors = append(c.Errors, errors.New("octokey/challenge: challenge HMAC mismatch"))
	}
}

// expectedDigest calculates the HMAC of the unsignedBuffer
func (c *Challenge) expectedDigest() []byte {
	toSign := c.unsignedBuffer().Raw()
	h := hmac.New(sha1.New, c.O.ChallengeSecret)
	h.Write(toSign)
	return h.Sum(nil)
}

// unsignedBuffer is an octokey buffer containing everything except the signature
func (c *Challenge) unsignedBuffer() *buffer.Buffer {
	b := &buffer.Buffer{}
	b.AddUint8(c.Version)
	b.AddTimestamp(c.Timestamp)
	b.AddIP(c.ClientIp)
	b.AddVarBytes(c.Random)
	return b
}

// unsignedBuffer is an octokey buffer containing everything including the signature
func (c *Challenge) signedBuffer() *buffer.Buffer {
	b := c.unsignedBuffer()
	b.AddVarBytes(c.expectedDigest())
	return b
}
