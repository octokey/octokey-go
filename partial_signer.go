package octokey

import (
	"errors"
	"io/ioutil"
	"math/big"
	"net/http"
	"reflect"
	"strings"
)
// A PartialSigner uses an escrow server to partially sign an mRSA request.
// Internally it sends a SignRequest to the server and expects a SignRequest
// response (which it could forward on to further servers if necessary)
type PartialSigner struct {
	Url string
	Key *PublicKey
}

// PartialDecrypt is used by the mrsa.Session to actually perform decryption.
func (ps *PartialSigner) PartialDecrypt(c *big.Int) (*big.Int, error) {

	request := new(SignRequest)
	request.Key = ps.Key
	request.M = c

	resp, err := ps.makeRequest(request.String())

	if err != nil {
		return nil, err
	}

	response, err := NewSignRequest(resp)

	if err != nil {
		return nil, err
	}

	if !reflect.DeepEqual(response.Key, request.Key) {
		return nil, errors.New("octokey/partial_signer: invalid response")
	}

	return response.M, nil
}

// makeRequest sends a sign reqquest to the mRSA escrow server and returns
// the resulting sign request
func (ps *PartialSigner) makeRequest(str string) (string, error) {

	res, err := http.Post(ps.Url, "octokey/sign-request", strings.NewReader(str))
	if err != nil {
		return "", err
	}

	if res.StatusCode != 200 {
		return "", errors.New("octokey/partial_signer: got non-200 response")
	}

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return "", err
	}

	return string(body), nil
}
