package main

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"errors"
	"github.com/ConradIrwin/mrsa"
	"github.com/octokey/octokey-go"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"testing"
)

func TestEscrowServer(t *testing.T) {

	k1, k2, err := octokey.GeneratePartialKey()

	if err != nil {
		t.Fatal(err)
	}

	_, err = uploadFile("http://localhost:5005/upload", "key", []byte(k2.String()))
	if err != nil {
		t.Fatal(err)
	}

	p2 := &octokey.PartialSigner{"http://localhost:5005/sign", (*octokey.PublicKey)(&k2.PublicKey)}

	s := new(mrsa.Session)
	s.Decryptors = append(s.Decryptors, p2)
	s.Decryptors = append(s.Decryptors, k1)
	s.PublicKey = k1.PublicKey

	buffer := sha1.Sum([]byte("Monkey!"))
	hashed := buffer[0:20]
	signature, err := s.SignPKCS1v15(crypto.SHA1, hashed)
	if err != nil {
		t.Fatal(err)
	}

	err = rsa.VerifyPKCS1v15((*rsa.PublicKey)(&k1.PublicKey), crypto.SHA1, hashed, signature)
	if err != nil {
		t.Fatal(err)
	}
}

func uploadFile(url string, name string, content []byte) ([]byte, error) {

	req := new(bytes.Buffer)

	w := multipart.NewWriter(req)

	file, err := w.CreateFormFile(name, "file.txt")
	if err != nil {
		return nil, err
	}
	_, err = file.Write([]byte(content))
	if err != nil {
		return nil, err
	}

	err = w.Close()
	if err != nil {
		return nil, err
	}

	res, err := http.Post(url, w.FormDataContentType(), req)
	if err != nil {
		return nil, err
	}

	if res.StatusCode != 200 {
		println(res.StatusCode)
		return nil, errors.New("Non-200 response")
	}

	return ioutil.ReadAll(res.Body)

}
