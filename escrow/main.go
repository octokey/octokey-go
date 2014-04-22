package main

import (
	"errors"
	"github.com/octokey/octokey-go"
	"io/ioutil"
	"log"
	"net/http"
)

var STORE = make(map[string]string, 1)

func main() {

	http.HandleFunc("/upload", safely(upload))
	http.HandleFunc("/sign", safely(sign))

	log.Println("Listening on :5005")
	http.ListenAndServe(":5005", nil)

}

func upload(w http.ResponseWriter, r *http.Request) {

	file, _, err := r.FormFile("key")
	badRequestIf(err)

	content, err := ioutil.ReadAll(file)
	badRequestIf(err)

	key, err := octokey.NewPartialKey(string(content))
	badRequestIf(err)

	WriteKey(key)

	w.Write([]byte("OK"))
}

func sign(w http.ResponseWriter, r *http.Request) {

	content, err := ioutil.ReadAll(r.Body)
	badRequestIf(err)

	println(string(content))

	request, err := octokey.NewSignRequest(string(content))
	badRequestIf(err)

	println("TRY")

	key := ReadKey(request.Key)
	println(key.String())
	if key == nil {
		badRequestIf(errors.New("no such key"))
	}

	err = request.Sign(key)
	badRequestIf(err)

	println(request.String())

	w.Write([]byte(request.String()))
}

func safely(f http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		log.Println(r.RemoteAddr + "\t" + r.URL.Path)

		defer func() {
			if e := recover(); e != nil {
				switch e.(type) {
				case badRequest:
					log.Println(r.RemoteAddr + ": " + e.(badRequest).err.Error())
					w.Write([]byte("400 bad request"))
				case internalErr:
					log.Println(r.RemoteAddr + ": " + e.(badRequest).err.Error())
					w.Write([]byte("500 server error"))
				default:
					panic(e)
				}
			}
		}()

		f(w, r)
	}
}

type badRequest struct {
	err error
}
type internalErr struct {
	err error
}

func badRequestIf(err error) {
	if err != nil {
		panic(badRequest{err})
	}
}

func internalErrIf(err error) {
	if err != nil {
		panic(internalErr{err})
	}
}
