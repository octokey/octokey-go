package main

import (
	"github.com/octokey/octokey-go"
	"sync"
)

var Store = make(map[string]octokey.PartialKey)
var Mutex = sync.Mutex{}

func WriteKey(key *octokey.PartialKey) {
	Mutex.Lock()
	defer Mutex.Unlock()

	println(key.String())

	Store[(*octokey.PublicKey)(&key.PublicKey).String()] = *key
}

func ReadKey(key *octokey.PublicKey) *octokey.PartialKey {
	Mutex.Lock()
	defer Mutex.Unlock()

	ret, ok := Store[key.String()]
	if !ok {
		return nil
	}

	return &ret
}
