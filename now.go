package octokey

import (
	"time"
)

var timeFactory = time.Now

// now is the same as time.Now() unless you're inside a function
// called by at()
func now() time.Time {
	return timeFactory()
}

// at runs your function with now() returning the provided time.
func at(t time.Time, f func()) {
	timeFactory = func() time.Time { return t }
	defer (func() { timeFactory = time.Now })()
	f()
}
