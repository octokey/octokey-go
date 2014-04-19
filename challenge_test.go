package octokey

import (
	"net"
	"strings"
	"testing"
	"time"
)

func TestNewChallengeIsValid(t *testing.T) {

	O := &Octokey{ChallengeSecret: []byte("hello world")}
	c, err := O.NewChallenge(net.ParseIP("127.0.0.1"))

	if err != nil {
		t.Fatal(err)
	}

	c2 := Challenge{O: O}
	c2.ReadFrom(c, net.ParseIP("127.0.0.1"))

	if c2.String() != c {
		t.Fatal(c2.String() + " != " + c)
	}

}

func TestValidation(t *testing.T) {

	for _, line := range strings.Split(TSV, "\n") {
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		fields := strings.Split(line, "\t")

		if len(fields) < 6 {
			t.Error(fields)
		}

		buffer, ok, errors, comment := fields[0], fields[3], fields[4], fields[5]

		date, err := time.Parse(time.RFC3339Nano, fields[1])
		if err != nil {
			t.Error(comment, err)
		}
		clientIp := net.ParseIP(fields[2])

		O := &Octokey{ChallengeSecret: []byte("12345")}

		at(date, func() {
			challenge := Challenge{O: O}
			challenge.ReadFrom(buffer, clientIp)

			if ok == "ok" {
				if len(challenge.Errors) > 0 {
					t.Error(comment, challenge.Errors)
				}

				if challenge.String() != buffer {
					t.Error(comment, challenge.String(), "!=", buffer)
				}
			} else {
				if len(challenge.Errors) == 0 {
					t.Error(comment, "did not fail")
				} else if len(challenge.Errors) != len(strings.Split(errors, ",")) {
					t.Error(comment, challenge.Errors, "!=", strings.Split(errors, ","))
				}

			}
		})

	}

}

const TSV = `
# challenge \t time \t client_ip \t valid \t errors \t comment	
AwAAATh9QH5LBH8AAAEAAAAg4crphs34YEVtBlq6SBuXvxaPspw/xrZevg7y8G4sGO4AAAAUNZB5XhNSefwLx3LXo7bfD9gD0FE=	2012-07-12T22:12:58.700Z	127.0.0.1	ok		example from now
AwAAATh9QH5LBgAAAAAAAAAAAAAAAAAAAAEAAAAgQeX8WvCI8lvxhdtuxZwsChTCT3YkGjE3XokW8t0D74oAAAAU9ec1/erT9z79bDTi/0zOkLt1gro=	2012-07-12T22:12:58.700Z	::1	ok		example with IPv6
# Removing this for now. It doesn't work on old rubies...
# AwAAAgmsTLsLBH8AAAEAAAAgPh+8E5nClERSRE+fBuOaTgYGysSy1aznwC8CRsdrOvsAAAAUBI0GylIYzCmvWxCpYLzD90b4EG0=	2040-12-31T12:11:20.654Z	127.0.0.1	ok		example from beyond 2038
AwAAATh9QIzMBH8AAAEAAAAgATuV8uT68x1fMtke3jCfQ9lqIhIpn8PdXUA02ZNF3fYAAAAUK1f4s9oM+r2m0uaM/m2bg9HJH3I=	2012-07-12T22:12:54.986Z	127.0.0.1	ok		example with date slightly ahead
AwAAATh9QH5LBH8AAAIAAAAgBR8+t8n8taWi2X05Uf3xO+wlamG/uQNOhqDJNs3C9lsAAAAUa4veUjlrnSOmcTl3WCw4JZQxV+8=	2012-07-12T22:12:58.700Z	127.0.0.1	error	Challenge IP mismatch	wrong IP (127.0.0.2 given)
CQAAATh9QH5LBH8AAAEAAAAggU9GZHwiZ8YNzevWDaprAl5MmXSVS3AqryxgOB5U1eAAAAAUWzL48p09piGp2aLv3SgaQ/HFM+A=	2015-10-07T09:30:30.678Z	127.0.0.1	error	Challenge version mismatch	wrong version (9 instead of 3)
AwAAATh9QH5LBH8AAAEAAAAFc3h4GeMAAAAU6vzHLybIDgVcKS3sxlkdPnPoJFE=	2012-07-12T22:12:58.700Z	127.0.0.1	error	Challenge random mismatch	(5 bytes given, not 32)
AwAAATh9QH5LBH8AAAEAAAAgvQzKCKpwNgUmbjThMR+6R5MG50mHVwYLshAKD4UQcesAAAAU7ZayWxgweg9137+E6bGEoUxWgak=	2012-07-12T22:12:58.700Z	127.0.0.1	error	Challenge HMAC mismatch	wrong signature (signed with "54321" not "12345")
AwAAATh9QH5LBH8AAAEAAAAg1QO5d/B6hd3BLGNRtsPA7lh8D1Vv3iCuqg7teGaetBYAAAAViX2zRzyB1KtyzLYGvd3pGA4spLUA	2012-07-12T22:12:58.700Z	127.0.0.1	error	Challenge HMAC mismatch	wrong signature (contains a trailing null byte)
AwAAATh9MTwLBH8AAAEAAAAgz+aUOWoNQy2M0GpV8CSo52S6FilNvgmMemKxi6rSr8IAAAAUoP3krFuxkXNU9vkHXKf5GZv1m0w=	2012-07-12T22:12:58.700Z	127.0.0.1	error	Challenge too old	challenge created < 5 minutes ago
AwAAATh9T8CLBH8AAAEAAAAgIwhffU8zvonpicKsL6o2TWc0dU4n7WBV7SHFr7yh0+gAAAAUvMddIqcmuWrpLd6L8rPLSw/sTnU=	2012-07-12T22:12:58.700Z	127.0.0.1	error	Challenge too new	challenge created > 30 sec in the future
AwAAATh9QH5LBH8AAAIAAAAgL/vv6TcOf32f5iUsapi1eW3N2CBOv/WON6Bp4g+awKUAAAAUK7ovSBPpGjeqh5L8IVZMXg6gxsA=	2012-07-12T22:12:58.700Z	127.0.0.1	error	Challenge HMAC mismatch, Challenge IP mismatch	wrong IP address, signature valid with correct IP
IQAAATh9QH5LBH8AAAEAAAAgL/vv6TcOf32f5iUsapi1eW3N2CBOv/WON6Bp4g+awKUAAAAUK7ovSBPpGjeqh5L8IVZMXg6gxsA=	2012-07-12T22:12:58.700Z	127.0.0.1	error	Challenge version mismatch	version 33 not 3, signature would be correct with correct version
AwAAATh9QH5LBH8AAAEAAAAgL/vv6TcOf32f5iUsapi1eW3N2CBOv/WON6Bp4g+awKQAAAAUK7ovSBPpGjeqh5L8IVZMXg6gxsA=	2012-07-12T22:12:58.700Z	127.0.0.1	error	Challenge HMAC mismatch	one bit change in random
AwAAATh9QHZ7BH8AAAEAAAAgL/vv6TcOf32f5iUsapi1eW3N2CBOv/WON6Bp4g+awKUAAAAUK7ovSBPpGjeqh5L8IVZMXg6gxsA=	2012-07-12T22:12:54.986Z	127.0.0.1	error	Challenge HMAC mismatch	date mismatch, signature would be correct with provided date
AwAAATh9QH5LBH8AAAEAAAAhL/vv6TcOf32f5iUsapi1eW3N2CBOv/WON6Bp4g+awKUAAAAAFCu6L0gT6Ro3qoeS/CFWTF4OoMbA	2012-07-12T22:12:58.700Z	127.0.0.1	error	Challenge HMAC mismatch, Challenge random mismatch	trailing byte in random data, signature valid if removed
AwAAATh9IfH7BH8AAAIAAAAFMTIzNDUAAAAUK7ovSBPpGjeqh5L8IVZMXg6gxsA=	2012-07-12T22:12:58.700Z	127.0.0.1	error	Challenge HMAC mismatch, Challenge IP mismatch, Challenge random mismatch, Challenge too old	Everything wrong at once
AwAAATh9QH5LBH8AAAEAAAAgL/vv6TcOf32f5iUsapi1	2012-07-12T22:12:58.700Z	127.0.0.1	error	Buffer too short	truncation
AwAAATh9QH5LBH8AAAEAAAAgL/vv6TcOf32f5iUsapi1eW3N2CBOv/WON6Bp4g+awKUAAAAUK7ovSBPpGjeqh5L8IVZMXg6gxsBm	2012-07-12T22:12:58.700Z	127.0.0.1	error	Buffer too long	trailing byte
`
