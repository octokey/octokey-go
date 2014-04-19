// Package octokey/buffer provides bit-packing needed by Octokey based on RFC 4251
package buffer

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"math/big"
	"net"
	"time"
	"unicode/utf8"
)

const MAX_STRING_SIZE = 100 * 1024

type Buffer struct {
	bytes.Buffer
	Error error
}

func NewBuffer(s string) *Buffer {
	b, err := base64.StdEncoding.DecodeString(s)

	return &Buffer{*bytes.NewBuffer(b), err}
}

func (b *Buffer) AddUint8(x uint8) {
	b.binaryWrite(x)
}

func (b *Buffer) ScanUint8() (x uint8) {
	b.binaryRead(&x)
	return x
}

func (b *Buffer) AddTimestamp(t time.Time) {
	x := uint64(t.Unix()*1000) + uint64(t.Nanosecond()/1000)
	b.binaryWrite(x)
}

func (b *Buffer) ScanTimestamp() (t time.Time) {

	var tmp uint64
	b.binaryRead(&tmp)

	return time.Unix(int64(tmp/1000), int64(tmp%1000)*1000)
}

func (b *Buffer) AddIP(ip net.IP) {

	// FIXME: The ruby octokey client distinguishes between the IPv6 address
	// ::ff.192.168.0.1 and the IPv4 address 192.168.0.1. The go client does
	// not
	tmp := ip.To4()

	if tmp != nil {
		b.AddUint8(4)
		b.Write(tmp)
	} else {
		b.AddUint8(6)
		b.Write(ip.To16())
	}
}

func (b *Buffer) ScanIP() (ip net.IP) {

	switch b.ScanUint8() {
	case 4:
		ip = make([]uint8, 4)
	case 6:
		ip = make([]uint8, 16)
	default:
		ip = make([]uint8, 0)
	}

	b.binaryRead(&ip)
	return ip.To16()
}

func (b *Buffer) AddString(x string) {
	if !utf8.ValidString(x) {
		b.Error = errors.New("octokey/buffer not writing invalid utf8")
		return
	}

	b.AddVarBytes([]byte(x))
}

func (b *Buffer) ScanString() string {

	x := b.ScanVarBytes()
	if !utf8.Valid(x) {
		b.Error = errors.New("octokey/buffer: not reading invalid utf8")
		return ""
	}

	return string(x)
}

func (b *Buffer) AddVarBytes(x []byte) {
	// FIXME: the ruby client raises if the varbytes are too big
	b.binaryWrite(uint32(len(x)))
	b.Write(x)
}

func (b *Buffer) ScanVarBytes() []byte {

	var l uint32
	b.binaryRead(&l)

	if l > MAX_STRING_SIZE {
		b.Error = errors.New("octokey/buffer: not reading long string")
		return make([]byte, 0)
	}

	bytes := make([]byte, l)
	b.binaryRead(&bytes)
	return bytes
}

func (b *Buffer) AddMPInt(x *big.Int) {
	if x.Cmp(big.NewInt(0)) < 0 {
		b.Error = errors.New("octokey/buffer: not writing negative mpint")
		return
	}

	tmp := x.Bytes()
	// RFC 2451 allows for negative integers using two's-complement.
	// We ensure that the first byte is a 0 for compatibility, even
	// though Octokey only uses positive numbers.
	if len(tmp) > 0 && tmp[0] >= 0x80 {
		b.binaryWrite(uint32(len(tmp) + 1))
		b.AddUint8(0)
		b.Write(tmp)
	} else {
		b.AddVarBytes(tmp)
	}
}

func (b *Buffer) ScanMPInt() (x *big.Int) {

	tmp := b.ScanVarBytes()
	x = new(big.Int)

	if len(tmp) > 0 && tmp[0] >= 0x80 {
		b.Error = errors.New("octokey/buffer: not reading negative mpint")
		return
	}

	if len(tmp) > 0 && tmp[0] == 0x00 && tmp[1] < 0x80 {
		b.Error = errors.New("octokey/buffer: not reading suspicious mpint")
		return
	}

	x.SetBytes(tmp)
	return
}

func (b *Buffer) AddBuffer(x *Buffer) {
	b.AddVarBytes(x.Raw())
}

func (b *Buffer) ScanBuffer() *Buffer {
	return &Buffer{*bytes.NewBuffer(b.ScanVarBytes()), nil}
}

func (b *Buffer) ScanEof() {

	if b.Error != nil {
		return
	}

	if b.Len() != 0 {
		b.Error = errors.New("octokey/buffer: buffer too long")
	}
}

// Raw returns the contents of the buffer in bytes.
func (b *Buffer) Raw() []byte {
	return b.Bytes()
}

// String returns the contents of the buffer in Base64.
func (b *Buffer) String() string {
	return base64.StdEncoding.EncodeToString(b.Raw())
}

// binaryRead uses reflection to read at item from the buffer. If that item is
// a number, it will be read in BigEndian order. If buf.err is set, nothing is
// read. If an error occurs while reading, buf.err is set.
func (b *Buffer) binaryRead(x interface{}) {
	if b.Error != nil {
		return
	}

	err := binary.Read(b, binary.BigEndian, x)

	if err != nil {
		b.Error = err
	}
}

// binaryWrite uses reflection to write an item into the buffer. If that item is
// a number, it will be written in BigEndian order.  If buf.err is set, nothing
// is written. If an error occurs while writing, buf.err is set.
func (b *Buffer) binaryWrite(x interface{}) {

	if b.Error != nil {
		return
	}

	err := binary.Write(b, binary.BigEndian, x)

	if err != nil {
		b.Error = err
	}

}
