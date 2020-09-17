// Copyright 2020 Collin Kreklow
//
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions:
//
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
// BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
// ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package beast_test

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"testing"

	"kreklow.us/go/go-adsb/beast"
)

type testCase struct {
	Msg  string
	ADSB string

	Format    uint8
	Signal    uint8
	Timestamp int64
}

func TestDecode2(t *testing.T) {
	tc := &testCase{
		Msg:       "1a3216f933baf325c45da99adad95ff6",
		ADSB:      "5da99adad95ff6",
		Format:    2,
		Timestamp: 2104964213144500,
		Signal:    196,
	}
	testDecoder(t, tc)
}

func TestDecode3(t *testing.T) {
	tc := &testCase{
		Msg:       "1a3316f933bbc63ec68da99ada58b98446e703357e2417",
		ADSB:      "8da99ada58b98446e703357e2417",
		Format:    3,
		Timestamp: 2104964217648000,
		Signal:    198,
	}
	testDecoder(t, tc)
}

func testDecoder(t *testing.T, tc *testCase) {
	b, err := hex.DecodeString(tc.Msg)
	if err != nil {
		t.Fatal("unexpected error:", err)
	}

	r := bytes.NewReader(b)
	d := beast.NewDecoder(r)
	f := new(beast.Frame)

	err = d.Decode(f)
	if err != nil {
		t.Fatal("unexpected error:", err)
	}

	if tc.Timestamp != f.Timestamp().Nanoseconds() {
		t.Errorf("Timestamp: expected %d, received %d", tc.Timestamp, f.Timestamp().Nanoseconds())
	}

	if tc.Signal != f.Signal() {
		t.Errorf("Signal: expected %d, received %d", tc.Signal, f.Signal())
	}

	if tc.ADSB != hex.EncodeToString(f.ADSB()) {
		t.Errorf("ADSB: expected %s, received %s", tc.ADSB, hex.EncodeToString(f.ADSB()))
	}
}

func TestDecodeNull(t *testing.T) {
	testDecoderError(t, "", "error reading stream: EOF", io.EOF)
}

func TestDecodeShort1(t *testing.T) {
	testDecoderError(t, "1a", "error reading stream: EOF", io.EOF)
}

func TestDecodeShort2(t *testing.T) {
	testDecoderError(t, "1a31", "error reading stream: EOF", io.EOF)
}

func TestDecodeShort3(t *testing.T) {
	testDecoderError(t, "1a331a", "error reading stream: EOF", io.EOF)
}

func TestDecodeShortUnescape(t *testing.T) {
	testDecoderError(t, "1a331a1a", "error reading stream: EOF", io.EOF)
}

func TestDecodeBadStart(t *testing.T) {
	testDecoderError(t, "ff00", "data stream corrupt", nil)
}

func TestDecodeTruncated(t *testing.T) {
	testDecoderError(t, "1a32ffff1a33ff", "frame truncated", nil)
}

func TestDecodeUnsupported1(t *testing.T) {
	testDecoderError(t, "1affffff", "unsupported frame type: ff", nil)
}

func TestDecodeUnsupported2(t *testing.T) {
	testDecoderError(t, "1a31ffffffffffffffffff", "format not supported: 31", nil)
}

func testDecoderError(t *testing.T, msg string, str string, we error) {
	b, err := hex.DecodeString(msg)
	if err != nil {
		t.Fatal("unexpected error:", err)
	}

	r := bytes.NewReader(b)
	d := beast.NewDecoder(r)
	f := new(beast.Frame)

	err = d.Decode(f)
	if err == nil {
		t.Errorf("expected %s, received nil", str)

		return
	}

	if err.Error() != str {
		t.Errorf("expected %s, received %s", str, err.Error())
	}

	if we != nil && !errors.Is(err, we) {
		t.Errorf("expected type %T, received type %T", we, err)
	}
}
