// Copyright 2019 Collin Kreklow
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

package beast

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestUnmarshalBadData(t *testing.T) {
	testUnmarshalError(t, "ff0000ff", "format identifier not found")
}

func TestUnmarshalBadLength2(t *testing.T) {
	testUnmarshalError(t, "1a32ffff", "expected 16 bytes, received 4")
}

func TestUnmarshalBadLength3(t *testing.T) {
	testUnmarshalError(t, "1a33ffff", "expected 23 bytes, received 4")
}

func TestUnmarshalType1(t *testing.T) {
	testUnmarshalError(t, "1a31ffff", "format not supported")
}

func TestUnmarshalType4(t *testing.T) {
	testUnmarshalError(t, "1a34ffff", "format not supported")
}

func TestUnmarshalBadType(t *testing.T) {
	testUnmarshalError(t, "1affffff", "invalid format identifier")
}

func TestUnmarshalBadDecode(t *testing.T) {
	testUnmarshalError(t, "1a32ffffffffffffffffffffffffffff", "unsupported format: 31")
}

func testUnmarshalError(t *testing.T, msg string, e string) {
	f := new(Frame)
	b, err := hex.DecodeString(msg)
	if err != nil {
		t.Fatal("unexpected error:", err)
	}
	err = f.UnmarshalBinary(b)
	if err == nil {
		t.Errorf("expected %s, received nil", e)
	} else if err.Error() != e {
		t.Errorf("expected %s, received %s", e, err.Error())
	}
}

type testCase struct {
	Msg string

	Format    uint8
	Timestamp uint64
	Signal    uint8

	DF   int
	TC   int
	ICAO string
}

func TestDecode2(t *testing.T) {
	tc := &testCase{
		Msg:       "1a3216f933baf325c45da99adad95ff6",
		Format:    2,
		Timestamp: 25259570557733,
		Signal:    196,
		DF:        11,
		TC:        -1,
		ICAO:      "a99ada",
	}
	testDecoder(t, tc)
}

func TestDecode3(t *testing.T) {
	tc := &testCase{
		Msg:       "1a3316f933bbc63ec68da99ada58b98446e703357e2417",
		Format:    3,
		Timestamp: 25259570611774,
		Signal:    198,
		DF:        17,
		TC:        11,
		ICAO:      "a99ada",
	}
	testDecoder(t, tc)
}

func testDecoder(t *testing.T, tc *testCase) {
	b, err := hex.DecodeString(tc.Msg)
	if err != nil {
		t.Fatal("unexpected error:", err)
	}
	r := bytes.NewReader(b)
	d := NewDecoder(r)
	f := new(Frame)
	err = d.Decode(f)
	if err != nil {
		t.Fatal("unexpected error:", err)
	}

	if tc.Format != f.Format {
		t.Errorf("Format: expected %d, received %d", tc.Format, f.Format)
	}
	if tc.Timestamp != f.Timestamp {
		t.Errorf("Timestamp: expected %d, received %d", tc.Timestamp, f.Timestamp)
	}
	if tc.Timestamp != f.Timestamp {
		t.Errorf("Timestamp: expected %d, received %d", tc.Timestamp, f.Timestamp)
	}
	if tc.Signal != f.Signal {
		t.Errorf("Signal: expected %d, received %d", tc.Signal, f.Signal)
	}
	if tc.DF != int(f.Msg.DF) {
		t.Errorf("DF: expected %d, received %d", tc.DF, f.Msg.DF)
	}
	if tc.TC != int(f.Msg.TC) {
		t.Errorf("TC: expected %d, received %d", tc.TC, f.Msg.TC)
	}
	if tc.ICAO != f.Msg.ICAO {
		t.Errorf("ICAO: expected %s, received %s", tc.ICAO, f.Msg.ICAO)
	}
}

func TestDecodeNull(t *testing.T) {
	testDecoderError(t, "", "EOF")
}

func TestDecodeShort1(t *testing.T) {
	testDecoderError(t, "1a", "EOF")
}

func TestDecodeShort2(t *testing.T) {
	testDecoderError(t, "1a31", "EOF")
}

func TestDecodeShort3(t *testing.T) {
	testDecoderError(t, "1a331a", "EOF")
}

func TestDecodeShortUnescape(t *testing.T) {
	testDecoderError(t, "1a331a1a", "EOF")
}

func TestDecodeBadStart(t *testing.T) {
	testDecoderError(t, "ff00", "data stream corrupt")
}

func TestDecodeTruncated(t *testing.T) {
	testDecoderError(t, "1a32ffff1a33ff", "frame truncated")
}

func TestDecodeUnsupported1(t *testing.T) {
	testDecoderError(t, "1affffff", "unsupported frame type")
}

func TestDecodeUnsupported2(t *testing.T) {
	testDecoderError(t, "1a31ffffffffffffffffff", "format not supported")
}

func testDecoderError(t *testing.T, msg string, e string) {
	b, err := hex.DecodeString(msg)
	if err != nil {
		t.Fatal("unexpected error:", err)
	}
	r := bytes.NewReader(b)
	d := NewDecoder(r)
	f := new(Frame)
	err = d.Decode(f)
	if err == nil {
		t.Errorf("expected %s, received nil", e)
	} else if err.Error() != e {
		t.Errorf("expected %s, received %s", e, err.Error())
	}
}
