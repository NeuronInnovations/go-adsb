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

package adsb

import (
	"bytes"
	"errors"
	"math"
)

// Message provides a high-level abstraction for ADS-B messages. The
// methods of Message provide convenient access to common data values.
// Use RawMessage to obtain direct access to the underlying binary data.
type Message struct {
	raw *RawMessage
}

const MPS_PER_KNOT = 0.514444444 // factor to convert from knot to meters per second

// NewMessage wraps a RawMessage and returns the new Message.
func NewMessage(r *RawMessage) (*Message, error) {
	m := new(Message)
	m.raw = r

	err := m.validateRaw()
	if err != nil {
		return nil, err
	}

	return m, nil
}

// UnmarshalBinary implements the BinaryUnmarshaler interface, storing
// the supplied data in the Message.
//
// If an error is returned that wraps ErrUnsupported, the data was
// successfully Unmarshalled and the Raw() method will still return the
// RawMessage for further inspection.
func (m *Message) UnmarshalBinary(data []byte) error {
	if m.raw == nil {
		m.raw = new(RawMessage)
	}

	err := m.raw.UnmarshalBinary(data)
	if err != nil {
		return err
	}

	return m.validateRaw()
}

// Validate that the downlink format is an expected value.
func (m *Message) validateRaw() error {
	df, err := m.raw.DF()
	if err != nil {
		return err
	}

	switch df {
	case 0, 4, 5, 11, 16, 17, 18, 20, 21, 24:
		return nil
	default:
		return newErrorf(ErrUnsupported, "downlink format %d", df)
	}
}

// Raw returns the underlying RawMessage. The content of the RawMessage
// will be overwritten by a subsequent call to UnmarsahalBinary.
func (m *Message) Raw() *RawMessage {
	return m.raw
}

// ICAO returns the ICAO address as an unsigned integer.
//
// Since the ICAO address is often extracted from the parity field,
// additional validation against a list of known addresses may be
// warranted.
func (m *Message) ICAO() (uint64, error) {
	aa, err := m.raw.AA()
	if err == nil {
		return aa, nil
	} else if !errors.Is(err, ErrNotAvailable) {
		return 0, err
	}

	ap, err := m.raw.AP()
	if err != nil {
		return 0, err
	}

	return ap ^ m.raw.Parity(), nil
}

// Alt returns the altitude.
func (m *Message) Alt() (int64, error) {
	df, err := m.raw.DF()
	if err != nil {
		return 0, newError(err, "error retrieving altitude")
	}

	switch df {
	case 0, 4, 16, 20:
		ac, err := m.raw.AC()
		if err != nil {
			return 0, newError(err, "error retrieving altitude")
		}

		return decodeAC(ac)
	case 17, 18:
		alt, err := m.raw.ESAltitude()
		if err != nil {
			return 0, newError(err, "error retrieving altitude")
		}

		return decodeESAlt(alt)
	default:
		return 0, newError(ErrNotAvailable, "error retrieving altitude")
	}
}

var callChars = []byte(
	"?ABCDEFGHIJKLMNOPQRSTUVWXYZ????? ???????????????0123456789??????")

// Call returns the callsign.
func (m *Message) Call() (string, error) {
	df, err := m.raw.DF()
	if err != nil {
		return "", newError(err, "error retrieving callsign")
	}

	switch df {
	case 17, 18:
		tc, _ := m.raw.ESType()
		if tc < 1 || tc > 4 {
			return "", newError(ErrNotAvailable, "error retrieving callsign")
		}
	case 20, 21:
		if m.raw.Bits(33, 40) != 0x20 {
			return "", newError(ErrNotAvailable, "error retrieving callsign")
		}
	default:
		return "", newError(ErrNotAvailable, "error retrieving callsign")
	}

	bits := m.raw.Bits(41, 88)

	call := make([]byte, 8)

	var i uint
	for i = 0; i < 8; i++ {
		call[i] = callChars[(bits>>(42-(i*6)))&0x3F]
	}

	return string(bytes.TrimRight(call, " ")), nil
}

var sqkTbl = [][]int{
	{25, 23, 21},
	{31, 29, 27},
	{24, 22, 20},
	{32, 30, 28},
}

// Sqk returns the squawk code.
func (m *Message) Sqk() ([]byte, error) {
	sqk := make([]byte, 0, 4)

	df, err := m.raw.DF()
	if err != nil {
		return nil, newError(err, "error retrieving squawk")
	}

	switch df {
	case 5, 21:
	default:
		return nil, newError(ErrNotAvailable, "error retrieving squawk")
	}

	sqk = sqk[0:4]

	for i, v := range sqkTbl {
		for _, x := range v {
			sqk[i] <<= 1
			sqk[i] |= m.raw.Bit(x)
		}
	}

	return sqk, nil
}

// CPR returns the compact position report.
func (m *Message) CPR() (*CPR, error) {
	df, err := m.raw.DF()
	if err != nil {
		return nil, newError(err, "error retrieving position")
	}

	switch df {
	case 17, 18:
		tc, err := m.raw.ESType()
		if err != nil {
			return nil, newError(err, "error retrieving position")
		}

		if tc < 9 || tc > 18 {
			return nil, newError(ErrNotAvailable, "error retrieving position")
		}
	default:
		return nil, newError(ErrNotAvailable, "error retrieving position")
	}

	c := new(CPR)
	c.Nb = 17
	c.T = m.raw.Bit(53)
	c.F = m.raw.Bit(54)
	c.Lat = uint32(m.raw.Bits(55, 71))
	c.Lon = uint32(m.raw.Bits(72, 88))

	return c, nil
}

// Ground speed decoding with GNSS information, in m/s.
// velocity: in m/s.
// heading: in degrees where the north is 0, east is 90, south is 180, west is 270.
func (m *Message) GroundSpeed() (velocity, heading float64, err error) {
	tc := m.raw.TC()
	if tc != 19 {
		return 0.0, 0.0, newError(ErrNotAvailable, "ground speed not available")
	}

	subType := m.raw.Bits(38, 40)
	if subType != 1 && subType != 2 {
		return 0.0, 0.0, newError(ErrNotAvailable, "ground speed not available")
	}

	dew := int(m.raw.Bit(46))
	vew := int(m.raw.Bits(47, 56))
	dns := int(m.raw.Bit(57))
	vns := int(m.raw.Bits(58, 67))

	if vew == 0 || vns == 0 {
		return 0.0, 0.0, newError(ErrNotAvailable, "ground speed not available")
	}

	vEW := float64(vew - 1)
	vNS := float64(vns - 1)
	if subType == 2 {
		vEW *= 4
		vNS *= 4
	}
	if dew == 1 {
		vEW = -vEW
	}
	if dns == 1 {
		vNS = -vNS
	}

	velocity = math.Sqrt(vEW*vEW+vNS*vNS) * MPS_PER_KNOT
	heading = math.Atan2(vEW, vNS) * 180.0 / math.Pi

	return velocity, heading, nil
}
