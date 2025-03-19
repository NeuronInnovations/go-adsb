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
	"encoding/hex"
	"errors"
	"fmt"
	"math"

	"github.com/NeuronInnovations/go-adsb/adsbtype"
)

// Message provides a high-level abstraction for ADS-B messages. The
// methods of Message provide convenient access to common data values.
// Use RawMessage to obtain direct access to the underlying binary data.
type Message struct {
	raw *RawMessage
}

const (
	KNOT_TO_MPS         = 0.514444444 // factor to convert from knot to m/s
	FEET_PER_MIN_TO_MPS = 0.00508     // factor to convert from feet/min to m/s
)

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
func (m *Message) CPR() (*CPR, bool, error) {
	df, err := m.raw.DF()
	if err != nil {
		return nil, false, newError(err, "error retrieving position")
	}

	var typeCode uint64
	switch df {
	case 17, 18:
		tc, err := m.raw.ESType()
		typeCode = tc
		if err != nil {
			return nil, false, newError(err, "error retrieving position")
		}

		if (tc < 9 || tc > 18) && (tc < 5 || tc > 8) {
			return nil, false, newError(ErrNotAvailable, "error retrieving position")
		}
	default:
		return nil, false, newError(ErrNotAvailable, "error retrieving position")
	}

	c := new(CPR)
	c.Nb = 17
	c.T = m.raw.Bit(53)
	c.F = m.raw.Bit(54)
	c.Lat = uint32(m.raw.Bits(55, 71))
	c.Lon = uint32(m.raw.Bits(72, 88))

	isAirborne := typeCode >= 9 && typeCode <= 18
	return c, isAirborne, nil
}

// Vertical speed, in m/s.
func (m *Message) VerticalSpeed() (float64, error) {
	df, err := m.raw.DF()
	if err != nil {
		return 0.0, newError(ErrNotAvailable, "err decode DF")
	} else if df != 17 && df != 18 {
		return 0.0, newError(ErrNotAvailable, "not a DF 17/18 packet")
	}

	tc := m.raw.TC()
	if tc != 19 {
		return 0.0, newError(ErrNotAvailable, "vertical rate not available")
	}

	dlen := m.raw.data.Len()
	if dlen < 14 {
		return 0.0, newError(ErrNotAvailable, fmt.Sprintf("invalid msg len: %d, %s", dlen, hex.EncodeToString(m.raw.data.Bytes())))
	}

	svr := int(m.raw.Bit(69))
	vr := int(m.raw.Bits(70, 78))
	if vr == 0 {
		return 0.0, newError(ErrNotAvailable, "vertical rate not available")
	}

	v := 64 * (vr - 1)
	if svr == 1 {
		v = -v
	}
	return float64(v) * FEET_PER_MIN_TO_MPS, nil
}

// Ground speed decoding with GNSS information, in m/s.
// velocity: in m/s.
// trackAngle: in degrees with range (-180, 180], where the north is 0, east is 90, south is 180, west is -90.
func (m *Message) GroundSpeed() (velocity, trackAngle float64, err error) {
	df, err := m.raw.DF()
	if err != nil {
		return 0.0, 0.0, newError(ErrNotAvailable, "err decode DF")
	} else if df != 17 && df != 18 {
		return 0.0, 0.0, newError(ErrNotAvailable, "not a DF 17/18 packet")
	}

	tc := m.raw.TC()
	if tc != 19 {
		return 0.0, 0.0, newError(ErrNotAvailable, "ground speed not available")
	}

	dlen := m.raw.data.Len()
	if dlen < 14 {
		return 0.0, 0.0, newError(ErrNotAvailable, fmt.Sprintf("invalid msg len: %d, %s", dlen, hex.EncodeToString(m.raw.data.Bytes())))
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

	velocity = math.Sqrt(vEW*vEW+vNS*vNS) * KNOT_TO_MPS
	trackAngle = math.Atan2(vEW, vNS) * 180.0 / math.Pi

	return velocity, trackAngle, nil
}

func (m *Message) SurfaceSpeed() (velocity, trackAngle float64, err error) {
	// Check if the message is a valid DF 17 or DF 18 (ADS-B message)
	df, err := m.raw.DF()
	if err != nil {
		return 0.0, 0.0, newError(ErrNotAvailable, "err decode DF")
	} else if df != 17 && df != 18 {
		return 0.0, 0.0, newError(ErrNotAvailable, "not a DF 17/18 packet")
	}

	// Check if the type code (TC) is for surface position (TC 5-8)
	tc := m.raw.TC()
	if tc < 5 || tc > 8 {
		return 0.0, 0.0, newError(ErrNotAvailable, "surface speed not available")
	}

	// Ensure the message has enough bits for surface speed decoding
	dlen := m.raw.data.Len()
	if dlen < 14 {
		return 0.0, 0.0, newError(ErrNotAvailable, fmt.Sprintf("invalid msg len: %d, %s", dlen, hex.EncodeToString(m.raw.data.Bytes())))
	}

	// Decode the movement field (ground speed)
	movement := int(m.raw.Bits(38, 44))
	velocity, err = decodeGroundSpeed(movement)
	if err != nil {
		return 0.0, 0.0, err
	}

	// Decode the ground track field
	trackStatus := int(m.raw.Bit(45))
	if trackStatus != 1 {
		return 0.0, 0.0, newError(ErrNotAvailable, "ground track not available")
	}
	trackEncoded := int(m.raw.Bits(46, 52))
	trackAngle = float64(trackEncoded) * (360.0 / 128.0)

	// Convert ground speed from knots to meters per second (optional)
	velocity *= KNOT_TO_MPS

	return velocity, trackAngle, nil
}

// decodeGroundSpeed decodes the ground speed from the movement field
func decodeGroundSpeed(movement int) (float64, error) {
	switch {
	case movement == 0:
		return 0.0, newError(ErrNotAvailable, "speed not available")
	case movement == 1:
		return 0.0, nil // Stopped
	case movement >= 2 && movement <= 8:
		return 0.125 + 0.125*float64(movement-2), nil
	case movement >= 9 && movement <= 12:
		return 1.0 + 0.25*float64(movement-9), nil
	case movement >= 13 && movement <= 38:
		return 2.0 + 0.5*float64(movement-13), nil
	case movement >= 39 && movement <= 93:
		return 15.0 + 1.0*float64(movement-39), nil
	case movement >= 94 && movement <= 108:
		return 70.0 + 2.0*float64(movement-94), nil
	case movement >= 109 && movement <= 123:
		return 100.0 + 5.0*float64(movement-109), nil
	case movement == 124:
		return 175.0, nil
	default:
		return 0.0, newError(ErrNotAvailable, "invalid movement value")
	}
}

// AircraftDetails retrieves the combined aircraft type and emitter category details.
func (m *Message) AircraftDetails() (string, error) {
	df, err := m.raw.DF()
	if err != nil {
		return "", newError(ErrNotAvailable, "error retrieving DF")
	}
	if df != 17 && df != 18 {
		return "", newError(ErrNotAvailable, "not a DF 17/18 packet")
	}

	// Retrieve Type Code (TC) and ensure it's between 1 and 4
	tc := m.raw.TC()
	if tc < 1 || tc > 4 {
		return "", newError(ErrNotAvailable, "Invalid Type Code")
	}

	// Retrieve Emitter Category (CAT) and ensure it's between 0 and 7
	ec := m.raw.CAT()
	if ec > 7 {
		return "", newError(ErrNotAvailable, "Invalid Category value")
	}

	// Create the key to lookup in EmitterCategories
	key := adsbtype.EmitterKey{
		TC:  adsbtype.TC(tc),
		CAT: adsbtype.CAT(ec),
	}

	emitterDescription, ok := adsbtype.EmitterCategories[key]
	if !ok {
		return "", newError(ErrNotAvailable, "Emitter Category not defined for this combination")
	}

	return emitterDescription, nil
}
