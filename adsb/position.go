// This file was modified from Original Copyright below:
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
	"math"
)

// CPR is an extended squitter compact position report.
type CPR struct {
	Nb  uint8  // number of encoded bits (17, 19, 14 or 12)
	T   uint8  // time bit
	F   uint8  // format bit
	Lat uint32 // encoded latitude
	Lon uint32 // encoded longitude
}

// DecodeLocal decodes an encoded position to a global latitude and
// longitude by comparing the position to a known reference point.
// Argument and return value is in the format [latitude, longitude].
func (c *CPR) DecodeLocal(rp []float64, isAirBorne bool) ([]float64, error) {
	switch {
	case len(rp) != 2:
		return nil, newError(nil, "must provide [lat, lon] as argument")
	case rp[0] > 90 || rp[0] < -90:
		return nil, newError(nil, "latitude out of range (-90 to 90)")
	case rp[1] > 190 || rp[1] < -180:
		return nil, newError(nil, "longitude out of range (-180 to 180)")
	}

	latr := rp[0]
	lonr := rp[1]
	latc := float64(c.Lat) / 131072
	lonc := float64(c.Lon) / 131072

	var dlat float64
	if isAirBorne {
		dlat = 360.0 / float64(60-c.F)
	} else {
		dlat = 90.0 / float64(60-c.F)
	}

	j := math.Floor(latr/dlat) +
		math.Floor((mod(latr, dlat)/dlat)-latc+0.5)

	coord := make([]float64, 2)

	coord[0] = dlat * (j + latc)

	var dlon float64

	nl := float64(cprNL(coord[0]) - c.F)

	if isAirBorne {
		if nl == 0 {
			dlon = 360.0
		} else {
			dlon = 360.0 / nl
		}
	} else {
		if nl == 0 {
			dlon = 90.0
		} else {
			dlon = 90.0 / nl
		}
	}

	m := math.Floor(lonr/dlon) +
		math.Floor((mod(lonr, dlon)/dlon)-lonc+0.5)

	coord[1] = dlon * (m + lonc)

	return coord, nil
}

func DecodeGlobalPosition(c1 *CPR, c2 *CPR, isAirBorne bool, referenceLat *float64, referenceLon *float64) ([]float64, error) {
	switch {
	case c1 == nil || c2 == nil:
		return nil, newError(nil, "incomplete arguments")
	case c1.Nb != c2.Nb:
		return nil, newError(nil, "bit encoding must be equal")
	case c1.F == c2.F:
		return nil, newError(nil, "format must be different")
	}

	var t0 bool // set t0 to true if the even format is the later message

	var lat0, lon0, lat1, lon1 float64

	if c1.F == 0 {
		t0 = false
		lat0 = float64(c1.Lat) / 131072 // 2**17 = 131072
		lon0 = float64(c1.Lon) / 131072
		lat1 = float64(c2.Lat) / 131072
		lon1 = float64(c2.Lon) / 131072
	} else {
		t0 = true
		lat0 = float64(c2.Lat) / 131072
		lon0 = float64(c2.Lon) / 131072
		lat1 = float64(c1.Lat) / 131072
		lon1 = float64(c1.Lon) / 131072
	}

	/* for surface vehicles, the following code should be used
	dlat0 := 90.0 / 60.0 // 360 / 4NZ  = 360 / 15 * 4
	dlat1 := 90.0 / 59.0 // 360 / 4NZ - 1  = 360 / 15 * 4 - 1
	*/

	var dlat0, dlat1 float64

	if isAirBorne {
		dlat0 = 360.0 / 60.0 // 360 / 4NZ  = 360 / 15 * 4
		dlat1 = 360.0 / 59.0 // 360 / 4NZ - 1  = 360 / 15 * 4 - 1

	} else {
		dlat0 = 90.0 / 60.0 // 360 / 4NZ  = 360 / 15 * 4
		dlat1 = 90.0 / 59.0 // 360 / 4NZ - 1  = 360 / 15 * 4 - 1
	}

	j := math.Floor(((59 * lat0) - (60 * lat1)) + 0.5)

	rlat0 := dlat0 * (mod(j, 60) + lat0)
	if rlat0 >= 270 {
		rlat0 -= 360
	}

	rlat1 := dlat1 * (mod(j, 59) + lat1)
	if rlat1 >= 270 {
		rlat1 -= 360
	}

	if cprNL(rlat0) != cprNL(rlat1) {
		return nil, newError(nil, "positions cross latitude boundary")
	}

	coord := calcGlobal(t0, lon0, lon1, rlat0, rlat1, isAirBorne, referenceLat, referenceLon)

	//TODO: check if null

	return coord, nil
}

// TODO: works for airborne positions but partially for surface. E.g. Birmingahm (norther hemisphere) is ok but Canbera (southern hemisphere) is not
// Use local decoding for surface for now and make sure you do sanity check for positions that are too far away from reference positions.
func calcGlobal(t0 bool, lon0, lon1, rlat0, rlat1 float64, isAirborne bool, referenceLat *float64, referenceLon *float64) []float64 {

	var nl, ni, dlon, lonc float64

	coord := make([]float64, 2)

	if t0 { //nolint:nestif // variables assigned based on t0 type
		coord[0] = rlat0
		nl = float64(cprNL(rlat0))

		if nl <= 1 {
			ni = 1
		} else {
			ni = nl
		}

		if isAirborne {
			dlon = 360.0 / ni
		} else {
			dlon = 90.0 / ni
		}

		lonc = lon0
	} else {
		coord[0] = rlat1
		nl = float64(cprNL(rlat1))

		if nl-1 <= 1 {
			ni = 1
		} else {
			ni = nl - 1
		}

		if isAirborne {
			dlon = 360.0 / ni
		} else {
			dlon = 90.0 / ni
		}
		lonc = lon1
	}

	//m := math.Floor(((lon0 * (nl - 1)) - (lon1 * nl)) + 0.5)
	m := math.Round(((lon0 * (nl - 1)) - (lon1 * nl)))
	coord[1] = dlon * (mod(m, ni) + lonc)
	if coord[1] >= 180 {
		coord[1] -= 360
	}

	// Modified candidate selection for longitude (surface messages)
	if !isAirborne {
		if referenceLon == nil || referenceLat == nil {
			return []float64{}
		}
		candidates := []float64{}
		for delta := -360.0; delta <= 360.0; delta += 90.0 {
			cand := coord[1] + delta
			if cand > 180 {
				cand -= 360
			} else if cand < -180 {
				cand += 360
			}
			candidates = append(candidates, cand)
		}
		// Select candidate minimizing the cosine-weighted difference
		closest := candidates[0]
		minDiff := math.Abs((*referenceLon - closest) * math.Cos(*referenceLat*math.Pi/180))
		for _, c := range candidates[1:] {
			diff := math.Abs((*referenceLon - c) * math.Cos(*referenceLat*math.Pi/180))
			if diff < minDiff {
				closest = c
				minDiff = diff
			}
		}
		coord[1] = closest
	}

	// For surface (non-airborne) messages, adjust latitude by selecting the candidate closest to the reference latitude.
	if !isAirborne {
		if referenceLat != nil {
			candidatesLat := []float64{}
			// Generate candidate latitudes by adding multiples of 90 degrees.
			// (We use 90° here because surface CPR covers a 90° zone.)
			for delta := -180.0; delta <= 180.0; delta += 90.0 {
				cand := coord[0] + delta
				// Clamp candidate to valid latitude range.
				if cand < -90 {
					cand = -90
				} else if cand > 90 {
					cand = 90
				}
				candidatesLat = append(candidatesLat, cand)
			}

			// Select the candidate latitude closest to the reference latitude.
			closestLat := candidatesLat[0]
			minDiff := math.Abs(*referenceLat - closestLat)
			for _, cand := range candidatesLat[1:] {
				if diff := math.Abs(*referenceLat - cand); diff < minDiff {
					closestLat = cand
					minDiff = diff
				}
			}

			coord[0] = closestLat
		}
	}
	return coord
}

// mod implements the MOD function as defined in the ADS-B
// specifications.
func mod(a float64, b float64) float64 {
	return a - (b * math.Floor(a/b))
}

/* Lookup table computed with the following code:
tbl := make(map[int]float64)

for nl := 59; nl > 1; nl-- {
	a := 1 - math.Cos(math.Pi/30)
	b := 1 - math.Cos(2*math.Pi/float64(nl))
	c := math.Sqrt(a / b)

	tbl[nl] = (180 / math.Pi) * math.Acos(c)

	fmt.Printf("%d: %s\n", nl, big.NewFloat(tbl[nl]).String())
}
*/

var nlTbl = map[uint8]float64{
	59: 10.4704713,
	58: 14.82817437,
	57: 18.18626357,
	56: 21.02939493,
	55: 23.54504487,
	54: 25.82924707,
	53: 27.9389871,
	52: 29.91135686,
	51: 31.77209708,
	50: 33.53993436,
	49: 35.22899598,
	48: 36.85025108,
	47: 38.41241892,
	46: 39.92256684,
	45: 41.38651832,
	44: 42.80914012,
	43: 44.19454951,
	42: 45.54626723,
	41: 46.86733252,
	40: 48.16039128,
	39: 49.42776439,
	38: 50.67150166,
	37: 51.89342469,
	36: 53.09516153,
	35: 54.27817472,
	34: 55.44378444,
	33: 56.59318756,
	32: 57.72747354,
	31: 58.84763776,
	30: 59.95459277,
	29: 61.04917774,
	28: 62.13216659,
	27: 63.20427479,
	26: 64.26616523,
	25: 65.3184531,
	24: 66.36171008,
	23: 67.39646774,
	22: 68.42322022,
	21: 69.44242631,
	20: 70.45451075,
	19: 71.45986473,
	18: 72.45884545,
	17: 73.45177442,
	16: 74.43893416,
	15: 75.42056257,
	14: 76.39684391,
	13: 77.36789461,
	12: 78.33374083,
	11: 79.29428225,
	10: 80.24923213,
	9:  81.19801349,
	8:  82.13956981,
	7:  83.07199445,
	6:  83.99173563,
	5:  84.89166191,
	4:  85.75541621,
	3:  86.53536998,
	2:  87,
}

// cprNL implements the longitude zone lookup table.
func cprNL(x float64) uint8 {
	x = math.Abs(x)

	var i uint8

	for i = 59; i > 1; i-- {
		if x < nlTbl[i] {
			return i
		}
	}

	return 1
}
