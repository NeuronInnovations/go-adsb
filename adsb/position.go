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

// Package adsb — position.go implements Compact Position Reporting (CPR) per
// EUROCAE ED-102B "Minimum Operational Performance Specification (MOPS) for
// 1090 MHz Extended Squitter ADS-B and TIS-B" (CPR: §T.3–§T.6, encoding §A.1.7).
// Equivalent material appears in RTCA DO-260B. An in-repo EUROCAE MOPS copy
// is available at the module root for cross-checking.
//
// Document page index (1-based; EUROCAE edition with 1492 numbered pages; locate
// material by § labels if pagination differs in another edition):
//   - §A.1.7 (CPR algorithm / field usage): pp. 1123 ff.
//   - §2.2.3.2.3.7 “CPR Encoded Latitude” (17-bit ME bits ↔ Lat): p. 87.
//   - §T.1–§T.10 (CPR tutorial): body pp. 1442–1486.
//   - §T.3 CPR coordinate system (zones): pp. 1444–1446.
//   - §T.5.1 global decoding (airborne): pp. 1451, 1456.
//   - §T.5.2 global decoding (surface): p. 1458.
//   - §T.5.3 local decoding (airborne): pp. 1459–1463.
//   - §T.5.4 local decoding (surface): p. 1464.
//   - §T.6 NL(φ) / transition latitudes (table aligns with nlTbl): pp. 1464, 1480.
//
// Inline comments tag steps against the § references above; 17-bit CPR uses 2^17 = 131072.
package adsb

import (
	"math"
)

// CPR is one extended squitter compact position report (Nb, T, F, Lat, Lon).
// Field sizes and ME bit placement follow §A.1.7 / §2.2.3.2.3.7 (pp. 1123 ff., 87).
type CPR struct {
	Nb  uint8  // number of encoded bits (17, 19, 14 or 12)
	T   uint8  // time bit (§T.4)
	F   uint8  // format bit: 0 = even, 1 = odd CPR subframe
	Lat uint32 // encoded latitude CPR (17-bit → scale by 1/131072)
	Lon uint32 // encoded longitude CPR (17-bit → scale by 1/131072)
}

// DecodeLocal — local (relative) CPR: one frame plus a reference [lat, lon]
// to resolve the latitude/longitude zones. Airborne uses 360°/NZ; surface uses 90°/NZ
// longitude cell width. §T.5.3 (airborne) / §T.5.4 (surface); pp. 1459–1464.
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
	// CPR latitude/longitude as fractional values in [0,1).
	latc := float64(c.Lat) / 131072
	lonc := float64(c.Lon) / 131072

	// latitude zone size Δ_lat — even/odd CPR grids (airborne 360°/NZ; surface 90°/NZ with F as in the MOPS).
	var dlat float64
	if isAirBorne {
		dlat = 360.0 / float64(60-c.F)
	} else {
		dlat = 90.0 / float64(60-c.F)
	}

	// latitude index j from reference lat and encoded latc.
	j := math.Floor(latr/dlat) +
		math.Floor((mod(latr, dlat)/dlat)-latc+0.5)

	coord := make([]float64, 2)

	// decoded latitude = Δ_lat * (j + latc).
	coord[0] = dlat * (j + latc)

	var dlon float64

	// NL(lat) from decoded lat; longitude zone count for this F.
	nl := float64(cprNL(coord[0]) - c.F)

	// longitude cell width Δ_lon — 360/NL airborne, 90/NL surface (NL=0 → one world strip).
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

	// longitude index m from reference lon and encoded lonc.
	m := math.Floor(lonr/dlon) +
		math.Floor((mod(lonr, dlon)/dlon)-lonc+0.5)

	// decoded longitude = Δ_lon * (m + lonc).
	coord[1] = dlon * (m + lonc)

	return coord, nil
}

// DecodeGlobalPosition — global CPR: two frames with opposite F (even+odd).
// referenceLat/referenceLon disambiguate surface latitude/longitude quadrants when non-nil.
// §T.5.1 (airborne) / §T.5.2 (surface); pp. 1451–1458.
func DecodeGlobalPosition(c1 *CPR, c2 *CPR, isAirBorne bool, referenceLat *float64, referenceLon *float64) ([]float64, error) {
	switch {
	case c1 == nil || c2 == nil:
		return nil, newError(nil, "incomplete arguments")
	case c1.Nb != c2.Nb:
		return nil, newError(nil, "bit encoding must be equal")
	case c1.F == c2.F:
		return nil, newError(nil, "format must be different")
	}

	// which subframe is “latest” sets which raw lat/lon pair is lat0/lon0 vs lat1/lon1.
	var t0 bool // true ⇒ even CPR is the later (second-in-time) message

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

	// global decode — Δ_lat for even (0) and odd (1) CPR subframes.
	var dlat0, dlat1 float64

	if isAirBorne {
		dlat0 = 360.0 / 60.0 // 360 / 4NZ  = 360 / 15 * 4
		dlat1 = 360.0 / 59.0 // 360 / 4NZ - 1  = 360 / 15 * 4 - 1

	} else {
		dlat0 = 90.0 / 60.0 // 360 / 4NZ  = 360 / 15 * 4
		dlat1 = 90.0 / 59.0 // 360 / 4NZ - 1  = 360 / 15 * 4 - 1
	}

	// latitude index j from paired even/odd fractional latitudes.
	j := math.Floor(((59 * lat0) - (60 * lat1)) + 0.5)

	// recovered latitudes rlat0, rlat1 before NL/NL consistency check.
	rlat0 := dlat0 * (mod(j, 60) + lat0)
	if rlat0 >= 270 {
		rlat0 -= 360
	}

	rlat1 := dlat1 * (mod(j, 59) + lat1)
	if rlat1 >= 270 {
		rlat1 -= 360
	}

	// §T.5.2 (surface): pick latitude hemisphere/band vs reference when given.
	if !isAirBorne && referenceLat != nil {
		adjustSurfaceCPRLatitudes(*referenceLat, &rlat0, &rlat1)
	}

	// both CPR latitudes must lie in the same NL(lat) band for a valid pair.
	if cprNL(rlat0) != cprNL(rlat1) {
		return nil, newError(nil, "positions cross latitude boundary")
	}

	// recover longitude from paired lon fractions + rlat*, then normalize.
	coord := calcGlobal(t0, lon0, lon1, rlat0, rlat1, isAirBorne, referenceLat, referenceLon)

	return coord, nil
}

// adjustSurfaceCPRLatitudes — surface latitude quadrant selection
// using a reference latitude (when encoded latitude hits ambiguous 0° bands).
// §T.5.2 (surface global latitude handling); p. 1458.
func adjustSurfaceCPRLatitudes(refLat float64, rlat0, rlat1 *float64) {
	fix := func(rlat *float64) {
		// poles/equator zero encodings and ±90° band flips vs ref.
		if *rlat == 0 {
			if refLat < -45 {
				*rlat = -90
			} else if refLat > 45 {
				*rlat = 90
			}
		} else if (*rlat - refLat) > 45 {
			*rlat -= 90
		}
	}
	fix(rlat0)
	fix(rlat1)
}

// adjustSurfaceLongitudeToRef — surface longitude: shift by multiples
// of 90° so the result is closest in sense to the reference longitude.
// §T.5.2 / §T.5.4; pp. 1458, 1464.
func adjustSurfaceLongitudeToRef(refLon, rlon float64) float64 {
	r := rlon + math.Floor((refLon-rlon+45)/90)*90
	r -= math.Floor((r+180)/360) * 360
	return r
}

// calcGlobal — global longitude from paired lon0/lon1 fractions
// and recovered latitudes rlat0/rlat1; t0 selects whether even or odd CPR is “latest”.
// §T.5.1 / §T.5.2; pp. 1451–1458 (see also §T.5.4 for surface local tie-breaks).
func calcGlobal(t0 bool, lon0, lon1, rlat0, rlat1 float64, isAirborne bool, referenceLat *float64, referenceLon *float64) []float64 {

	var nl, ni, dlon, lonc float64

	coord := make([]float64, 2)

	if t0 { //nolint:nestif // even CPR is latest — decoded lat is rlat0.
		coord[0] = rlat0

		// NL = number of longitude zones at this latitude (even subframe).
		nl = float64(cprNL(rlat0))

		// Ni = NL for even format (minimum 1).
		if nl <= 1 {
			ni = 1
		} else {
			ni = nl
		}

		// Δ_lon = 360°/Ni airborne, 90°/Ni surface.
		if isAirborne {
			dlon = 360.0 / ni
		} else {
			dlon = 90.0 / ni
		}

		lonc = lon0
	} else { // odd CPR is latest — decoded lat is rlat1.
		coord[0] = rlat1
		nl = float64(cprNL(rlat1))

		// odd format uses Ni = NL − 1 (clamped to at least 1).
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

	// longitude index m from paired lon fractions; lonc is the active subframe’s lon CPR.
	m := math.Round(((lon0 * (nl - 1)) - (lon1 * nl)))
	coord[1] = dlon * (math.Mod(m, ni) + lonc)
	if coord[1] >= 180 {
		coord[1] -= 360
	}

	// Surface global longitude is ambiguous in 90° steps until a reference
	// fixes the lane (same MOPS surface material as adjustSurfaceLongitudeToRef).
	// With both ref lon and ref lat, apply that shift once. If only ref lat is
	// set, the first branch is skipped and latitude may still be disambiguated
	// in 90° bands below (longitude enumeration lived here historically but was
	// redundant with adjustSurfaceLongitudeToRef and unreachable once added).
	if !isAirborne && referenceLon != nil && referenceLat != nil {
		coord[1] = adjustSurfaceLongitudeToRef(*referenceLon, coord[1])
	} else if !isAirborne {
		// ±90° latitude band candidates vs reference when ref lat alone may resolve band.
		if referenceLat != nil {
			candidatesLat := []float64{}
			for delta := -180.0; delta <= 180.0; delta += 90.0 {
				cand := coord[0] + delta
				if cand < -90 {
					cand = -90
				} else if cand > 90 {
					cand = 90
				}
				candidatesLat = append(candidatesLat, cand)
			}
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

// mod — MOD (always-non-negative remainder) for CPR indices.
// Used in §T.5 / local decode; pp. 1459–1464.
func mod(a float64, b float64) float64 {
	return a - (b * math.Floor(a/b))
}

// nlTbl holds NL(lat) latitude zone count breakpoints φᵢ (degrees), tabulated
// per §T.6 (same construction as the sample Go generator in git history).
// §T.6 NL function / transition latitudes; pp. 1464, 1480.
//
//	NL from 59 down: acos(sqrt((1-cos π/30)/(1-cos 2π/NL))) in degrees.
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

// cprNL — NL(φ): number of longitude zones at |latitude|, from the φᵢ table.
// §T.6; pp. 1464, 1480.
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
