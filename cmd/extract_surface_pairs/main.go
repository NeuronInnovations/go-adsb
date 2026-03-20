package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	"github.com/NeuronInnovations/go-adsb/adsb"
)

type recLine struct {
	SensorLat float64 `json:"sensor_lat"`
	SensorLon float64 `json:"sensor_lon"`
	RawModeS  string  `json:"raw_mode_s"`
}

func main() {
	path := "recordings/rec.jsonl"
	if len(os.Args) > 1 {
		path = os.Args[1]
	}
	f, err := os.Open(path)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	dec := json.NewDecoder(f)
	type last struct {
		c      *adsb.CPR
		refLat float64
		refLon float64
	}
	lasts := make(map[uint64]last)

	for dec.More() {
		var line recLine
		if err := dec.Decode(&line); err != nil {
			break
		}
		raw, err := base64.StdEncoding.DecodeString(line.RawModeS)
		if err != nil || len(raw) < 14 {
			continue
		}
		var msg adsb.Message
		if err := msg.UnmarshalBinary(raw); err != nil {
			continue
		}
		icao, _ := msg.ICAO()
		cpr, air, err := msg.CPR()
		if err != nil || air {
			continue
		}
		prev, ok := lasts[icao]
		cp := *cpr
		if !ok {
			lasts[icao] = last{c: &cp, refLat: line.SensorLat, refLon: line.SensorLon}
			continue
		}
		if prev.c.F == cpr.F {
			lasts[icao] = last{c: &cp, refLat: line.SensorLat, refLon: line.SensorLon}
			continue
		}
		var even, odd *adsb.CPR
		if prev.c.F == 0 {
			e1, o1 := *prev.c, cp
			even, odd = &e1, &o1
		} else {
			e1, o1 := cp, *prev.c
			even, odd = &e1, &o1
		}
		refLat := (prev.refLat + line.SensorLat) / 2
		refLon := (prev.refLon + line.SensorLon) / 2
		fmt.Printf("// icao=%06X sensor approx %.5f,%.5f\n", icao, refLat, refLon)
		pos, err := adsb.DecodeGlobalPosition(even, odd, false, &refLat, &refLon)
		if err != nil {
			fmt.Printf("// DecodeGlobalPosition err: %v\n", err)
		} else {
			fmt.Printf("// decoded lat=%.5f lon=%.5f\n", pos[0], pos[1])
		}
		fmt.Printf("even: &adsb.CPR{Nb:17, T:%d, F:%d, Lat:%d, Lon:%d},\n", even.T, even.F, even.Lat, even.Lon)
		fmt.Printf("odd:  &adsb.CPR{Nb:17, T:%d, F:%d, Lat:%d, Lon:%d},\n", odd.T, odd.F, odd.Lat, odd.Lon)
		fmt.Printf("refLat, refLon := %.8f, %.8f\n", refLat, refLon)
		fmt.Println("---")
		lasts[icao] = last{c: &cp, refLat: line.SensorLat, refLon: line.SensorLon}
	}
}
