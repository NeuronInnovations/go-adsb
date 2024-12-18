# Overview
<!--
[![PkgGoDev](https://pkg.go.dev/badge/kreklow.us/go/go-adsb)](https://pkg.go.dev/kreklow.us/go/go-adsb)
![GitHub](https://img.shields.io/github/license/cjkreklow/go-adsb.svg)
![GitHub tag (latest SemVer)](https://img.shields.io/github/tag/cjkreklow/go-adsb.svg)
[![Build Status](https://www.travis-ci.org/cjkreklow/go-adsb.svg?branch=main)](https://www.travis-ci.org/cjkreklow/go-adsb)
[![codecov](https://codecov.io/gh/cjkreklow/go-adsb/branch/main/graph/badge.svg)](https://codecov.io/gh/cjkreklow/go-adsb)
-->

`go-adsb` is a Go module that includes packages for working with ADS-B and
Mode S aircraft transponder data.

## beast
The `beast` package is a low-level library for handling data in [Mode S
Beast format](https://wiki.jetvision.de/wiki/Mode-S_Beast:Data_Output_Formats),
as provided by common software such as
[dump1090](https://github.com/flightaware/dump1090).
`Decoder` provides a consumer for an `io.Reader` such as
[net.Conn](https://golang.org/pkg/net/#Conn), which will then parse a Beast
stream into individual frames. These frames are passed to a
[BinaryUnmarshaler](https://golang.org/pkg/encoding/#BinaryUnmarshaler) via
`Decode`. The provided `Frame` is a BinaryUnmarshaler that provides methods
to extract the Beast data such as timestamp and signal level, as well as the
enclosed Mode S or ADS-B data.

## adsb
The `adsb` package is a library for decoding Mode S and ADS-B transponder
messages. `RawMessage` is a low-level wrapper that provides access to
arbitrary bit sequences and named message fields. `Message` is a
higher-level abstraction that provides functions to retrieve decoded values
such as altitude and callsign from the encoded data.

Both `Message` and `RawMessage` designed to accept a `beast.Frame` to
provide a complete solution for decoding usable values from an incoming data
stream.

## adsbtype
The `adsbtype` package provides constants for Mode S and ADS-B data fields
that have fixed values. Converting the value to a provided data type allows
the text description of the value to be returned via the `%s` operator in
Printf-style operations.

# Usage
See the documentation on [pkg.go.dev](https://pkg.go.dev/kreklow.us/go/go-adsb)
for import paths and usage information.

# Attribution

This project is a fork of [bluvec's repository](https://github.com/bluvec/go-adsb), which itself was forked from the original project by [Collin Kreklow](https://github.com/cjkreklow/go-adsb).

The original project by [Collin Kreklow](https://github.com/cjkreklow/go-adsb) is licensed under the [MIT License](https://opensource.org/licenses/MIT).

Credit goes to both [Collin Kreklow](https://github.com/cjkreklow/go-adsb) and [bluvec](https://github.com/bluvec/go-adsb) for their contributions to this project.

This fork, maintained by Neuron Innovations, aims to build upon their excellent work.

