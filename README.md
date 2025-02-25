# go-libaegis

[![Go Reference](https://pkg.go.dev/badge/github.com/jedisct1/go-libaegis.svg)](https://pkg.go.dev/github.com/jedisct1/go-libaegis)
[![License](https://img.shields.io/github/license/jedisct1/go-libaegis)](https://github.com/jedisct1/go-libaegis/blob/main/LICENSE)

A Go binding for [libaegis](https://github.com/jedisct1/libaegis), implementing [the AEGIS family](https://datatracker.ietf.org/doc/draft-irtf-cfrg-aegis-aead/) of modern authenticated encryption algorithms designed for high performance and security.

## Features

- Provides a Go wrapper around `libaegis` for seamless integration.
- Implements AEGIS-128L, AEGIS-128X, AEGIS-256 and AEGIS-256X.
- Optimized for modern CPUs with hardware acceleration.
- Lightweight and easy to use within Go applications.

## Installation

To install `go-libaegis`, use:

```sh
go get github.com/jedisct1/go-libaegis
```

## Usage

```go
package main

import (
    "crypto/rand"
    "fmt"
    // other options:
    // aegis128l, aegis128x4, aegis256, aegis256x2, aegis256x4    
    "github.com/jedisct1/go-libaegis/aegis128x2"
)

func main() {
    key := make([]byte, aegis128x2.KeySize)
    rand.Read(key)

    nonce := make([]byte, aegis128x2.NonceSize)
    rand.Read(nonce)

    plaintext := []byte("Hello, world!")
    associatedData := []byte("metadata")

    // tag size can be 16 or 32 bytes
    aead, err := aegis128x2.New(key, 16)
    if err != nil {
        panic(err)
    }

    ciphertext := aead.Seal(nil, nonce, plaintext, associatedData)

    decrypted, err := aead.Open(nil, nonce, ciphertext, associatedData)
    if err != nil {
        panic(err)
    }

    fmt.Println("Decrypted message:", string(decrypted))
}
```

## Requirements

- Go 1.16+
- A C toolchain

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Feel free to open an issue or submit a pull request.

## Security Notice

Always ensure that you use randomly generated keys and unique nonces when using authenticated encryption to maintain security.