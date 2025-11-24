# go-libaegis

[![Go Reference](https://pkg.go.dev/badge/github.com/aegis-aead/go-libaegis.svg)](https://pkg.go.dev/github.com/aegis-aead/go-libaegis)
[![License](https://img.shields.io/github/license/aegis-aead/go-libaegis)](https://github.com/aegis-aead/go-libaegis/blob/main/LICENSE)

A Go binding for [libaegis](https://github.com/aegis-aead/libaegis), implementing [the AEGIS family](https://datatracker.ietf.org/doc/draft-irtf-cfrg-aegis-aead/) of modern authenticated encryption algorithms designed for high performance and security.

## Features

- Provides a Go wrapper around `libaegis` for seamless integration.
- Implements AEGIS-128L, AEGIS-128X, AEGIS-256 and AEGIS-256X.
- Supports both one-shot and incremental (streaming) encryption/decryption.
- Optimized for modern CPUs with hardware acceleration.
- Lightweight and easy to use within Go applications.

## Installation

To install `go-libaegis`, use:

```sh
go get github.com/aegis-aead/go-libaegis
```

## Usage

```go
package main

import (
    "crypto/rand"
    "fmt"
    // other options:
    // aegis128l, aegis128x4, aegis256, aegis256x2, aegis256x4    
    "github.com/aegis-aead/go-libaegis/aegis128x2"
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

### Incremental encryption/decryption

For large messages or streaming scenarios, use the incremental API to process data in chunks:

```go
package main

import (
    "crypto/rand"
    "fmt"
    "github.com/aegis-aead/go-libaegis/aegis128l"
)

func main() {
    key := make([]byte, aegis128l.KeySize)
    rand.Read(key)

    nonce := make([]byte, aegis128l.NonceSize)
    rand.Read(nonce)

    associatedData := []byte("metadata")
    tagLen := 16

    // Incremental encryption
    enc, err := aegis128l.NewEncrypter(key, nonce, associatedData, tagLen)
    if err != nil {
        panic(err)
    }

    // Encrypt data in chunks - ciphertext is output immediately
    ciphertext1 := enc.Encrypt([]byte("Hello, "))
    ciphertext2 := enc.Encrypt([]byte("world!"))
    tag := enc.Final()

    // Incremental decryption
    dec, err := aegis128l.NewDecrypter(key, nonce, associatedData, tagLen)
    if err != nil {
        panic(err)
    }

    // Decrypt chunks - but don't use plaintext until Final succeeds!
    plaintext1 := dec.Decrypt(ciphertext1)
    plaintext2 := dec.Decrypt(ciphertext2)

    // Verify authentication tag
    if err := dec.Final(tag); err != nil {
        // Authentication failed - discard all decrypted data
        panic("authentication failed")
    }

    // Now it's safe to use the plaintext
    fmt.Println("Decrypted:", string(plaintext1)+string(plaintext2))
}
```

The incremental API is interoperable with the one-shot API: `ciphertext || tag` from incremental encryption equals the output of `Seal()`.

## Requirements

- Go 1.19+
- A C toolchain

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Feel free to open an issue or submit a pull request.

## Security Notice

Always ensure that you use randomly generated keys and unique nonces when using authenticated encryption to maintain security.

### Alternatives in Go

- [`github.com/ericlagergren/aegis`](https://github.com/ericlagergren/aegis) implements AEGIS-128L and AEGIS-256 without the need for CGO.