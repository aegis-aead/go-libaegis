package aegis128l

import (
	"crypto/rand"
	"fmt"

	"github.com/aegis-aead/go-libaegis/common"
)

func Example() {
	if !common.Available {
		return
	}
	key := make([]byte, KeySize)
	rand.Read(key)
	aead, err := New(key, 16)
	if err != nil {
		panic(err)
	}

	nonce := make([]byte, aead.NonceSize())
	rand.Read(nonce)

	ciphertext := aead.Seal(nil, nonce, []byte("hello, world!"), nil)

	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err)
	}

	fmt.Println(string(plaintext))
	// Output: hello, world!
}
