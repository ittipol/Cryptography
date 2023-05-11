package encryption

import (
	"crypto/aes"
	"encoding/hex"
	"fmt"
)

func EncryptAES(key []byte, plaintext string) string {

	c, err := aes.NewCipher(key)
	// CheckError(err)

	if err != nil {
		fmt.Println("EncryptAES Error")
		// return ""
		panic(err)
	}

	out := make([]byte, len(plaintext))

	c.Encrypt(out, []byte(plaintext))

	return hex.EncodeToString(out)
}

func DecryptAES(key []byte, ct string) {
	ciphertext, _ := hex.DecodeString(ct)

	c, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println("DecryptAES Error")
		panic(err)
	}

	pt := make([]byte, len(ciphertext))
	c.Decrypt(pt, ciphertext)

	s := string(pt[:])
	fmt.Println("DECRYPTED:", s)
}
