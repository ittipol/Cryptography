package main

import (
	"crypto/rand"
	"fmt"
	"go-encryption/encryption"
	"math/big"
)

const (
	keyList string = "abcdefghijklmnopqrstuvwxyzABCDEFHFGHIJKLMNOPQRSTUVWXYZ1234567890"
)

func main() {

	key := keyGen()

	println("KEY: " + key)
	// cipher key
	// key := "C&F)J@NcRfUjXn2r5u8x/A?D*G-KaPd3"

	// count := utf8.RuneCountInString("oxQSX9iBdPe6mUk8iunwdYLG0a+PD8MngMYz0lofyfM=")

	cipherText, _ := encryption.EncryptMessage([]byte(key), "This is message")

	println(cipherText)

	decodedStr, _ := encryption.DecryptMessage([]byte(key), cipherText)

	println(decodedStr)

	// plaintext
	// pt := "This is a secret"

	// cipherText := encryption.EncryptAES([]byte(key), pt)

	// fmt.Println(cipherText)

	// encryption.DecryptAES([]byte(key), cipherText)

}

func keyGen() (keyString string) {

	strLen := 32

	for key := 1; key <= strLen; key++ {
		res, _ := rand.Int(rand.Reader, big.NewInt(64))
		keyGen := keyList[res.Int64()]
		stringGen := fmt.Sprintf("%c", keyGen)
		// f.Write([]byte(stringGen))
		// println(stringGen)
		keyString += stringGen
	}

	return
}
