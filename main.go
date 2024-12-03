package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"go-encryption/encryption"
	"math/big"
	"unicode/utf8"
)

type product struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

const (
	keyList string = "abcdefghijklmnopqrstuvwxyzABCDEFHFGHIJKLMNOPQRSTUVWXYZ1234567890"
)

func main() {

	key := keyGen()
	// key2 := keyGen()

	println("KEY: " + key)
	// cipher key
	// key := "C&F)J@NcRfUjXn2r5u8x/A?D*G-KaPd3"

	text := "ทดสอบนับตัวอักษร"

	count := utf8.RuneCountInString(text)
	fmt.Printf("Count: %v [%s]\n", count, text)

	data := product{
		ID:   1,
		Name: "TEST",
	}

	json, _ := json.Marshal(data)

	cipherText, _ := encryption.EncryptMessage([]byte(key), string(json))
	_ = cipherText
	// println(err.Error())

	fmt.Printf("cipherText[Base64]: %s\n", cipherText)

	decodedStr, err := encryption.DecryptMessage([]byte(key), cipherText)

	if err != nil {
		panic(err.Error())
	}

	println("Result: " + decodedStr)

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
