package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
)

func EncryptMessage(key []byte, message string) (string, error) {
	byteMsg := []byte(message)

	fmt.Printf("byteMsg: %v \n", byteMsg)

	block, err := aes.NewCipher(key)

	// fmt.Printf("block: %v \n", block)

	if err != nil {
		return "", fmt.Errorf("could not create new cipher: %v", err)
	}

	fmt.Printf("aes.BlockSize: %v \n", aes.BlockSize)

	cipherText := make([]byte, aes.BlockSize+len(byteMsg))
	iv := cipherText[:aes.BlockSize]
	fmt.Printf("iv#1: %v \n", iv)

	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return "", fmt.Errorf("could not encrypt: %v", err)
	}

	fmt.Printf("iv#2: %v \n", iv)
	fmt.Printf("cipherText#1: %v \n", cipherText)

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(cipherText[aes.BlockSize:], byteMsg)

	fmt.Printf("cipherText#2: %v \n", cipherText)

	return base64.StdEncoding.EncodeToString(cipherText), nil
}

func DecryptMessage(key []byte, message string) (string, error) {
	cipherText, err := base64.StdEncoding.DecodeString(message)
	if err != nil {
		return "", fmt.Errorf("could not base64 decode: %v", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("could not create new cipher: %v", err)
	}

	if len(cipherText) < aes.BlockSize {
		return "", fmt.Errorf("invalid ciphertext block size")
	}

	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(cipherText, cipherText)

	return string(cipherText), nil
}
