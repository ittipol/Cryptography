package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"log"
)

func main() {

	clientCurve := ecdh.P256()
	clientPrivKey, err := clientCurve.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}
	clientPubKey := clientPrivKey.PublicKey()

	serverCurve := ecdh.P256()
	serverPrivKey, err := serverCurve.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}
	serverPubKey := serverPrivKey.PublicKey()

	// =================================================

	clientSecret, err := clientPrivKey.ECDH(serverPubKey)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}
	serverSecret, err := serverPrivKey.ECDH(clientPubKey)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}
	if !bytes.Equal(clientSecret, serverSecret) {
		log.Fatalf("The secrets do not match")
	}
	log.Printf("The secrets match")
	println(len(clientSecret))
	println(len(serverSecret))

	fmt.Println(clientSecret)
	fmt.Println(serverSecret)

	fmt.Printf("%x\n", clientSecret)
	fmt.Printf("%x\n", serverSecret)

	fmt.Printf("\n")

	// =================================================

	plaintext := []byte("This is a secret message")

	// AES
	// encryptedData := aesEncrypt(plaintext, clientSecret)
	// message := aesDecrypt(encryptedData, serverSecret)

	// AES/GCM mode
	base64CipherText := aesGcmModeEncrypt(plaintext, clientSecret)
	message := aesGcmModeDecrypt(base64CipherText, serverSecret)

	fmt.Println(message)
}

func aesEncrypt(plaintext []byte, key []byte) string {

	// keySize = 256 bit, 32 bytes
	// BlockSize = 128 bit, 16 bytes

	block, err := aes.NewCipher(key)

	if err != nil {
		log.Fatalf("could not create new cipher: %v", err)
	}

	fmt.Printf("aes.BlockSize: %v \n", aes.BlockSize)

	cipherText := make([]byte, aes.BlockSize+len(plaintext))
	iv := cipherText[:aes.BlockSize]
	fmt.Printf("iv#1: %v \n", iv)

	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		log.Fatalf("could not encrypt: %v", err)
	}

	fmt.Printf("iv#2: %v \n", iv)
	fmt.Printf("cipherText#1: %v \n", cipherText)

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(cipherText[aes.BlockSize:], plaintext)

	fmt.Printf("cipherText#2: %v \n", cipherText)

	return base64.StdEncoding.EncodeToString(cipherText)
}

func aesDecrypt(encryptedData string, key []byte) string {
	cipherText, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		log.Fatalf("could not base64 decode: %v", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatalf("could not create new cipher: %v", err)
	}

	if len(cipherText) < aes.BlockSize {
		log.Fatalf("invalid ciphertext block size")
	}

	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(cipherText, cipherText)

	return string(cipherText)
}

func aesGcmModeEncrypt(plaintext []byte, key []byte) string {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}

	fmt.Printf("aes.BlockSize: %v \n", aes.BlockSize)
	fmt.Printf("gcm.NonceSize: %v \n", gcm.NonceSize())

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err)
	}

	cipherText := gcm.Seal(nonce, nonce, plaintext, nil)

	fmt.Printf("cipherText: %v \n", cipherText)

	fmt.Printf("Ciphertext (Hex): %x\n", cipherText)

	return base64.StdEncoding.EncodeToString(cipherText)
}

func aesGcmModeDecrypt(base64CipherText string, key []byte) string {

	cipherText, err := base64.StdEncoding.DecodeString(base64CipherText)
	if err != nil {
		log.Fatalf("could not base64 decode: %v", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatalf(err.Error())
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Fatalf(err.Error())
	}

	decryptedNonce := cipherText[:gcm.NonceSize()]
	encryptedData := cipherText[gcm.NonceSize():]

	decryptedPlaintext, err := gcm.Open(nil, decryptedNonce, encryptedData, nil)
	if err != nil {
		log.Fatalf(err.Error())
	}

	fmt.Printf("Decrypted Plaintext: %s\n", decryptedPlaintext)

	return string(decryptedPlaintext)
}

func randomByte() []byte {
	key := make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, key)
	if err != nil {
		log.Fatalf(err.Error())
	}

	return key
}
