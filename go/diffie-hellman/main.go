package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"math/big"

	"github.com/fxtlabs/primes"
)

func main() {

	// Gen client key pair
	clientPrivKey, clientPubKey, err := generateKeyPair()
	if err != nil {
		panic(err)
	}
	fmt.Printf("clientPrivKey ---------> [%x]\n", clientPrivKey.Bytes())
	fmt.Printf("clientPubKey ---------> [%x]\n\n", clientPubKey.Bytes())

	// Gen server key pair
	serverPrivKey, serverPubKey, err := generateKeyPair()
	if err != nil {
		panic(err)
	}
	fmt.Printf("serverPrivKey ---------> [%x]\n", serverPrivKey.Bytes())
	fmt.Printf("serverPubKey ---------> [%x]\n", serverPubKey.Bytes())

	fmt.Println()

	// =================================================================================

	// clientPrivateKeyHex := "467807F7DF955D00C6B5F56E157657312933793D7E4D2262D0D05A2C89B31090" // Gen From CS
	// serverPrivateKeyHex := "B1F53D13D670338594E8158817B371DB50FF29E33CD0BEA60DFD6CED82C4AE34" // Gen From CS

	clientPrivateKeyHex := "c3ef6732ef04061b5e9d7b1fe7c80ab3b75be2b82522ee5c8b7bf0f84a08f2d8" // Gen From Go
	serverPrivateKeyHex := "7cea6b94017e734867b9e5571ecd011a4a40d73f48c6f99f9ccc46633ad4dd75" // Gen From Go

	clientPrivateKeyByte, err := hex.DecodeString(clientPrivateKeyHex)
	if err != nil {
		log.Fatalf("Error decoding hex string: %v", err)
		panic(err)
	}

	serverPrivateKeyByte, err := hex.DecodeString(serverPrivateKeyHex)
	if err != nil {
		log.Fatalf("Error decoding hex string: %v", err)
		panic(err)
	}

	curve := ecdh.P256()

	clientPrivateKey, err := curve.NewPrivateKey(clientPrivateKeyByte)
	if err != nil {
		log.Fatalf("Error: %v", err)
		panic(err)
	}
	clientPublicKey := clientPrivateKey.PublicKey()

	serverPrivateKey, err := curve.NewPrivateKey(serverPrivateKeyByte)
	if err != nil {
		log.Fatalf("Error: %v", err)
		panic(err)
	}
	serverPublicKey := serverPrivateKey.PublicKey()

	clientSecretKey := deriveSharedSecret(clientPrivateKey, serverPublicKey)
	serverSecretKey := deriveSharedSecret(serverPrivateKey, clientPublicKey)

	clientSecretKeyBase64 := base64.StdEncoding.EncodeToString(clientSecretKey)
	serverSecretKeyBase64 := base64.StdEncoding.EncodeToString(serverSecretKey)

	fmt.Printf("clientSecretKeyBase64: %s\n", clientSecretKeyBase64)
	fmt.Printf("serverSecretKeyBase64: %s\n", serverSecretKeyBase64)
}

func main2() {

	fmt.Println("\n\nPrime Number")

	// gen prime
	primeNumber := generatePrime()

	fmt.Println(primeNumber)
	fmt.Println(len(primeNumber.String()))
	fmt.Println(primeNumber.BitLen())

	fmt.Println("BigInt as int64:", primeNumber.Int64())

	if primes.IsPrime(int(primeNumber.Int64())) {
		fmt.Printf("%d is prime\n", primeNumber)
	} else {
		fmt.Printf("%d is composite\n", primeNumber)
	}

	// =================================================

	fmt.Println("\n\nECDH")

	// Gen client key pair
	clientPrivKey, clientPubKey, err := generateKeyPair()
	if err != nil {
		panic(err)
	}

	// Gen server key pair
	serverPrivKey, serverPubKey, err := generateKeyPair()
	if err != nil {
		panic(err)
	}

	// Compute shared key
	clientSecretKey := deriveSharedSecret(clientPrivKey, serverPubKey)
	serverSecretKey := deriveSharedSecret(serverPrivKey, clientPubKey)

	if !bytes.Equal(clientSecretKey, serverSecretKey) {
		log.Fatalf("The secrets do not match")
	} else {
		log.Printf("The secrets match")
	}

	println(len(clientSecretKey))
	println(len(serverSecretKey))

	fmt.Println(clientSecretKey)
	fmt.Println(serverSecretKey)

	fmt.Printf("%x\n", clientSecretKey)
	fmt.Printf("%x\n", serverSecretKey)

	// =================================================

	fmt.Println("\n\nAES")

	plaintext := []byte("This is a secret message")

	// AES
	// encryptedData := aesEncrypt(plaintext, clientSecretKey)
	// message := aesDecrypt(encryptedData, serverSecretKey)

	// AES/GCM mode
	base64CipherText := aesGcmModeEncrypt(plaintext, clientSecretKey)
	message := aesGcmModeDecrypt(base64CipherText, serverSecretKey)

	fmt.Println(message)
}

func generateKeyPair() (privKey *ecdh.PrivateKey, pubKey *ecdh.PublicKey, err error) {

	curve := ecdh.P256() // curves secp256r1
	privKey, err = curve.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("Error: %v", err)
		return
	}

	pubKey = privKey.PublicKey()

	// fmt.Printf("privKey length: [%v]\n", len(privKey.Bytes()))
	// fmt.Printf("pubKey length: [%v]\n", len(pubKey.Bytes()))

	return
}

func deriveSharedSecret(myPrivKey *ecdh.PrivateKey, otherPartyPublicKey *ecdh.PublicKey) []byte {

	secretKey, err := myPrivKey.ECDH(otherPartyPublicKey)
	if err != nil {
		log.Fatalf("Error: %v", err)
		return make([]byte, 0)
		// return []byte{}
	}

	return secretKey
}

func aesEncrypt(plaintext []byte, key []byte) string {

	// keySize = 256 bit, 32 bytes
	// BlockSize = 128 bit, 16 bytes

	block, err := aes.NewCipher(key)

	if err != nil {
		log.Fatalf("could not create new cipher: %v", err)
		return ""
	}

	fmt.Printf("aes.BlockSize: %v \n", aes.BlockSize)

	cipherText := make([]byte, aes.BlockSize+len(plaintext))
	iv := cipherText[:aes.BlockSize]
	fmt.Printf("iv#1: %v \n", iv)

	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		log.Fatalf("could not encrypt: %v", err)
		return ""
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
		return ""
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatalf("could not create new cipher: %v", err)
		return ""
	}

	if len(cipherText) < aes.BlockSize {
		log.Fatalf("invalid ciphertext block size")
		return ""
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
		log.Fatalf(err.Error())
		return ""
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Fatalf(err.Error())
		return ""
	}

	fmt.Printf("aes.BlockSize: %v \n", aes.BlockSize)
	fmt.Printf("gcm.NonceSize: %v \n", gcm.NonceSize())

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		log.Fatalf(err.Error())
		return ""
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
		return ""
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatalf(err.Error())
		return ""
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Fatalf(err.Error())
		return ""
	}

	decryptedNonce := cipherText[:gcm.NonceSize()]
	encryptedData := cipherText[gcm.NonceSize():]

	decryptedPlaintext, err := gcm.Open(nil, decryptedNonce, encryptedData, nil)
	if err != nil {
		log.Fatalf(err.Error())
		return ""
	}

	fmt.Printf("Decrypted Plaintext: %s\n", decryptedPlaintext)

	return string(decryptedPlaintext)
}

func randomByte() []byte {
	key := make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, key)
	if err != nil {
		log.Fatalf(err.Error())
		return make([]byte, 0)
		// return []byte{}
	}

	return key
}

func generatePrime() *big.Int {
	prime, _ := rand.Prime(rand.Reader, 256)
	return prime
}
