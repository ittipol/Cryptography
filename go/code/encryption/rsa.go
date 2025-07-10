package encryption

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
)

func GenRsaKey() (privateKey *rsa.PrivateKey, publicKey rsa.PublicKey) {

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	// The public key is a part of the *rsa.PrivateKey struct
	publicKey = privateKey.PublicKey

	// fmt.Printf("Private Key: %v | Public Key: %v \n", privateKey, publicKey)

	return privateKey, publicKey
}

func Encryption(plainText string, publicKey rsa.PublicKey) []byte {
	encryptedBytes, err := rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		&publicKey,
		[]byte(plainText),
		nil)
	if err != nil {
		panic(err)
	}

	fmt.Println("encrypted bytes: ", encryptedBytes)
	// fmt.Println("encrypted string: ", string(encryptedBytes))

	return encryptedBytes
}

func Decryption(encryptedBytes []byte, privateKey *rsa.PrivateKey, publicKey rsa.PublicKey) {
	fmt.Printf("Private Key: %v | Public Key: %v \n", privateKey, publicKey)
	decryptedBytes, err := privateKey.Decrypt(nil, encryptedBytes, &rsa.OAEPOptions{Hash: crypto.SHA256})
	if err != nil {
		panic(err)
	}

	// We get back the original information in the form of bytes, which we
	// the cast to a string and print
	fmt.Println("decrypted message: ", string(decryptedBytes))
}

func Signing(privateKey *rsa.PrivateKey) (signature []byte, msgHashSum []byte) {
	msg := []byte("verifiable message")

	// Before signing, we need to hash our message
	// The hash is what we actually sign
	msgHash := sha256.New()
	_, err := msgHash.Write(msg)
	if err != nil {
		panic(err)
	}
	msgHashSum = msgHash.Sum(nil)

	signature, err = rsa.SignPSS(rand.Reader, privateKey, crypto.SHA256, msgHashSum, nil)
	if err != nil {
		return nil, nil
	}

	return signature, msgHashSum
}

func Verification(signature []byte, msgHashSum []byte, publicKey rsa.PublicKey) bool {
	err := rsa.VerifyPSS(&publicKey, crypto.SHA256, msgHashSum, signature, nil)
	if err != nil {
		fmt.Println("could not verify signature: ", err)
		return false
	}
	// If we don't get any error from the `VerifyPSS` method, that means our
	// signature is valid
	fmt.Println("signature verified")

	return true
}
