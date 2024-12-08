package encryption

import (
	"encoding/base64"
)

func EncodeBase64(encryptedBytes []byte) string {
	dst := make([]byte, base64.StdEncoding.EncodedLen(len(encryptedBytes)))
	base64.StdEncoding.Encode(dst, encryptedBytes)

	return string(dst)
}

func DecodeBase64(strBase64 string) []byte {
	data, err := base64.StdEncoding.DecodeString(strBase64)
	if err != nil {
		return nil
	}

	return data
}
