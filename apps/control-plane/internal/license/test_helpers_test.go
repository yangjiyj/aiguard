package license

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
)

func marshalFile(file *File) (string, error) {
	data, err := json.Marshal(file)
	return string(data), err
}

func encodePublicKey(pub ed25519.PublicKey) string {
	return base64.StdEncoding.EncodeToString(pub)
}
