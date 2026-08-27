package secrets

import (
	"errors"

	"golang.org/x/crypto/blowfish"
)

const bcryptAlphabet = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

var bcryptMagic = []byte("OrpheanBeholderScryDoubt")

// deterministicBcrypt derives a stable bcrypt value from secret seed material.
// The caller owns both inputs; neither is retained.
func deterministicBcrypt(password, salt []byte, cost uint8) ([]byte, error) {
	if len(password) == 0 || len(password) > 72 ||
		len(salt) != 16 || cost < 4 || cost > 31 {
		return nil, errors.New("invalid deterministic bcrypt input")
	}
	encodedSalt := bcryptBase64(salt)
	decodedSalt := append([]byte(nil), salt...)
	key := append(append([]byte(nil), password...), 0)
	cipher, err := blowfish.NewSaltedCipher(key, decodedSalt)
	if err != nil {
		clear(key)
		clear(decodedSalt)
		return nil, err
	}
	for round := uint64(0); round < uint64(1)<<cost; round++ {
		blowfish.ExpandKey(key, cipher)
		blowfish.ExpandKey(decodedSalt, cipher)
	}
	clear(key)
	clear(decodedSalt)

	hash := append([]byte(nil), bcryptMagic...)
	for offset := 0; offset < len(hash); offset += blowfish.BlockSize {
		for round := 0; round < 64; round++ {
			cipher.Encrypt(hash[offset:offset+blowfish.BlockSize], hash[offset:offset+blowfish.BlockSize])
		}
	}
	encodedHash := bcryptBase64(hash[:23])
	clear(hash)
	result := make([]byte, 0, 60)
	result = append(result, '$', '2', 'y', '$', '0'+cost/10, '0'+cost%10, '$')
	result = append(result, encodedSalt...)
	result = append(result, encodedHash...)
	clear(encodedSalt)
	clear(encodedHash)
	return result, nil
}

func bcryptBase64(source []byte) []byte {
	result := make([]byte, 0, (len(source)*4+2)/3)
	for offset := 0; offset < len(source); {
		first := source[offset]
		offset++
		result = append(result, bcryptAlphabet[first>>2])
		first = (first & 0x03) << 4
		if offset >= len(source) {
			result = append(result, bcryptAlphabet[first])
			break
		}
		second := source[offset]
		offset++
		first |= second >> 4
		result = append(result, bcryptAlphabet[first])
		first = (second & 0x0f) << 2
		if offset >= len(source) {
			result = append(result, bcryptAlphabet[first])
			break
		}
		second = source[offset]
		offset++
		first |= second >> 6
		result = append(result, bcryptAlphabet[first], bcryptAlphabet[second&0x3f])
	}
	return result
}
