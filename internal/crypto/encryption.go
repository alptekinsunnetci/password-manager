package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"io"

	"password-manager/internal/database"

	"golang.org/x/crypto/pbkdf2"
)

type Encryptor struct {
	key []byte
	db  *database.DB
}

// HashPassword creates a hash of the master password
func HashPassword(password string) string {
	hash := sha256.Sum256([]byte(password))
	return base64.StdEncoding.EncodeToString(hash[:])
}

// NewEncryptor creates a new encryptor with the given master password
func NewEncryptor(masterPassword string, db *database.DB) (*Encryptor, error) {
	// Hash the master password
	passwordHash := HashPassword(masterPassword)

	// Check if this is the first run
	verified, err := db.VerifyMasterPassword(passwordHash)
	if err != nil {
		return nil, err
	}

	// If not verified and no master password exists, set it
	if !verified {
		var storedHash string
		err := db.Conn.QueryRow("SELECT password_hash FROM master_password ORDER BY id DESC LIMIT 1").Scan(&storedHash)
		if err == sql.ErrNoRows {
			// First run, set the master password
			if err := db.SetMasterPassword(passwordHash); err != nil {
				return nil, err
			}
		} else if err != nil {
			return nil, err
		} else {
			// Master password exists but doesn't match
			return nil, errors.New("incorrect master password")
		}
	}

	// Get salt from database
	saltStr, err := db.GetSalt()
	if err != nil {
		return nil, err
	}

	salt, err := base64.StdEncoding.DecodeString(saltStr)
	if err != nil {
		return nil, err
	}

	// Generate a key from the master password using PBKDF2
	key := pbkdf2.Key([]byte(masterPassword), salt, 100000, 32, sha256.New)

	return &Encryptor{
		key: key,
		db:  db,
	}, nil
}

// Encrypt encrypts the given plaintext
func (e *Encryptor) Encrypt(plaintext string) (string, error) {
	block, err := aes.NewCipher(e.key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts the given ciphertext
func (e *Encryptor) Decrypt(ciphertext string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(e.key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", errors.New("ciphertext too short")
	}

	nonce := data[:nonceSize]
	ciphertextBytes := data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertextBytes, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}
