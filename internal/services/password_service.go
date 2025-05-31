package services

import (
	"errors"
	"password-manager/internal/crypto"
	"password-manager/internal/database"
	"password-manager/internal/models"
)

type PasswordService struct {
	db        *database.DB
	encryptor *crypto.Encryptor
}

// NewPasswordService creates a new password service
func NewPasswordService(db *database.DB, encryptor *crypto.Encryptor) *PasswordService {
	return &PasswordService{
		db:        db,
		encryptor: encryptor,
	}
}

// CreatePassword creates a new password entry
func (ps *PasswordService) CreatePassword(req *models.PasswordRequest) error {
	if req.Service == "" || req.Username == "" || req.Password == "" {
		return errors.New("service, username, and password are required")
	}

	// Check if password already exists
	existing, _ := ps.db.GetPassword(req.Service, req.Username)
	if existing != nil {
		return errors.New("password entry already exists for this service and username")
	}

	// Encrypt the password
	encryptedPassword, err := ps.encryptor.Encrypt(req.Password)
	if err != nil {
		return err
	}

	password := &models.Password{
		Service:  req.Service,
		Username: req.Username,
		Password: encryptedPassword,
		URL:      req.URL,
		Notes:    req.Notes,
	}

	return ps.db.CreatePassword(password)
}

// GetPassword retrieves and decrypts a password
func (ps *PasswordService) GetPassword(service, username string) (*models.Password, error) {
	password, err := ps.db.GetPassword(service, username)
	if err != nil {
		return nil, err
	}

	// Decrypt the password
	decryptedPassword, err := ps.encryptor.Decrypt(password.Password)
	if err != nil {
		return nil, err
	}

	password.Password = decryptedPassword
	return password, nil
}

// ListPasswords retrieves all passwords (without decrypting them for security)
func (ps *PasswordService) ListPasswords() ([]*models.Password, error) {
	passwords, err := ps.db.ListPasswords()
	if err != nil {
		return nil, err
	}

	// Don't decrypt passwords in list view for security
	for _, password := range passwords {
		password.Password = "••••••••"
	}

	return passwords, nil
}

// SearchPasswords searches for passwords
func (ps *PasswordService) SearchPasswords(searchTerm string) ([]*models.Password, error) {
	passwords, err := ps.db.SearchPasswords(searchTerm)
	if err != nil {
		return nil, err
	}

	// Don't decrypt passwords in search results for security
	for _, password := range passwords {
		password.Password = "••••••••"
	}

	return passwords, nil
}

// UpdatePassword updates an existing password
func (ps *PasswordService) UpdatePassword(service, username string, req *models.PasswordRequest) error {
	// Check if password exists
	_, err := ps.db.GetPassword(service, username)
	if err != nil {
		return errors.New("password entry not found")
	}

	// Encrypt the new password
	encryptedPassword, err := ps.encryptor.Encrypt(req.Password)
	if err != nil {
		return err
	}

	updates := &models.Password{
		Password: encryptedPassword,
		URL:      req.URL,
		Notes:    req.Notes,
	}

	return ps.db.UpdatePassword(service, username, updates)
}

// DeletePassword deletes a password entry
func (ps *PasswordService) DeletePassword(service, username string) error {
	return ps.db.DeletePassword(service, username)
}
