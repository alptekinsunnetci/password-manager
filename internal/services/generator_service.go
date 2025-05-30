package services

import (
    "crypto/rand"
    "math/big"
    "password-manager/internal/models"
    "strings"
)

type GeneratorService struct{}

// NewGeneratorService creates a new password generator service
func NewGeneratorService() *GeneratorService {
    return &GeneratorService{}
}

// GeneratePassword generates a password based on the given options
func (gs *GeneratorService) GeneratePassword(options *models.GeneratorOptions) (string, error) {
    if options.Length <= 0 {
        options.Length = 12 // Default length
    }

    charset := gs.buildCharset(options)
    if len(charset) == 0 {
        // Default to all character types if none selected
        options.IncludeUpper = true
        options.IncludeLower = true
        options.IncludeNumbers = true
        options.IncludeSymbols = true
        charset = gs.buildCharset(options)
    }

    password := make([]byte, options.Length)
    for i := range password {
        randomIndex, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
        if err != nil {
            return "", err
        }
        password[i] = charset[randomIndex.Int64()]
    }

    return string(password), nil
}

// buildCharset builds the character set based on options
func (gs *GeneratorService) buildCharset(options *models.GeneratorOptions) string {
    var charset strings.Builder

    if options.IncludeLower {
        if options.ExcludeSimilar {
            charset.WriteString("abcdefghjkmnpqrstuvwxyz") // Exclude i, l, o
        } else {
            charset.WriteString("abcdefghijklmnopqrstuvwxyz")
        }
    }

    if options.IncludeUpper {
        if options.ExcludeSimilar {
            charset.WriteString("ABCDEFGHJKMNPQRSTUVWXYZ") // Exclude I, L, O
        } else {
            charset.WriteString("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
        }
    }

    if options.IncludeNumbers {
        if options.ExcludeSimilar {
            charset.WriteString("23456789") // Exclude 0, 1
        } else {
            charset.WriteString("0123456789")
        }
    }

    if options.IncludeSymbols {
        if options.ExcludeSimilar {
            charset.WriteString("!@#$%^&*-_=+[]{}:;") // Exclude similar looking symbols
        } else {
            charset.WriteString("!@#$%^&*()_+-=[]{}|;:,.<>?")
        }
    }

    return charset.String()
}

// ValidatePasswordStrength validates password strength
func (gs *GeneratorService) ValidatePasswordStrength(password string) map[string]bool {
    strength := map[string]bool{
        "has_lower":   false,
        "has_upper":   false,
        "has_number":  false,
        "has_symbol":  false,
        "min_length":  len(password) >= 8,
        "good_length": len(password) >= 12,
    }

    for _, char := range password {
        switch {
        case char >= 'a' && char <= 'z':
            strength["has_lower"] = true
        case char >= 'A' && char <= 'Z':
            strength["has_upper"] = true
        case char >= '0' && char <= '9':
            strength["has_number"] = true
        case strings.ContainsRune("!@#$%^&*()_+-=[]{}|;:,.<>?", char):
            strength["has_symbol"] = true
        }
    }

    return strength
}
