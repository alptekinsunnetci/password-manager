package models

import "time"

// Password represents a password entry in the database
type Password struct {
    ID          int       `json:"id"`
    Service     string    `json:"service"`
    Username    string    `json:"username"`
    Password    string    `json:"password"` // Encrypted
    URL         string    `json:"url,omitempty"`
    Notes       string    `json:"notes,omitempty"`
    CreatedAt   time.Time `json:"created_at"`
    UpdatedAt   time.Time `json:"updated_at"`
}

// PasswordRequest represents a request to create/update a password
type PasswordRequest struct {
    Service  string `json:"service"`
    Username string `json:"username"`
    Password string `json:"password"`
    URL      string `json:"url,omitempty"`
    Notes    string `json:"notes,omitempty"`
}

// GeneratorOptions represents password generation options
type GeneratorOptions struct {
    Length         int  `json:"length"`
    IncludeUpper   bool `json:"include_upper"`
    IncludeLower   bool `json:"include_lower"`
    IncludeNumbers bool `json:"include_numbers"`
    IncludeSymbols bool `json:"include_symbols"`
    ExcludeSimilar bool `json:"exclude_similar"`
}
