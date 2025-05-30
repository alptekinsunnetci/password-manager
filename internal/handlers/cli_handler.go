package handlers

import (
    "bufio"
    "fmt"
    "os"
    "password-manager/internal/models"
    "password-manager/internal/services"
    "strconv"
    "strings"
    "syscall"

    "golang.org/x/term"
)

type CLIHandler struct {
    passwordService   *services.PasswordService
    generatorService  *services.GeneratorService
    scanner          *bufio.Scanner
}

// NewCLIHandler creates a new CLI handler
func NewCLIHandler(passwordService *services.PasswordService, generatorService *services.GeneratorService) *CLIHandler {
    return &CLIHandler{
        passwordService:  passwordService,
        generatorService: generatorService,
        scanner:         bufio.NewScanner(os.Stdin),
    }
}

// Start starts the CLI interface
func (h *CLIHandler) Start() {
    fmt.Println("🔐 Password Manager")
    fmt.Println("==================")

    for {
        fmt.Println("\nSelect an option:")
        fmt.Println("1. Add new password")
        fmt.Println("2. Get password")
        fmt.Println("3. List all passwords")
        fmt.Println("4. Search passwords")
        fmt.Println("5. Update password")
        fmt.Println("6. Delete password")
        fmt.Println("7. Generate password")
        fmt.Println("8. Exit")
        fmt.Print("\nEnter your choice (1-8): ")

        choice := h.readInput()
        fmt.Println()

        switch choice {
        case "1":
            h.addPassword()
        case "2":
            h.getPassword()
        case "3":
            h.listPasswords()
        case "4":
            h.searchPasswords()
        case "5":
            h.updatePassword()
        case "6":
            h.deletePassword()
        case "7":
            h.generatePassword()
        case "8":
            fmt.Println("Goodbye! 👋")
            return
        default:
            fmt.Println("❌ Invalid choice. Please try again.")
        }
    }
}

func (h *CLIHandler) addPassword() {
    fmt.Println("➕ Add New Password")
    fmt.Println("-------------------")

    fmt.Print("Service name: ")
    service := h.readInput()

    fmt.Print("Username: ")
    username := h.readInput()

    fmt.Print("Generate password? (y/n): ")
    generateChoice := strings.ToLower(h.readInput())

    var password string
    if generateChoice == "y" || generateChoice == "yes" {
        generated, err := h.generatePasswordHelper()
        if err != nil {
            fmt.Printf("❌ Error generating password: %v\n", err)
            return
        }
        password = generated
        fmt.Printf("Generated password: %s\n", password)
    } else {
        fmt.Print("Password: ")
        password = h.readPassword()
    }

    fmt.Print("URL (optional): ")
    url := h.readInput()

    fmt.Print("Notes (optional): ")
    notes := h.readInput()

    req := &models.PasswordRequest{
        Service:  service,
        Username: username,
        Password: password,
        URL:      url,
        Notes:    notes,
    }

    if err := h.passwordService.CreatePassword(req); err != nil {
        fmt.Printf("❌ Error: %v\n", err)
    } else {
        fmt.Println("✅ Password saved successfully!")
    }
}

func (h *CLIHandler) getPassword() {
    fmt.Println("🔍 Get Password")
    fmt.Println("---------------")

    fmt.Print("Service name: ")
    service := h.readInput()

    fmt.Print("Username: ")
    username := h.readInput()

    password, err := h.passwordService.GetPassword(service, username)
    if err != nil {
        fmt.Printf("❌ Error: %v\n", err)
        return
    }

    fmt.Printf("\n📋 Password Details:\n")
    fmt.Printf("Service: %s\n", password.Service)
    fmt.Printf("Username: %s\n", password.Username)
    fmt.Printf("Password: %s\n", password.Password)
    if password.URL != "" {
        fmt.Printf("URL: %s\n", password.URL)
    }
    if password.Notes != "" {
        fmt.Printf("Notes: %s\n", password.Notes)
    }
    fmt.Printf("Created: %s\n", password.CreatedAt.Format("2006-01-02 15:04:05"))
    fmt.Printf("Updated: %s\n", password.UpdatedAt.Format("2006-01-02 15:04:05"))
}

func (h *CLIHandler) listPasswords() {
    fmt.Println("📋 All Passwords")
    fmt.Println("----------------")

    passwords, err := h.passwordService.ListPasswords()
    if err != nil {
        fmt.Printf("❌ Error: %v\n", err)
        return
    }

    if len(passwords) == 0 {
        fmt.Println("No passwords stored.")
        return
    }

    for _, password := range passwords {
        fmt.Printf("🔐 %s (%s) - %s\n", password.Service, password.Username, password.Password)
    }
}

func (h *CLIHandler) searchPasswords() {
    fmt.Println("🔍 Search Passwords")
    fmt.Println("-------------------")

    fmt.Print("Search term: ")
    searchTerm := h.readInput()

    passwords, err := h.passwordService.SearchPasswords(searchTerm)
    if err != nil {
        fmt.Printf("❌ Error: %v\n", err)
        return
    }

    if len(passwords) == 0 {
        fmt.Println("No passwords found.")
        return
    }

    fmt.Printf("\nFound %d password(s):\n", len(passwords))
    for _, password := range passwords {
        fmt.Printf("🔐 %s (%s) - %s\n", password.Service, password.Username, password.Password)
    }
}

func (h *CLIHandler) updatePassword() {
    fmt.Println("✏️ Update Password")
    fmt.Println("------------------")

    fmt.Print("Service name: ")
    service := h.readInput()

    fmt.Print("Username: ")
    username := h.readInput()

    fmt.Print("Generate new password? (y/n): ")
    generateChoice := strings.ToLower(h.readInput())

    var password string
    if generateChoice == "y" || generateChoice == "yes" {
        generated, err := h.generatePasswordHelper()
        if err != nil {
            fmt.Printf("❌ Error generating password: %v\n", err)
            return
        }
        password = generated
        fmt.Printf("Generated password: %s\n", password)
    } else {
        fmt.Print("New password: ")
        password = h.readPassword()
    }

    fmt.Print("URL (optional): ")
    url := h.readInput()

    fmt.Print("Notes (optional): ")
    notes := h.readInput()

    req := &models.PasswordRequest{
        Service:  service,
        Username: username,
        Password: password,
        URL:      url,
        Notes:    notes,
    }

    if err := h.passwordService.UpdatePassword(service, username, req); err != nil {
        fmt.Printf("❌ Error: %v\n", err)
    } else {
        fmt.Println("✅ Password updated successfully!")
    }
}

func (h *CLIHandler) deletePassword() {
    fmt.Println("🗑️ Delete Password")
    fmt.Println("------------------")

    fmt.Print("Service name: ")
    service := h.readInput()

    fmt.Print("Username: ")
    username := h.readInput()

    fmt.Printf("Are you sure you want to delete the password for %s (%s)? (y/n): ", service, username)
    confirm := strings.ToLower(h.readInput())

    if confirm == "y" || confirm == "yes" {
        if err := h.passwordService.DeletePassword(service, username); err != nil {
            fmt.Printf("❌ Error: %v\n", err)
        } else {
            fmt.Println("✅ Password deleted successfully!")
        }
    } else {
        fmt.Println("❌ Deletion cancelled.")
    }
}

func (h *CLIHandler) generatePassword() {
    fmt.Println("🎲 Generate Password")
    fmt.Println("--------------------")

    options := h.getGeneratorOptions()
    password, err := h.generatorService.GeneratePassword(options)
    if err != nil {
        fmt.Printf("❌ Error generating password: %v\n", err)
        return
    }

    fmt.Printf("\n🔐 Generated Password: %s\n", password)

    // Show password strength
    strength := h.generatorService.ValidatePasswordStrength(password)
    fmt.Println("\n📊 Password Strength:")
    fmt.Printf("Has lowercase: %v\n", strength["has_lower"])
    fmt.Printf("Has uppercase: %v\n", strength["has_upper"])
    fmt.Printf("Has numbers: %v\n", strength["has_number"])
    fmt.Printf("Has symbols: %v\n", strength["has_symbol"])
    fmt.Printf("Minimum length (8+): %v\n", strength["min_length"])
    fmt.Printf("Good length (12+): %v\n", strength["good_length"])
}

func (h *CLIHandler) generatePasswordHelper() (string, error) {
    options := h.getGeneratorOptions()
    return h.generatorService.GeneratePassword(options)
}

func (h *CLIHandler) getGeneratorOptions() *models.GeneratorOptions {
    options := &models.GeneratorOptions{
        Length:         12,
        IncludeUpper:   true,
        IncludeLower:   true,
        IncludeNumbers: true,
        IncludeSymbols: true,
        ExcludeSimilar: false,
    }

    fmt.Print("Password length (default 12): ")
    lengthStr := h.readInput()
    if lengthStr != "" {
        if length, err := strconv.Atoi(lengthStr); err == nil && length > 0 {
            options.Length = length
        }
    }

    fmt.Print("Include uppercase letters? (Y/n): ")
    if strings.ToLower(h.readInput()) == "n" {
        options.IncludeUpper = false
    }

    fmt.Print("Include lowercase letters? (Y/n): ")
    if strings.ToLower(h.readInput()) == "n" {
        options.IncludeLower = false
    }

    fmt.Print("Include numbers? (Y/n): ")
    if strings.ToLower(h.readInput()) == "n" {
        options.IncludeNumbers = false
    }

    fmt.Print("Include symbols? (Y/n): ")
    if strings.ToLower(h.readInput()) == "n" {
        options.IncludeSymbols = false
    }

    fmt.Print("Exclude similar characters (0,O,l,1,I)? (y/N): ")
    if strings.ToLower(h.readInput()) == "y" {
        options.ExcludeSimilar = true
    }

    return options
}

func (h *CLIHandler) readInput() string {
    h.scanner.Scan()
    return strings.TrimSpace(h.scanner.Text())
}

func (h *CLIHandler) readPassword() string {
    fmt.Print("Password: ")
    password, err := term.ReadPassword(int(syscall.Stdin))
    fmt.Println()
    if err != nil {
        fmt.Printf("❌ Error reading password: %v\n", err)
        return ""
    }
    return string(password)
}
