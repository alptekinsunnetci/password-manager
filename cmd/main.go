package main

import (
	"fmt"
	"log"
	"password-manager/internal/crypto"
	"password-manager/internal/database"
	"password-manager/internal/handlers"
	"password-manager/internal/services"
	"syscall"

	"golang.org/x/term"
	_ "modernc.org/sqlite"
)

func main() {
	// Initialize database first
	dbPath := "passwords.db"
	db, err := database.NewDB(dbPath)
	if err != nil {
		log.Fatal("Error initializing database:", err)
	}
	defer db.Close()

	// Get master password
	fmt.Print("Enter master password: ")
	masterPassword, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		log.Fatal("Error reading master password:", err)
	}

	if len(masterPassword) == 0 {
		log.Fatal("Master password cannot be empty")
	}

	// Initialize encryption with database connection
	encryptor, err := crypto.NewEncryptor(string(masterPassword), db)
	if err != nil {
		log.Fatal("Error initializing encryption:", err)
	}

	// Initialize services
	passwordService := services.NewPasswordService(db, encryptor)
	generatorService := services.NewGeneratorService()

	// Initialize CLI handler
	cliHandler := handlers.NewCLIHandler(passwordService, generatorService)

	// Start CLI
	cliHandler.Start()
}
