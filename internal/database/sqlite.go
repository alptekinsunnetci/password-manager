package database

import (
	"database/sql"
	"password-manager/internal/models"
	"time"

	_ "modernc.org/sqlite"
)

type DB struct {
	conn *sql.DB
}

// NewDB creates a new database connection
func NewDB(dataSourceName string) (*DB, error) {
	conn, err := sql.Open("sqlite", dataSourceName)
	if err != nil {
		return nil, err
	}

	db := &DB{conn: conn}
	if err := db.createTables(); err != nil {
		return nil, err
	}

	return db, nil
}

// createTables creates the necessary tables
func (db *DB) createTables() error {
	query := `
    CREATE TABLE IF NOT EXISTS passwords (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        service TEXT NOT NULL,
        username TEXT NOT NULL,
        password TEXT NOT NULL,
        url TEXT,
        notes TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(service, username)
    );
    
    CREATE INDEX IF NOT EXISTS idx_service ON passwords(service);
    `

	_, err := db.conn.Exec(query)
	return err
}

// CreatePassword creates a new password entry
func (db *DB) CreatePassword(password *models.Password) error {
	query := `
    INSERT INTO passwords (service, username, password, url, notes, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    `

	now := time.Now()
	result, err := db.conn.Exec(query, password.Service, password.Username,
		password.Password, password.URL, password.Notes, now, now)
	if err != nil {
		return err
	}

	id, err := result.LastInsertId()
	if err != nil {
		return err
	}

	password.ID = int(id)
	password.CreatedAt = now
	password.UpdatedAt = now
	return nil
}

// GetPassword gets a password by service and username
func (db *DB) GetPassword(service, username string) (*models.Password, error) {
	query := `
    SELECT id, service, username, password, url, notes, created_at, updated_at
    FROM passwords WHERE service = ? AND username = ?
    `

	password := &models.Password{}
	err := db.conn.QueryRow(query, service, username).Scan(
		&password.ID, &password.Service, &password.Username, &password.Password,
		&password.URL, &password.Notes, &password.CreatedAt, &password.UpdatedAt,
	)

	if err != nil {
		return nil, err
	}

	return password, nil
}

// ListPasswords lists all passwords
func (db *DB) ListPasswords() ([]*models.Password, error) {
	query := `
    SELECT id, service, username, password, url, notes, created_at, updated_at
    FROM passwords ORDER BY service, username
    `

	rows, err := db.conn.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var passwords []*models.Password
	for rows.Next() {
		password := &models.Password{}
		err := rows.Scan(
			&password.ID, &password.Service, &password.Username, &password.Password,
			&password.URL, &password.Notes, &password.CreatedAt, &password.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		passwords = append(passwords, password)
	}

	return passwords, rows.Err()
}

// UpdatePassword updates an existing password
func (db *DB) UpdatePassword(service, username string, updates *models.Password) error {
	query := `
    UPDATE passwords SET password = ?, url = ?, notes = ?, updated_at = ?
    WHERE service = ? AND username = ?
    `

	now := time.Now()
	_, err := db.conn.Exec(query, updates.Password, updates.URL, updates.Notes,
		now, service, username)
	return err
}

// DeletePassword deletes a password entry
func (db *DB) DeletePassword(service, username string) error {
	query := `DELETE FROM passwords WHERE service = ? AND username = ?`
	_, err := db.conn.Exec(query, service, username)
	return err
}

// SearchPasswords searches passwords by service name
func (db *DB) SearchPasswords(searchTerm string) ([]*models.Password, error) {
	query := `
    SELECT id, service, username, password, url, notes, created_at, updated_at
    FROM passwords WHERE service LIKE ? OR username LIKE ? OR url LIKE ?
    ORDER BY service, username
    `

	searchPattern := "%" + searchTerm + "%"
	rows, err := db.conn.Query(query, searchPattern, searchPattern, searchPattern)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var passwords []*models.Password
	for rows.Next() {
		password := &models.Password{}
		err := rows.Scan(
			&password.ID, &password.Service, &password.Username, &password.Password,
			&password.URL, &password.Notes, &password.CreatedAt, &password.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		passwords = append(passwords, password)
	}

	return passwords, rows.Err()
}

// Close closes the database connection
func (db *DB) Close() error {
	return db.conn.Close()
}
