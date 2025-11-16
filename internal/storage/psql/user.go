package psql

import (
	"context"
	"errors"
	"social-communication-platform/internal/domain"
	"time"
	"fmt"

	"github.com/jackc/pgx/v4/pgxpool"
)

type UsersRepo struct {
	db *pgxpool.Pool
}

func NewUsersRepo(db *pgxpool.Pool) *UsersRepo {
	return &UsersRepo{db: db}
}

func (s *UsersRepo) InsertUsers(users domain.User) (int64, error) {
    var id int64
    fmt.Printf("DEBUG INSERT: Starting insert - Firstname: %s, Email: %s\n", 
        users.Firstname, users.Email)
    
    query := `INSERT INTO users (firstname, lastname, email, password_hash) VALUES ($1, $2, $3, $4) RETURNING id`
    
    fmt.Printf("DEBUG INSERT: Executing query: %s\n", query)
    fmt.Printf("DEBUG INSERT: Params: %s, %s, %s, [hash]\n", 
        users.Firstname, users.Lastname, users.Email)
    
    err := s.db.QueryRow(context.Background(), query,
        users.Firstname, users.Lastname, users.Email, users.PasswordHash).
        Scan(&id)
    
    if err != nil {
        fmt.Printf("DEBUG INSERT: ERROR: %v\n", err)
        return 0, err
    }
    
    fmt.Printf("DEBUG INSERT: SUCCESS - Inserted with ID: %d\n", id)
    return id, nil
}

func (s *UsersRepo) SelectUsers(email string) (domain.User, error) {
    var stud domain.User
    fmt.Printf("DEBUG SELECT: Searching user with email: %s\n", email)
    
    query := `SELECT id, firstname, lastname, email, password_hash, created_at, two_fa_enabled FROM users WHERE email = $1`
    
    err := s.db.QueryRow(context.Background(), query, email).
        Scan(&stud.ID, &stud.Firstname, &stud.Lastname, &stud.Email, &stud.PasswordHash, &stud.CreatedAt, &stud.TwoFAEnabled)
    
    if err != nil {
        fmt.Printf("DEBUG SELECT: ERROR: %v\n", err)
        return stud, err
    }
    
    fmt.Printf("DEBUG SELECT: SUCCESS - User ID: %d, Email: %s\n", stud.ID, stud.Email)
    return stud, nil
}

func (s *UsersRepo) RefreshStore(userID int64, token string, expiresAt time.Time) error {
	_, err := s.db.Exec(context.Background(), 
		"INSERT INTO refresh_token (user_id, token, expires_at) VALUES ($1, $2, $3)", 
		userID, token, expiresAt)
	
	return err
}

func (s *UsersRepo) RefreshGet(token string) (int64, error) {
	var userID int64
	var expiresAt time.Time
	err := s.db.QueryRow(context.Background(), 
		"SELECT user_id, expires_at FROM refresh_token WHERE token = $1", token).
		Scan(&userID, &expiresAt)

	if err != nil {
		return 0, err
	}

	if time.Now().After(expiresAt) {
		s.RefreshDelete(token)
		return 0, errors.New("token expired")
	}

	return userID, nil
}

func (s *UsersRepo) RefreshDelete(token string) error {
	_, err := s.db.Exec(context.Background(), 
		"DELETE FROM refresh_token WHERE token = $1", token)

	return err
}

func (s *UsersRepo) UserBlocked(email string, windowStart time.Time) ([]map[string]interface{}, error) {
	q := `SELECT blocked_until FROM login_attempts	WHERE email = $1 AND blocked_until >= $2	ORDER BY blocked_until DESC LIMIT 1`
	var blockedUntil string

	err := s.db.QueryRow(context.Background(), q, email, windowStart).Scan(&blockedUntil)
	if err != nil {
		if err.Error() == "no rows in result set" {
			return []map[string]interface{}{}, nil
		}
		return nil, err
	}

	result := []map[string]interface{}{
		{"blocked_until": blockedUntil},
	}

	return result, nil 
}

func (s *UsersRepo) LogAttempt(email string, result bool, attemptTime time.Time) error {
	q := `INSERT INTO login_attempts (email, result, attempt_time) VALUES ($1, $2, $3)`
	time := attemptTime.Format(time.RFC3339)

	_, err := s.db.Exec(context.Background(), q, email, result, time)
	return err
}

func (s *UsersRepo) GetFailedLogAttempts(email string, windowStart time.Time) (int, error) {
	q := `SELECT COUNT(*) FROM login_attempts WHERE email = $1 AND result = false AND attempt_time >= $2`
	var count int
	err := s.db.QueryRow(context.Background(), q, email, windowStart).Scan(&count)
	return count, err
}

func (s *UsersRepo) BlockUser(email, blockedUntil string) error {
	q := `UPDATE login_attempts SET blocked_until = $2 WHERE email = $1 AND blocked_until IS NULL`
	_, err := s.db.Exec(context.Background(), q, email, blockedUntil)
	
	return err
}

func (s *UsersRepo) SelectUserByID(id int64) (domain.User, error) {
    var stud domain.User
    query := `SELECT id, firstname, lastname, email, password_hash, created_at, two_fa_enabled FROM users WHERE id = $1`
    
    err := s.db.QueryRow(context.Background(), query, id).
        Scan(&stud.ID, &stud.Firstname, &stud.Lastname, &stud.Email, &stud.PasswordHash, &stud.CreatedAt, &stud.TwoFAEnabled)
    
    if err != nil {
        return stud, err
    }
    
    return stud, nil
}

func (s *UsersRepo) RenovationTwoFAStatus(userID int64, enabled bool) error {
    query := `UPDATE users SET two_fa_enabled = $1 WHERE id = $2`
    _, err := s.db.Exec(context.Background(), query, enabled, userID)
    return err
}