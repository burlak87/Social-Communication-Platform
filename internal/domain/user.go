package domain

import "time"

type User struct {
	ID           int64      `json:"id"`
	Nikename     string		`json:"nikename"`
	Firstname    string     `json:"firstname"`
	Lastname     string		`json:"lastname"`
	Email        string		`json:"email"`
	Password     string		`json:"password"`
	PasswordHash string		`json:"-"`
	CreatedAt    time.Time	`json:"created_at"`
	TwoFAEnabled bool		`json:"two_fa_enabled"`
}

type TwoFaCodes struct {
	RequiresTwoFa bool   `json:"requires_two_fa"`
	TempToken     string `json:"temp_token"`
}

type TwoFaCode struct {
	ID        int64		`json:"id"`
	UserID    int64     `json:"user_id"`
	Code      string    `json:"code"`
	ExpiresAt time.Time `json:"expires_at"`
	Attempts  int64     `json:"attempts"`
	IsUsed    bool      `json:"is_used"`
	CreatedAt time.Time `json:"created_at"`
}

type Code struct {
	TempToken string `json:"temp_token"`
	Code      string `json:"code"`
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type RegisterRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type TwoFaToggleRequest struct {
	Password string `json:"password"`
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}