package rest

import (
	"encoding/json"
	"fmt"
	"net/http"
	"social-communication-platform/internal/apperror"
	"social-communication-platform/internal/domain"
	"social-communication-platform/pkg/logging"

	"github.com/julienschmidt/httprouter"
)

type UserService interface {
	UserRegister(users domain.User) (domain.User, error)
	UserLogin(user domain.User) (domain.TokenResponse, domain.TwoFaCodes, error)
	UserRefresh(token string) (domain.TokenResponse, error)
	SendEmailCode(tempToken string) error
	VerifyCode(code domain.Code) (domain.TokenResponse, error)
	EnableTwoFA(userID int64) error
	DisableTwoFA(userID int64, password string) error
}

type UserHandler struct {
	service UserService
	logger *logging.Logger
}

func NewUserService(u UserService, l *logging.Logger) *UserHandler {
	return &UserHandler{
		service: u,
		logger: l,
	}
}

var stud []domain.User

func (u *UserHandler) Register(router *httprouter.Router, jwtSecret string) {
	router.HandlerFunc(http.MethodPost, "/api/auth/register", apperror.Middleware(u.signUp))
	router.HandlerFunc(http.MethodPost, "/api/auth/login", apperror.Middleware(u.signIn))
	router.HandlerFunc(http.MethodPost, "/api/auth/refresh", apperror.Middleware(u.refresh))
	router.HandlerFunc(http.MethodPost, "/api/auth/send-code", apperror.Middleware(u.sendEmailCode))
	router.HandlerFunc(http.MethodPost, "/api/auth/verify-code", apperror.Middleware(u.verifyCode))
	router.Handler(http.MethodPost, "/api/auth/enable-2fa", apperror.JWTMiddleware(jwtSecret, http.HandlerFunc(apperror.Middleware(u.enableTwoFA))))
	router.Handler(http.MethodPost, "/api/auth/disable-2fa", apperror.JWTMiddleware(jwtSecret, http.HandlerFunc(apperror.Middleware(u.disableTwoFA))))
}

func (u *UserHandler) signUp(w http.ResponseWriter, r *http.Request) error {
	w.Header().Set("Content-Type", "application/json")
	
	var user domain.User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		u.logger.Error("Failed to decode JSON: " + err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return err
	}
	defer r.Body.Close()
	
	fmt.Printf("DEBUG: Received - Firstname: %s, Email: %s\n", user.Firstname, user.Email)
	
	createdUser, err := u.service.UserRegister(user)
	if err != nil {
		u.logger.Error("Failed to register user: " + err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return err
	}
	
	fmt.Printf("DEBUG: User created with ID: %d\n", createdUser.ID)
	
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(createdUser)
	return nil
}

func (u *UserHandler) signIn(w http.ResponseWriter, r *http.Request) error {
	w.Header().Set("Content-Type", "application/json")
	
	var user domain.User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		u.logger.Error("Failed to decode JSON: " + err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return err
	}
	defer r.Body.Close()
	
	accessToken, tempToken, err := u.service.UserLogin(user)
	if err != nil {
		u.logger.Error("Failed to login user: " + err.Error())
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return err
	}
	
	if tempToken.RequiresTwoFa {
		return json.NewEncoder(w).Encode(tempToken)
	}
	
	json.NewEncoder(w).Encode(accessToken)
	return nil
}

func (u *UserHandler) refresh(w http.ResponseWriter, r *http.Request) error {
	w.Header().Set("Content-Type", "application/json")
	
	var tokens struct { RefreshToken string `json:"refresh_token"` }
	if err := json.NewDecoder(r.Body).Decode(&tokens); err != nil {
		u.logger.Error("Failed to decode JSON: " + err.Error())
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return err
	}
	defer r.Body.Close()

	token, err := u.service.UserRefresh(tokens.RefreshToken)
	if err != nil {
		u.logger.Error("Failed to refresh token: " + err.Error())
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return err
	}

	json.NewEncoder(w).Encode(token)
	return nil
}

func (u *UserHandler) sendEmailCode(w http.ResponseWriter, r *http.Request) error {
	w.Header().Set("Content-Type", "application/json")

	var req struct { TempToken string `json:"temp_token"`}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		u.logger.Error("Failed to decode JSON: " + err.Error())
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return err
	}
	defer r.Body.Close()
	
	err := u.service.SendEmailCode(req.TempToken)
	if err != nil {
		u.logger.Error("Failed to temp token: " + err.Error())
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return err
	}
	
	res := map[string]bool{"success": true}
	json.NewEncoder(w).Encode(res)
	return nil
}

func (u *UserHandler) verifyCode(w http.ResponseWriter, r *http.Request) error {
	w.Header().Set("Content-Type", "application/json")

	var code domain.Code
	if err := json.NewDecoder(r.Body).Decode(&code); err != nil {
		u.logger.Error("Failed to decode JSON: " + err.Error())
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return err
	}
	defer r.Body.Close()
	
	tokenRes, err := u.service.VerifyCode(code)
	if err != nil {
		u.logger.Error("Failed to verify code: " + err.Error())
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return err
	}
	
	json.NewEncoder(w).Encode(tokenRes)
	return nil
}

func (u *UserHandler) enableTwoFA(w http.ResponseWriter, r *http.Request) error {
	w.Header().Set("Content-Type", "application/json")

	userID, ok := r.Context().Value("userID").(int64)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return nil
	}
	
	err := u.service.EnableTwoFA(userID)
	if err != nil {
		u.logger.Error("Failed to enable 2FA: " + err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return err
	}
	
	res := map[string]bool{"success": true}
	json.NewEncoder(w).Encode(res)
	return nil
}

func (u *UserHandler) disableTwoFA(w http.ResponseWriter, r *http.Request) error {
	w.Header().Set("Content-Type", "application/json")
	
	userID, ok := r.Context().Value("userID").(int64)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusBadRequest)
		return nil
	}
	
	var req domain.TwoFaToggleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		u.logger.Error("Failed to decode JSON: " + err.Error())
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return err
	}
	defer r.Body.Close()
	
	err := u.service.DisableTwoFA(userID, req.Password)
	if err != nil {
		u.logger.Error("Failed to disable 2FA: " + err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return err
	}
	
	res := map[string]bool{"success": true}
	json.NewEncoder(w).Encode(res)
	return nil
}