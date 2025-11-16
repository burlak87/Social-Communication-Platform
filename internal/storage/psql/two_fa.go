package psql

import (
	"context"
	"social-communication-platform/internal/domain"
	"time"

	"github.com/jackc/pgx/v4/pgxpool"
)

type TwoFaRepo struct {
	db *pgxpool.Pool
}

func NewTwoFaRepo(db *pgxpool.Pool) *TwoFaRepo {
	return &TwoFaRepo{db: db}
}

func (t *TwoFaRepo) InsertTwoFaCode(userID int64, code string, expiresAt time.Time) error {
	q := `INSERT INTO two_fa_codes (user_id, code, expires_at) VALUES ($1, $2, $3)`
	_, err := t.db.Exec(context.Background(), q, userID, code, expiresAt)
	return err
}

func (t *TwoFaRepo) SelectTwoFaCodeByUserID(userID int64) (domain.TwoFaCode, error) {
	var twoFaCode domain.TwoFaCode
	q := `
		SELECT id, user_id, code, expires_at, attempts, is_used, created_at
		FROM two_fa_codes 
		WHERE user_id = $1 AND is_used = false AND attempts < 3 AND expires_at > NOW()
		ORDER BY created_at DESC 
		LIMIT 1
	`

	err := t.db.QueryRow(context.Background(), q, userID).
		Scan(&twoFaCode.ID, &twoFaCode.UserID, &twoFaCode.Code, &twoFaCode.ExpiresAt,
			&twoFaCode.Attempts, &twoFaCode.IsUsed, &twoFaCode.CreatedAt)

	return twoFaCode, err
}

func (t *TwoFaRepo) RenovationTwoFaCodeAttempts(codeID int64, attempts int) error {
	q := `UPDATE two_fa_codes SET attempts = $1 WHERE id = $2`
	_, err := t.db.Exec(context.Background(), q, attempts, codeID)
	return err
}

func (t *TwoFaRepo) MarkTwoFaCodeUsed(codeID int64) error {
	q := `UPDATE two_fa_codes SET is_used = true WHERE id = $1`
	_, err := t.db.Exec(context.Background(), q, codeID)
	return err
}

func (t *TwoFaRepo) SelectRecentCodeRequests(userID int64, since time.Time) (int, error) {
	q := `SELECT COUNT(*) FROM two_fa_codes WHERE user_id = $1 AND created_at > $2`
	var count int
	err := t.db.QueryRow(context.Background(), q, userID, since).Scan(&count)
	return count, err
}

func (t *TwoFaRepo) SelectRecentVerificationAttempts(userID int64, since time.Time) (int, error) {
	q := `
		SELECT COUNT(*) FROM two_fa_codes 
		WHERE user_id = $1 AND created_at > $2 AND (attempts > 0 OR is_used = true)
	`
	var count int
	err := t.db.QueryRow(context.Background(), q, userID, since).Scan(&count)
	return count, err
}