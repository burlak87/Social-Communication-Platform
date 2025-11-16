package postgresql

import (
	"context"
	"social-communication-platform/internal/config"
	repeatable "social-communication-platform/pkg/utils"
	"time"
	"log"
	"fmt"

	"github.com/jackc/pgconn"
	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
)

type Client interface {
	Exec(ctx context.Context, sql string, arguments ...interface{}) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error)
	QueryRows(ctx context.Context, sql string, args ...interface{}) pgx.Rows
	Begin(ctx context.Context) (pgx.Tx, error)
}

func NewClient(ctx context.Context, maxAttempts int, sc config.StorageConfig) (pool *pgxpool.Pool, err error) {
	dsn := fmt.Sprintf("postgresql://%s:%s@%s:%s/%s?sslmode=disable&connect_timeout=5", sc.Username, sc.Password, sc.Host, sc.Port, sc.Database)
	fmt.Println(dsn)
	fmt.Println("Attempting to connect to PostgreSQL...")
	err = repeatable.DoWithTries(func() error {
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		
		pool, err = pgxpool.Connect(ctx, dsn)
		if err != nil {
			fmt.Printf("Connection failed: %v\n", err)
			return err
		}
		
		conn, err :=  pool.Acquire(ctx)
		if err != nil {
			return err
		}
		defer conn.Release()
		if err := conn.Conn().Ping(ctx); err != nil {
			return err
		}
		
		fmt.Println("Successfully connected to PostgreSQL!")
		return nil
	}, maxAttempts, 10 * time.Second)

	if err != nil {
    	log.Fatalf("Failed to connect to PostgreSQL after %d attempts: %v", maxAttempts, err)
  	}

	var id int64
  	err = pool.QueryRow(context.Background(),
    "INSERT INTO users (firstname, lastname, email, password_hash) VALUES ($1, $2, $3, $4) RETURNING id",
    "Test", "User", "test@test.com", "hash").Scan(&id)
    
   	if err != nil {
    	log.Fatal("Insert error:", err)
    }
    fmt.Printf("Inserted user with ID: %d\n", id)

    var count int
    err = pool.QueryRow(context.Background(), "SELECT COUNT(*) FROM users").Scan(&count)
    if err != nil {
    	log.Fatal("Count error:", err)
    }
  
    fmt.Printf("Total users: %d\n", count)
    return pool, nil
}