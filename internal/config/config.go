package config

import (
	"social-communication-platform/pkg/logging"
	"sync"

	"github.com/ilyakaznacheev/cleanenv"
)

type Config struct {
	Env           string `yaml:"env" env-default:""development"`
	StorageConfig
}

type StorageConfig struct {
	Host     string `yaml:"host" env:"DB_HOST" env-default:"db"`
	Port     string `yaml:"port" env:"DB_PORT" env-default:"5432"`
	Database string `yaml:"database" env:"DB_NAME" env-default:"postgres"`
	Username string `yaml:"username" env:"DB_USERNAME" env-default:"postgres"`
	Password string `yaml:"password" env:"DB_PASSWORD" env-default:"postgres"`
}

var (
	instance *Config
	once sync.Once
)

func GetConfig() *Config {
	once.Do(func() {
		logger := logging.GetLogger()
		logger.Info("read application configuration")
		instance = &Config{}
		
		if err := cleanenv.ReadEnv(instance); err != nil {
			logger.Errorf("Error reading env vars: %v", err)
		}
		
		if err := cleanenv.ReadConfig("/config.yml", instance); err != nil {
			logger.Errorf("Config file not found, using env vars: %v", err)
		}
		
		logger.Infof("Database config: %s:%s", instance.Host, instance.Port)
	})
	return instance
}