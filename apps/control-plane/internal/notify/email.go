package notify

import (
	"fmt"
	"net/smtp"
	"strings"
)

// EmailConfig holds configuration for SMTP email sending.
type EmailConfig struct {
	Host     string   `json:"host"`
	Port     int      `json:"port"`
	Username string   `json:"username"`
	Password string   `json:"password"`
	From     string   `json:"from"`
	To       []string `json:"to"`
}

// SendEmail sends a plain-text email using SMTP.
// Returns an error if the config is invalid or sending fails.
func SendEmail(cfg EmailConfig, subject, body string) error {
	if cfg.Host == "" || len(cfg.To) == 0 {
		return fmt.Errorf("email config invalid: host and to are required")
	}
	if cfg.Port == 0 {
		cfg.Port = 25
	}
	addr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
	msg := []byte("From: " + cfg.From + "\r\n" +
		"To: " + strings.Join(cfg.To, ",") + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"Content-Type: text/plain; charset=UTF-8\r\n" +
		"\r\n" + body)
	var auth smtp.Auth
	if cfg.Username != "" {
		auth = smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.Host)
	}
	return smtp.SendMail(addr, auth, cfg.From, cfg.To, msg)
}
