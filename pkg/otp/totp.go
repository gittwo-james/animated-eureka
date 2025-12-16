package otp

import (
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

type TOTPConfig struct {
	Issuer      string
	AccountName string
	Period      uint
	SecretSize  uint
}

func GenerateTOTPSecret(cfg TOTPConfig) (*otp.Key, error) {
	period := cfg.Period
	if period == 0 {
		period = 30
	}
	secretSize := cfg.SecretSize
	if secretSize == 0 {
		secretSize = 32
	}

	return totp.Generate(totp.GenerateOpts{
		Issuer:      cfg.Issuer,
		AccountName: cfg.AccountName,
		Period:      period,
		SecretSize:  secretSize,
	})
}

func ValidateTOTPCode(code, secret string) bool {
	return totp.Validate(code, secret)
}

func ValidateTOTPCodeAt(code, secret string, t time.Time) bool {
	valid, err := totp.ValidateCustom(code, secret, t, totp.ValidateOpts{Period: 30, Skew: 1, Digits: otp.DigitsSix})
	return err == nil && valid
}
