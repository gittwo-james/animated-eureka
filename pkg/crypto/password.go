package crypto

import (
    "errors"
    "unicode"

    "golang.org/x/crypto/bcrypt"
)

const BCryptCost = 12

var ErrPasswordTooWeak = errors.New("password does not meet complexity requirements")

func HashPassword(password string) (string, error) {
    hash, err := bcrypt.GenerateFromPassword([]byte(password), BCryptCost)
    if err != nil {
        return "", err
    }
    return string(hash), nil
}

func ComparePassword(hash string, password string) error {
    return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}

func ValidatePasswordComplexity(password string) ([]string, error) {
    var issues []string
    if len(password) < 12 {
        issues = append(issues, "must be at least 12 characters")
    }

    var hasUpper, hasLower, hasDigit, hasSpecial bool
    for _, r := range password {
        switch {
        case unicode.IsUpper(r):
            hasUpper = true
        case unicode.IsLower(r):
            hasLower = true
        case unicode.IsDigit(r):
            hasDigit = true
        case unicode.IsPunct(r) || unicode.IsSymbol(r):
            hasSpecial = true
        }
    }

    if !hasUpper {
        issues = append(issues, "must include an uppercase letter")
    }
    if !hasLower {
        issues = append(issues, "must include a lowercase letter")
    }
    if !hasDigit {
        issues = append(issues, "must include a number")
    }
    if !hasSpecial {
        issues = append(issues, "must include a special character")
    }

    if len(issues) > 0 {
        return issues, ErrPasswordTooWeak
    }
    return nil, nil
}
