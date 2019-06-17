package service

import (
	"github.com/bitstored/auth-service/errors"
	"github.com/dgrijalva/jwt-go"
	"github.com/mitchellh/mapstructure"
	"time"
)

type Identity struct {
	UserID    string
	FistName  string
	LastName  string
	IsAdmin   bool
	IsBlocked bool
}

type AccountStatus int

const (
	validToken AccountStatus = iota
	notFoundAccount
	expiredToken
	blockedAccount
	invalidToken
)
const (
	gRPCPortUser = "localhost:4008"
)

func (s *AuthService) validateToken(token *jwt.Token) AccountStatus {
	claims := new(CustomClaims)
	err := mapstructure.Decode(token.Claims, claims)
	if err != nil {
		return invalidToken
	}
	userID := UserID(claims.Issuer)
	tokens, ok := s.Tokens[userID]

	if !ok {
		if att, ok := s.Attempts[userID]; !ok {
			s.Attempts[userID] = 1
		} else {
			if att == maxAttempts {
				return blockedAccount
			}
			s.Attempts[userID] = att + 1
		}
	}

	for _, t := range tokens {
		tStr, _ := t.SignedString(mySigningKey)
		tokenStr, _ := token.SignedString(mySigningKey)
		if tStr == tokenStr {
			c := new(CustomClaims)
			_ = mapstructure.Decode(token.Claims, c)
			if c.StandardClaims.ExpiresAt < time.Now().Unix() {
				return expiredToken
			}
			return validToken
		}
	}

	if att, ok := s.Attempts[userID]; !ok {
		s.Attempts[userID] = 1
	} else {
		if att == maxAttempts {
			return blockedAccount
		}
		s.Attempts[userID] = att + 1
	}
	return notFoundAccount
}

func (s *AuthService) registerToken(token *jwt.Token) error {
	claims, ok := token.Claims.(CustomClaims)
	if !ok {
		return errors.NewError(errors.ErrKindInvalidJWTToken, "unable to parse jwt token").Error()
	}
	userID := UserID(claims.Id)
	if _, ok := s.Tokens[userID]; ok {
		s.Tokens[userID] = append(s.Tokens[userID], token)
	} else {
		s.Tokens[userID] = []*jwt.Token{token}
	}
	return nil
}
