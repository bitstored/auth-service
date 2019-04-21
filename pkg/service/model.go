package service

import (
	"github.com/bitstored/auth-service/errors"
	"github.com/dgrijalva/jwt-go"
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

func (s *AuthService) getIdentityByID(uid string) (*Identity, *errors.Err) {
	return nil, errors.NewError(errors.ErrKindInvalidUserID, "unable to retrieve identity, invalid userID")
}

func (s *AuthService) validateToken(token *jwt.Token) AccountStatus {
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return invalidToken
	}
	userID := UserID(claims[userIdKey].(string))
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
		return notFoundAccount
	}

	for _, t := range tokens {
		tStr, _ := t.SignedString(mySigningKey)
		tokenStr, _ := token.SignedString(mySigningKey)
		if tStr == tokenStr {
			c := t.Claims.(jwt.MapClaims)
			if c[expirationKey].(time.Time).After(time.Now()) {
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
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return errors.NewError(errors.ErrKindInvalidJWTToken, "unable to parse jwt token").Error()
	}
	userID := UserID(claims[userIdKey].(string))
	if _, ok := s.Tokens[userID]; ok {
		s.Tokens[userID] = append(s.Tokens[userID], token)
	} else {
		s.Tokens[userID] = []*jwt.Token{token}
	}
	return nil
}
