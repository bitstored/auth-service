package service

import (
	"github.com/bitstored/auth-service/errors"
)

type Identity struct {
	UserID    string
	FistName  string
	LastName  string
	IsAdmin   bool
	IsBlocked bool
}

func (s *AuthService) getIdentityByID(uid string) (*Identity, error) {
	return nil, errors.NewError(errors.ErrKindInvalidUserID, "unable to retrieve identity, invalid userID").Error()
}

func (s *AuthService) validateTokenByUser(uid, token string) bool {
	return true
}
