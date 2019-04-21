package service

import (
	"fmt"
	"github.com/bitstored/auth-service/errors"
	jwt "github.com/dgrijalva/jwt-go"
	"time"
)

const (
	mySigningKey   string = "This is a very long and complicated signing key, home this will take 1000 years to be broken"
	expirationTime        = time.Hour * 24
	userIdKey             = "user_id"
	isAdminKey            = "is_admin"
	firstNameKey          = "first_name"
	lastNameKey           = "last_name"
	expirationKey         = "exp"
	maxAttempts           = 3
)

type UserID string

type AuthService struct {
	Tokens   map[UserID][]*jwt.Token
	Attempts map[UserID]int
}

func NewAuthService() *AuthService {
	return &AuthService{}
}

func (s *AuthService) GenerateJWTToken(userID string) (*errors.Err, string) {
	/* Create the token */
	identity, err := s.getIdentityByID(userID)
	if err != nil {
		return err, ""
	}
	token := jwt.New(jwt.SigningMethodRS512)
	claims := token.Claims.(jwt.MapClaims)
	claims[userIdKey] = identity.UserID
	claims[isAdminKey] = identity.IsAdmin
	claims[firstNameKey] = identity.FistName
	claims[lastNameKey] = identity.LastName
	claims[expirationKey] = time.Now().Add(expirationTime).Unix()
	tokenString, _ := token.SignedString(mySigningKey)

	return nil, tokenString
}

func (s *AuthService) ValidateJWTToken(tokenString string) (*Identity, *errors.Err) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
		return []byte(mySigningKey), nil
	})
	if err != nil {
		return nil, errors.NewError(errors.ErrKindInvalidJWTToken, err.Error())
	}
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		uid := claims[userIdKey].(string)
		identity, err := s.getIdentityByID(uid)
		if err != nil {
			return nil, err
		}

		status := s.validateToken(token)
		if status == notFoundAccount {
			return nil, errors.NewError(errors.ErrKindInvalidJWTToken, "account/token not found")
		}
		if status == expiredToken {
			return nil, errors.NewError(errors.ErrKindTokenExpired, "token expired")
		}
		if status == blockedAccount {
			return nil, errors.NewError(errors.ErrKindAccountLocked, "account is locked")
		}
		if status == invalidToken {
			return nil, errors.NewError(errors.ErrKindInvalidJWTToken, "token is invalid")
		}
		isAdmin, ok := claims[isAdminKey].(bool)
		if !ok || isAdmin != identity.IsAdmin {
			return nil, errors.NewError(errors.ErrKindInvalidJWTToken, "token is invalid, data doen't match")
		}
		fistName, ok := claims[firstNameKey].(string)
		if !ok || fistName != identity.FistName {
			return nil, errors.NewError(errors.ErrKindInvalidJWTToken, "token is invalid, data doen't match")
		}
		lastName, ok := claims[lastNameKey].(string)
		if !ok || lastName != identity.LastName {
			return nil, errors.NewError(errors.ErrKindInvalidJWTToken, "token is invalid, data doen't match")
		}
		expTime, ok := claims[expirationKey].(time.Time)
		if !ok || expTime.After(time.Now()) {
			return nil, errors.NewError(errors.ErrKindInvalidJWTToken, "token is invalid, data doen't match")
		}
		return identity, nil
	}
	return nil, errors.NewError(errors.ErrKindInvalidJWTToken, err.Error())
}
