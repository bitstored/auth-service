package service

import (
	"fmt"
	"github.com/bitstored/auth-service/errors"
	jwt "github.com/dgrijalva/jwt-go"
	"time"
)

const (
	mySigningKey   string = "This is a very long and complicated signing key, home this will take 1000 years to be broken"
	expirationTime        = time.Hour * 24 * 31
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

func (s *AuthService) GenerateJWTToken(userID string, firsname, lastname string, isAdmin bool) (*errors.Err, string) {
	/* Create the token */

	token := jwt.New(jwt.SigningMethodRS512)
	claims := token.Claims.(jwt.MapClaims)
	claims[userIdKey] = userID
	claims[isAdminKey] = isAdmin
	claims[firstNameKey] = firsname
	claims[lastNameKey] = lastname
	claims[expirationKey] = time.Now().Add(expirationTime).Unix()
	tokenString, _ := token.SignedString(mySigningKey)

	return nil, tokenString
}

func (s *AuthService) ValidateJWTToken(tokenString string, userID string, firsname, lastname string, isAdmin bool) (bool, *errors.Err) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return false, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
		return []byte(mySigningKey), nil
	})
	if err != nil {
		return false, errors.NewError(errors.ErrKindInvalidJWTToken, err.Error())
	}
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {

		status := s.validateToken(token)
		if status == notFoundAccount {
			return false, errors.NewError(errors.ErrKindInvalidJWTToken, "account/token not found")
		}
		if status == expiredToken {
			return false, errors.NewError(errors.ErrKindTokenExpired, "token expired")
		}
		if status == blockedAccount {
			return false, errors.NewError(errors.ErrKindAccountLocked, "account is locked")
		}
		if status == invalidToken {
			return false, errors.NewError(errors.ErrKindInvalidJWTToken, "token is invalid")
		}

		uid, ok := claims[userIdKey].(string)
		if !ok || uid != userID {
			return false, errors.NewError(errors.ErrKindInvalidJWTToken, "token is invalid, data doen't match")
		}
		isAdmin, ok := claims[isAdminKey].(bool)
		if !ok || isAdmin != isAdmin {
			return false, errors.NewError(errors.ErrKindInvalidJWTToken, "token is invalid, data doen't match")
		}
		fistName, ok := claims[firstNameKey].(string)
		if !ok || fistName != firsname {
			return false, errors.NewError(errors.ErrKindInvalidJWTToken, "token is invalid, data doen't match")
		}
		lastName, ok := claims[lastNameKey].(string)
		if !ok || lastName != lastname {
			return false, errors.NewError(errors.ErrKindInvalidJWTToken, "token is invalid, data doen't match")
		}
		expTime, ok := claims[expirationKey].(time.Time)
		if !ok || expTime.After(time.Now()) {
			return false, errors.NewError(errors.ErrKindInvalidJWTToken, "token is invalid, data doen't match")
		}
		return true, nil
	}
	return false, errors.NewError(errors.ErrKindInvalidJWTToken, err.Error())
}
