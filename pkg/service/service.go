package service

import (
	"fmt"
	"github.com/bitstored/auth-service/errors"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/mitchellh/mapstructure"

	"time"
)

const (
	expirationTime = time.Hour * 24 * 31
	userIdKey      = "user_id"
	isAdminKey     = "is_admin"
	firstNameKey   = "first_name"
	lastNameKey    = "last_name"
	expirationKey  = "exp"
	maxAttempts    = 3
)

var (
	mySigningKey = []byte("This is a very long and complicated signing key")
)

type CustomClaims struct {
	IsAdmin   bool   `json:"is_admin"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	*jwt.StandardClaims
}

type UserID string

type AuthService struct {
	Tokens   map[UserID][]*jwt.Token
	Attempts map[UserID]int
}

func NewAuthService() *AuthService {
	return &AuthService{
		make(map[UserID][]*jwt.Token, 0),
		make(map[UserID]int, 0),
	}
}

func (s *AuthService) GenerateJWTToken(userID string, firsname, lastname string, isAdmin bool) (*errors.Err, string) {
	/* Create the token */

	token := jwt.New(jwt.SigningMethodHS256)

	claims := &CustomClaims{
		IsAdmin:   isAdmin,
		FirstName: firsname,
		LastName:  lastname,
		StandardClaims: &jwt.StandardClaims{
			ExpiresAt: time.Now().Add(expirationTime).Unix(),
			Issuer:    userID,
		},
	}
	token.Claims = claims
	tokenString, err := token.SignedString(mySigningKey)
	if err != nil {
		return errors.NewError(errors.ErrKindAccountNotFound, err.Error()), ""
	}
	s.Tokens[UserID(userID)] = append(s.Tokens[UserID(userID)], token)
	return nil, tokenString
}

func (s *AuthService) ValidateJWTToken(tokenString string, userID string, firsname, lastname string, isAdmin bool) (bool, *errors.Err) {
	token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
		return mySigningKey, nil
	})
	if err != nil {
		return false, errors.NewError(errors.ErrKindInvalidJWTToken, err.Error())
	}
	if token.Valid {
		claims := new(CustomClaims)
		err := mapstructure.Decode(token.Claims, claims)
		if err != nil {
			return false, errors.NewError(errors.ErrKindInvalidJWTToken, err.Error())
		}
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

		uid := claims.Issuer
		if uid != userID {
			return false, errors.NewError(errors.ErrKindInvalidJWTToken, "token is invalid, data doen't match")
		}
		isAdmin := claims.IsAdmin
		if isAdmin != isAdmin {
			return false, errors.NewError(errors.ErrKindInvalidJWTToken, "token is invalid, data doen't match")
		}
		fistName := claims.FirstName
		if fistName != firsname {
			return false, errors.NewError(errors.ErrKindInvalidJWTToken, "token is invalid, data doen't match")
		}
		lastName := claims.LastName
		if lastName != lastname {
			return false, errors.NewError(errors.ErrKindInvalidJWTToken, "token is invalid, data doen't match")
		}
		expTime := claims.ExpiresAt
		if expTime < time.Now().Unix() {
			return false, errors.NewError(errors.ErrKindInvalidJWTToken, "token is invalid, data doen't match")
		}
		return true, nil
	}
	if err != nil {
		return false, errors.NewError(errors.ErrKindInvalidJWTToken, err.Error())
	}
	return false, errors.NewError(errors.ErrKindInvalidJWTToken, "Unable to parse")
}
