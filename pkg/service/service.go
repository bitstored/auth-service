package service

import (
	"fmt"
	"github.com/bitstored/auth-service/errors"
	jwt "github.com/dgrijalva/jwt-go"
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
	mySigningKey = []byte("This is a very long and complicated signing key, home this will take 1000 years to be broken")
)

type CustomClaims struct {
	IsAdmin   bool   `json:"is_admin"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	jwt.StandardClaims
}

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

	claims := CustomClaims{
		isAdmin,
		firsname,
		lastname,
		jwt.StandardClaims{
			ExpiresAt: time.Now().Add(expirationTime).Unix(),
			Issuer:    userID,
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)

	tokenString, err := token.SignedString(mySigningKey)
	fmt.Printf("Token %v String %s Err %v", token, tokenString, err)
	return nil, tokenString
}

func (s *AuthService) ValidateJWTToken(tokenString string, userID string, firsname, lastname string, isAdmin bool) (bool, *errors.Err) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return false, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
		return []byte(mySigningKey), nil
	})
	if err != nil {
		return false, errors.NewError(errors.ErrKindInvalidJWTToken, err.Error())
	}
	if claims, ok := token.Claims.(CustomClaims); ok && token.Valid {

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

		uid := claims.Id
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
	return false, errors.NewError(errors.ErrKindInvalidJWTToken, err.Error())
}
