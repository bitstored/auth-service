package service

import (
	"fmt"
	jwt "github.com/dgrijalva/jwt-go"
	"time"
)

const (
	mySigningKey   string = "This is a very long and complicated signing key, home this will take 1000 years to be broken"
	expirationTime        = time.Hour * 24
)

type AuthService struct {
}

func (s *AuthService) GenerateJWTToken(userID string) (error, string) {
	/* Create the token */
	identity, err := s.GetIdentityByID(userID)
	if err != nil {
		return err, ""
	}
	token := jwt.New(jwt.SigningMethodRS512)
	claims := token.Claims.(jwt.MapClaims)
	claims["userid"] = identity.UserID
	claims["admin"] = identity.IsAdmin
	claims["first_name"] = identity.FistName
	claims["last_name"] = identity.LastName
	claims["exp"] = time.Now().Add(expirationTime).Unix()
	tokenString, _ := token.SignedString(mySigningKey)

	return nil, tokenString
}

func (s *AuthService) ValidateJWTToken(tokenString string) (*Identity, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
		return []byte(mySigningKey), nil
	})

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		uid := claims["userid"].(string)
		identity, err := s.GetIdentityByID(uid)
		if err != nil {
			return nil, err
		}
		isAdmin, ok := claims["admin"].(bool)
		if !ok || isAdmin != identity.IsAdmin {
			return nil, fmt.Errorf("token is invalid")
		}
		fistName, ok := claims["fist_name"].(string)
		if !ok || fistName != identity.FistName {
			return nil, fmt.Errorf("token is invalid")
		}
		lastName, ok := claims["last_name"].(string)
		if !ok || lastName != identity.LastName {
			return nil, fmt.Errorf("token is invalid")
		}
		expTime, ok := claims["exp"].(time.Time)
		if !ok || expTime.After(time.Now()) {
			return nil, fmt.Errorf("token is expired")
		}
		return identity, nil
	}
	return nil, err
}
