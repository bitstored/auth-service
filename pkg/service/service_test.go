package service

import (
	"reflect"
	"testing"

	"github.com/bitstored/auth-service/errors"
)

func TestNewAuthService(t *testing.T) {
	tests := []struct {
		name string
		want *AuthService
	}{
		name: "Ok",
		want: &AuthService{
			Tokens: make(map[UserID][]*Token, 0),
			
		}
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewAuthService(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewAuthService() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAuthService_GenerateJWTToken(t *testing.T) {
	type args struct {
		userID   string
		firsname string
		lastname string
		isAdmin  bool
	}
	tests := []struct {
		name  string
		args  args
		want  *errors.Err
		want1 string
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewAuthService()

			got, got1 := s.GenerateJWTToken(tt.args.userID, tt.args.firsname, tt.args.lastname, tt.args.isAdmin)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("AuthService.GenerateJWTToken() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("AuthService.GenerateJWTToken() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func TestAuthService_ValidateJWTToken(t *testing.T) {

	type args struct {
		tokenString string
		userID      string
		firsname    string
		lastname    string
		isAdmin     bool
	}
	tests := []struct {
		name  string
		args  args
		want  bool
		want1 *errors.Err
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewAuthService()
			got, got1 := s.ValidateJWTToken(tt.args.tokenString, tt.args.userID, tt.args.firsname, tt.args.lastname, tt.args.isAdmin)
			if got != tt.want {
				t.Errorf("AuthService.ValidateJWTToken() got = %v, want %v", got, tt.want)
			}
			if !reflect.DeepEqual(got1, tt.want1) {
				t.Errorf("AuthService.ValidateJWTToken() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}
