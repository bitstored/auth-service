package service

import (
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/stretchr/testify/require"
	"reflect"
	"testing"

	"github.com/bitstored/auth-service/errors"
)

func TestNewAuthService(t *testing.T) {
	tests := []struct {
		name string
		want *AuthService
	}{
		{
			name: "Ok",
			want: &AuthService{
				Tokens:   make(map[UserID][]*jwt.Token, 0),
				Attempts: make(map[UserID]int, 0),
			},
		},
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
		name string
		args args
		want *errors.Err
	}{
		{
			name: "OK",
			args: args{
				userID:   "uid1",
				firsname: "First",
				lastname: "Last",
				isAdmin:  true,
			},
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewAuthService()

			got, got1 := s.GenerateJWTToken(tt.args.userID, tt.args.firsname, tt.args.lastname, tt.args.isAdmin)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("AuthService.GenerateJWTToken() got = %v, want %v", got, tt.want)
			}
			require.NotEmpty(t, got1)
			ok, err := s.ValidateJWTToken(got1, tt.args.userID, tt.args.firsname, tt.args.lastname, tt.args.isAdmin)
			require.Nil(t, err)

			require.True(t, ok)
		})
	}
}

func TestAuthService_ValidateJWTToken(t *testing.T) {
	s := NewAuthService()
	_, token := s.GenerateJWTToken("uid1", "First", "Last", true)
	_, token1 := s.GenerateJWTToken("uid1", "First2", "Last2", false)

	type args struct {
		tokenString string
		userID      string
		firsname    string
		lastname    string
		isAdmin     bool
	}
	tests := []struct {
		name    string
		args    args
		want    bool
		wantErr bool
	}{
		{
			name: "EmptyToken",
			args: args{
				tokenString: "",
				userID:      "uid1",
				firsname:    "First",
				lastname:    "Last",
				isAdmin:     true,
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "Wrong first name",
			args: args{
				tokenString: token,
				userID:      "uid1",
				firsname:    "The First",
				lastname:    "Last",
				isAdmin:     true,
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "Wrong lats name",
			args: args{
				tokenString: token,
				userID:      "uid1",
				firsname:    "First",
				lastname:    "Me Last",
				isAdmin:     true,
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "Wrong role",
			args: args{
				tokenString: token,
				userID:      "uid1",
				firsname:    "First",
				lastname:    "Last",
				isAdmin:     false,
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "Wrong uid",
			args: args{
				tokenString: token,
				userID:      "uiddddddd1",
				firsname:    "First",
				lastname:    "Last",
				isAdmin:     true,
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "Wrong token",
			args: args{
				tokenString: token1,
				userID:      "uid1",
				firsname:    "First",
				lastname:    "Last",
				isAdmin:     true,
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "Corrupted token",
			args: args{
				tokenString: "Corrupted" + token,
				userID:      "uid1",
				firsname:    "First",
				lastname:    "Last",
				isAdmin:     true,
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "OK",
			args: args{
				tokenString: token,
				userID:      "uid1",
				firsname:    "First",
				lastname:    "Last",
				isAdmin:     true,
			},
			want:    true,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1 := s.ValidateJWTToken(tt.args.tokenString, tt.args.userID, tt.args.firsname, tt.args.lastname, tt.args.isAdmin)

			if tt.wantErr && got1 == nil {
				t.Errorf("[%s] AuthService.ValidateJWTToken() got error = %v", tt.name, got1)
			}
			if got != tt.want {
				t.Errorf("[%s]AuthService.ValidateJWTToken() got = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}
