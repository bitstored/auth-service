package server_test

import (
	"context"
	"github.com/stretchr/testify/require"
	"reflect"
	"testing"

	"github.com/bitstored/auth-service/pb"
	"github.com/bitstored/auth-service/pkg/server"
	"github.com/bitstored/auth-service/pkg/service"
)

var Service = service.NewAuthService()
var Server = server.NewServer(Service)

func TestAuthServer_ValidatePassword(t *testing.T) {
	type fields struct {
		service *service.AuthService
	}
	type args struct {
		ctx context.Context
		in  *pb.ValidatePasswordRequest
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *pb.ValidatePasswordResponse
		wantErr bool
	}{
		{
			name: "Password Valid",
			fields: fields{
				service: Service,
			},
			args: args{
				ctx: context.Background(),
				in: &pb.ValidatePasswordRequest{
					Password: "AnaAre2Mere!",
				},
			},
			want: &pb.ValidatePasswordResponse{
				IsValid:         true,
				ResponseCode:    0,
				ResponseMessage: "",
			},
			wantErr: false,
		},
		{
			name: "Password Short",
			fields: fields{
				service: Service,
			},
			args: args{
				ctx: context.Background(),
				in: &pb.ValidatePasswordRequest{
					Password: "ana",
				},
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "Password No digit",
			fields: fields{
				service: Service,
			},
			args: args{
				ctx: context.Background(),
				in: &pb.ValidatePasswordRequest{
					Password: "AnaAreMar!",
				},
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "Password No Upper case",
			fields: fields{
				service: Service,
			},
			args: args{
				ctx: context.Background(),
				in: &pb.ValidatePasswordRequest{
					Password: "anaare1mar!",
				},
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "Password No Symbol",
			fields: fields{
				service: Service,
			},
			args: args{
				ctx: context.Background(),
				in: &pb.ValidatePasswordRequest{
					Password: "Anaare2Mere",
				},
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "Password Long",
			fields: fields{
				service: Service,
			},
			args: args{
				ctx: context.Background(),
				in: &pb.ValidatePasswordRequest{
					Password: "AnaAre333Mere!AnaAre333MereAnaAre333MereAnaAre333MereAnaAre333MereAnaAre333MereAnaAre333MereAnaAre333MereAnaAre333MereAnaAre333MereAnaAre333MereAnaAre333MereAnaAre333MereAnaAre333MereAnaAre333MereAnaAre333MereAnaAre333MereAnaAre333Mere",
				},
			},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &server.AuthServer{
				Service: tt.fields.service,
			}
			got, err := s.ValidatePassword(tt.args.ctx, tt.args.in)
			if (err != nil) != tt.wantErr {
				t.Errorf("AuthServer.ValidatePassword() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("AuthServer.ValidatePassword() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAuthServer_ValidateEmail(t *testing.T) {
	type fields struct {
		service *service.AuthService
	}
	type args struct {
		ctx context.Context
		in  *pb.ValidateEmailRequest
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *pb.ValidateEmailResponse
		wantErr bool
	}{
		{
			name: "Test Valid",
			fields: fields{
				service: Service,
			},
			args: args{
				ctx: context.Background(),
				in: &pb.ValidateEmailRequest{
					Email: "johndoe@gmail.com",
				},
			},
			want: &pb.ValidateEmailResponse{
				IsValid:         true,
				ResponseCode:    0,
				ResponseMessage: "",
			},
			wantErr: false,
		},
		{
			name: "Test Valid Point",
			fields: fields{
				service: Service,
			},
			args: args{
				ctx: context.Background(),
				in: &pb.ValidateEmailRequest{
					Email: "john.doe@gmail.com",
				},
			},
			want: &pb.ValidateEmailResponse{
				IsValid:         true,
				ResponseCode:    0,
				ResponseMessage: "",
			},
			wantErr: false,
		},
		{
			name: "Test Valid Digit",
			fields: fields{
				service: Service,
			},
			args: args{
				ctx: context.Background(),
				in: &pb.ValidateEmailRequest{
					Email: "john.doe1@gmail.com",
				},
			},
			want: &pb.ValidateEmailResponse{
				IsValid:         true,
				ResponseCode:    0,
				ResponseMessage: "",
			},
			wantErr: false,
		},
		{
			name: "Test Valid Upper",
			fields: fields{
				service: Service,
			},
			args: args{
				ctx: context.Background(),
				in: &pb.ValidateEmailRequest{
					Email: "john.doe12@gmail.com",
				},
			},
			want: &pb.ValidateEmailResponse{
				IsValid:         true,
				ResponseCode:    0,
				ResponseMessage: "",
			},
			wantErr: false,
		},
		{
			name: "Test Invalid Missing Ending",
			fields: fields{
				service: Service,
			},
			args: args{
				ctx: context.Background(),
				in: &pb.ValidateEmailRequest{
					Email: "john.doe@gmail.",
				},
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "Test Invalid Missing Start",
			fields: fields{
				service: Service,
			},
			args: args{
				ctx: context.Background(),
				in: &pb.ValidateEmailRequest{
					Email: "@gmail.com",
				},
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "Test Invalid Missing @",
			fields: fields{
				service: Service,
			},
			args: args{
				ctx: context.Background(),
				in: &pb.ValidateEmailRequest{
					Email: "john.doegmail.rom",
				},
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "Test Invalid Missing Double @",
			fields: fields{
				service: Service,
			},
			args: args{
				ctx: context.Background(),
				in: &pb.ValidateEmailRequest{
					Email: "john.doe@gmail@com",
				},
			},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &server.AuthServer{
				Service: tt.fields.service,
			}
			got, err := s.ValidateEmail(tt.args.ctx, tt.args.in)
			if (err != nil) != tt.wantErr {
				t.Errorf("AuthServer.ValidateEmail() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("AuthServer.ValidateEmail() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAuthServer_GenerateJWT(t *testing.T) {
	type fields struct {
		service *service.AuthService
	}
	type args struct {
		ctx context.Context
		in  *pb.GenerateJWTRequest
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "Test Valid",
			fields: fields{
				service: Service,
			},
			args: args{
				ctx: context.Background(),
				in: &pb.GenerateJWTRequest{
					UserId:    "uid1",
					FirstName: "First",
					Lastname:  "Last",
					IsAdmin:   true,
				},
			},
			wantErr: false,
		},
		{
			name: "Test Valid",
			fields: fields{
				service: Service,
			},
			args: args{
				ctx: context.Background(),
				in: &pb.GenerateJWTRequest{
					UserId:    "uid1",
					FirstName: "First",
					Lastname:  "Last",
					IsAdmin:   false,
				},
			},
			wantErr: false,
		},
		{
			name: "Test Unicode",
			fields: fields{
				service: Service,
			},
			args: args{
				ctx: context.Background(),
				in: &pb.GenerateJWTRequest{
					UserId:    "©√©∆˙ˆ¬˜µ¬˚˙˙",
					FirstName: "",
					Lastname:  "",
					IsAdmin:   true,
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &server.AuthServer{
				Service: tt.fields.service,
			}
			_, err := s.GenerateJWT(tt.args.ctx, tt.args.in)
			if (err != nil) != tt.wantErr {
				t.Errorf("AuthServer.GenerateJWT() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

		})
	}
}

func TestAuthServer_ValidateJWT(t *testing.T) {
	response, err := Server.GenerateJWT(context.Background(), &pb.GenerateJWTRequest{
		UserId:    "uid1",
		FirstName: "First",
		Lastname:  "Last",
		IsAdmin:   true,
	})
	require.NoError(t, err)
	type fields struct {
		service *service.AuthService
	}
	type args struct {
		ctx context.Context
		in  *pb.ValidateJWTRequest
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *pb.ValidateJWTResponse
		wantErr bool
	}{
		{
			name: "Test Valid, token ok",
			fields: fields{
				service: Service,
			},
			args: args{
				ctx: context.Background(),
				in: &pb.ValidateJWTRequest{
					Token:     response.GetToken(),
					UserId:    "uid1",
					FirstName: "First",
					Lastname:  "Last",
					IsAdmin:   true,
				},
			},
			want: &pb.ValidateJWTResponse{
				IsValid: true,
				UserId:  "uid1",
				IsAdmin: true,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &server.AuthServer{
				Service: tt.fields.service,
			}
			got, err := s.ValidateJWT(tt.args.ctx, tt.args.in)
			if (err != nil) != tt.wantErr {
				t.Errorf("AuthServer.ValidateJWT() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("AuthServer.ValidateJWT() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewServer(t *testing.T) {
	type args struct {
		service *service.AuthService
	}
	tests := []struct {
		name string
		args args
		want *server.AuthServer
	}{
		{
			name: " nil",
			args: args{
				service: nil,
			},
			want: &server.AuthServer{
				Service: nil,
			},
		},
		{
			name: "Not nil",
			args: args{
				service: service.NewAuthService(),
			},
			want: &server.AuthServer{
				Service: service.NewAuthService(),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := server.NewServer(tt.args.service); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewServer() = %v, want %v", got, tt.want)
			}
		})
	}
}
