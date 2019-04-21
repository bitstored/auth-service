package server

import (
	"context"
	"github.com/bitstored/auth-service/pb"
	"github.com/bitstored/auth-service/pkg/service"
)

type AuthServer struct {
	service *service.AuthService
}

func (s *AuthServer) ValidatePassword(ctx context.Context, in *pb.ValidatePasswordRequest) (*pb.ValidatePasswordResponse, error) {
	return nil, nil
}
func (s *AuthServer) ValidateEmail(ctx context.Context, in *pb.ValidateEmailRequest) (*pb.ValidateEmailResponse, error) {
	return nil, nil
}
func (s *AuthServer) GenerateJWT(ctx context.Context, in *pb.GenerateJWTRequest) (*pb.GenerateJWTResponse, error) {
	return nil, nil
}
func (s *AuthServer) ValidateJWT(ctx context.Context, in *pb.ValidateJWTRequest) (*pb.ValidateJWTResponse, error) {
	return nil, nil
}

func NewServer(service *service.AuthService) *AuthServer {
	return &AuthServer{service}
}
