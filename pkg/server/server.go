package server

import (
	"context"
	"github.com/bitstored/auth-service/pb"
	"github.com/bitstored/auth-service/pkg/service"
	"github.com/bitstored/auth-service/pkg/validator"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"strconv"
)

type AuthServer struct {
	service *service.AuthService
}

func (s *AuthServer) ValidatePassword(ctx context.Context, in *pb.ValidatePasswordRequest) (*pb.ValidatePasswordResponse, error) {
	ok, err := validator.Password(in.Password)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Message())
	}
	return &pb.ValidatePasswordResponse{IsValid: strconv.FormatBool(ok)}, nil
}

func (s *AuthServer) ValidateEmail(ctx context.Context, in *pb.ValidateEmailRequest) (*pb.ValidateEmailResponse, error) {
	ok := validator.Email(in.Email)
	if !ok {
		return nil, status.Error(codes.InvalidArgument, "not a valid email")
	}
	return &pb.ValidateEmailResponse{IsValid: strconv.FormatBool(ok)}, nil
}

func (s *AuthServer) GenerateJWT(ctx context.Context, in *pb.GenerateJWTRequest) (*pb.GenerateJWTResponse, error) {
	err, token := s.service.GenerateJWTToken(in.GetUserID())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Message())
	}
	return &pb.GenerateJWTResponse{ResponseCode: 200, ResponseMessage: "token generated success", Token: token}, nil
}

func (s *AuthServer) ValidateJWT(ctx context.Context, in *pb.ValidateJWTRequest) (*pb.ValidateJWTResponse, error) {
	token := in.GetToken()
	if token == "" {
		return nil, status.Error(codes.InvalidArgument, "token to be validated is missing")
	}
	identity, err := s.service.ValidateJWTToken(token)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Message())
	}
	return &pb.ValidateJWTResponse{UserId: identity.UserID, IsAdmin: strconv.FormatBool(identity.IsAdmin)}, nil
}

func NewServer(service *service.AuthService) *AuthServer {
	return &AuthServer{service}
}
