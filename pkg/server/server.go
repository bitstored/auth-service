package server

import (
	"context"
	"github.com/bitstored/auth-service/pb"
	"github.com/bitstored/auth-service/pkg/service"
	"github.com/bitstored/auth-service/pkg/validator"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	_ "strconv"
)

type AuthServer struct {
	Service *service.AuthService
}

func (s *AuthServer) ValidatePassword(ctx context.Context, in *pb.ValidatePasswordRequest) (*pb.ValidatePasswordResponse, error) {
	ok, err := validator.Password(in.Password)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Message())
	}
	return &pb.ValidatePasswordResponse{IsValid: ok}, nil
}

func (s *AuthServer) ValidateEmail(ctx context.Context, in *pb.ValidateEmailRequest) (*pb.ValidateEmailResponse, error) {
	ok := validator.Email(in.Email)
	if !ok {
		return nil, status.Error(codes.InvalidArgument, "not a valid email")
	}
	return &pb.ValidateEmailResponse{IsValid: ok}, nil
}

func (s *AuthServer) GenerateJWT(ctx context.Context, in *pb.GenerateJWTRequest) (*pb.GenerateJWTResponse, error) {
	err, token := s.Service.GenerateJWTToken(in.GetUserId(), in.GetFirstName(), in.GetLastname(), in.GetIsAdmin())
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
	ok, err := s.Service.ValidateJWTToken(token, in.GetUserId(), in.GetFirstName(), in.GetLastname(), in.GetIsAdmin())
	if err != nil || !ok {
		return nil, status.Error(codes.InvalidArgument, err.Message())
	}

	return &pb.ValidateJWTResponse{UserId: in.GetUserId(), IsAdmin: in.GetIsAdmin(), IsValid: ok}, nil
}

func NewServer(service *service.AuthService) *AuthServer {
	return &AuthServer{Service: service}
}
