package server

import (
	"context"
	"net/http"
	"testing"

	"github.com/bitstored/auth-service/pb"
	gwruntime "github.com/grpc-ecosystem/grpc-gateway/runtime"
	"google.golang.org/grpc"
)

func TestNewGateway(t *testing.T) {
	mux := gwruntime.NewServeMux()
	var err error
	for _, f := range []func(context.Context, *gwruntime.ServeMux, *grpc.ClientConn) error{
		pb.RegisterAuthServiceHandler,
	} {
		err = f(context.TODO(), mux, nil)
	}
	type args struct {
		ctx  context.Context
		conn *grpc.ClientConn
	}
	tests := []struct {
		name    string
		args    args
		want    http.Handler
		wantErr bool
	}{
		{
			name: "Test fail",
			args: args{
				ctx:  context.TODO(),
				conn: nil,
			},
			want:    mux,
			wantErr: err != nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewGateway(tt.args.ctx, tt.args.conn)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewGateway() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got == nil {
				t.Errorf("NewGateway() = %v, want %v", got, tt.want)
			}
		})
	}
}
