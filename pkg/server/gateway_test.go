package server

import (
	"context"
	"net/http"
	"reflect"
	"testing"

	"google.golang.org/grpc"
)

func TestNewGateway(t *testing.T) {
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
		// TODO:
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewGateway(tt.args.ctx, tt.args.conn)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewGateway() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewGateway() = %v, want %v", got, tt.want)
			}
		})
	}
}
