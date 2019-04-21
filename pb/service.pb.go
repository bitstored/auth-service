// Code generated by protoc-gen-go. DO NOT EDIT.
// source: service.proto

package pb

import (
	context "context"
	fmt "fmt"
	proto "github.com/golang/protobuf/proto"
	_ "google.golang.org/genproto/googleapis/api/annotations"
	grpc "google.golang.org/grpc"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion3 // please upgrade the proto package

type ValidatePasswordRequest struct {
	Password             string   `protobuf:"bytes,1,opt,name=password,proto3" json:"password,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *ValidatePasswordRequest) Reset()         { *m = ValidatePasswordRequest{} }
func (m *ValidatePasswordRequest) String() string { return proto.CompactTextString(m) }
func (*ValidatePasswordRequest) ProtoMessage()    {}
func (*ValidatePasswordRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_a0b84a42fa06f626, []int{0}
}

func (m *ValidatePasswordRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ValidatePasswordRequest.Unmarshal(m, b)
}
func (m *ValidatePasswordRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ValidatePasswordRequest.Marshal(b, m, deterministic)
}
func (m *ValidatePasswordRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ValidatePasswordRequest.Merge(m, src)
}
func (m *ValidatePasswordRequest) XXX_Size() int {
	return xxx_messageInfo_ValidatePasswordRequest.Size(m)
}
func (m *ValidatePasswordRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_ValidatePasswordRequest.DiscardUnknown(m)
}

var xxx_messageInfo_ValidatePasswordRequest proto.InternalMessageInfo

func (m *ValidatePasswordRequest) GetPassword() string {
	if m != nil {
		return m.Password
	}
	return ""
}

type ValidatePasswordResponse struct {
	ResponseCode         int32    `protobuf:"varint,1,opt,name=response_code,json=responseCode,proto3" json:"response_code,omitempty"`
	ResponseMessage      string   `protobuf:"bytes,2,opt,name=response_message,json=responseMessage,proto3" json:"response_message,omitempty"`
	IsValid              string   `protobuf:"bytes,3,opt,name=is_valid,json=isValid,proto3" json:"is_valid,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *ValidatePasswordResponse) Reset()         { *m = ValidatePasswordResponse{} }
func (m *ValidatePasswordResponse) String() string { return proto.CompactTextString(m) }
func (*ValidatePasswordResponse) ProtoMessage()    {}
func (*ValidatePasswordResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_a0b84a42fa06f626, []int{1}
}

func (m *ValidatePasswordResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ValidatePasswordResponse.Unmarshal(m, b)
}
func (m *ValidatePasswordResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ValidatePasswordResponse.Marshal(b, m, deterministic)
}
func (m *ValidatePasswordResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ValidatePasswordResponse.Merge(m, src)
}
func (m *ValidatePasswordResponse) XXX_Size() int {
	return xxx_messageInfo_ValidatePasswordResponse.Size(m)
}
func (m *ValidatePasswordResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_ValidatePasswordResponse.DiscardUnknown(m)
}

var xxx_messageInfo_ValidatePasswordResponse proto.InternalMessageInfo

func (m *ValidatePasswordResponse) GetResponseCode() int32 {
	if m != nil {
		return m.ResponseCode
	}
	return 0
}

func (m *ValidatePasswordResponse) GetResponseMessage() string {
	if m != nil {
		return m.ResponseMessage
	}
	return ""
}

func (m *ValidatePasswordResponse) GetIsValid() string {
	if m != nil {
		return m.IsValid
	}
	return ""
}

type ValidateEmailRequest struct {
	Email                string   `protobuf:"bytes,1,opt,name=email,proto3" json:"email,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *ValidateEmailRequest) Reset()         { *m = ValidateEmailRequest{} }
func (m *ValidateEmailRequest) String() string { return proto.CompactTextString(m) }
func (*ValidateEmailRequest) ProtoMessage()    {}
func (*ValidateEmailRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_a0b84a42fa06f626, []int{2}
}

func (m *ValidateEmailRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ValidateEmailRequest.Unmarshal(m, b)
}
func (m *ValidateEmailRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ValidateEmailRequest.Marshal(b, m, deterministic)
}
func (m *ValidateEmailRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ValidateEmailRequest.Merge(m, src)
}
func (m *ValidateEmailRequest) XXX_Size() int {
	return xxx_messageInfo_ValidateEmailRequest.Size(m)
}
func (m *ValidateEmailRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_ValidateEmailRequest.DiscardUnknown(m)
}

var xxx_messageInfo_ValidateEmailRequest proto.InternalMessageInfo

func (m *ValidateEmailRequest) GetEmail() string {
	if m != nil {
		return m.Email
	}
	return ""
}

type ValidateEmailResponse struct {
	ResponseCode         int32    `protobuf:"varint,1,opt,name=response_code,json=responseCode,proto3" json:"response_code,omitempty"`
	ResponseMessage      string   `protobuf:"bytes,2,opt,name=response_message,json=responseMessage,proto3" json:"response_message,omitempty"`
	IsValid              string   `protobuf:"bytes,3,opt,name=is_valid,json=isValid,proto3" json:"is_valid,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *ValidateEmailResponse) Reset()         { *m = ValidateEmailResponse{} }
func (m *ValidateEmailResponse) String() string { return proto.CompactTextString(m) }
func (*ValidateEmailResponse) ProtoMessage()    {}
func (*ValidateEmailResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_a0b84a42fa06f626, []int{3}
}

func (m *ValidateEmailResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ValidateEmailResponse.Unmarshal(m, b)
}
func (m *ValidateEmailResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ValidateEmailResponse.Marshal(b, m, deterministic)
}
func (m *ValidateEmailResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ValidateEmailResponse.Merge(m, src)
}
func (m *ValidateEmailResponse) XXX_Size() int {
	return xxx_messageInfo_ValidateEmailResponse.Size(m)
}
func (m *ValidateEmailResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_ValidateEmailResponse.DiscardUnknown(m)
}

var xxx_messageInfo_ValidateEmailResponse proto.InternalMessageInfo

func (m *ValidateEmailResponse) GetResponseCode() int32 {
	if m != nil {
		return m.ResponseCode
	}
	return 0
}

func (m *ValidateEmailResponse) GetResponseMessage() string {
	if m != nil {
		return m.ResponseMessage
	}
	return ""
}

func (m *ValidateEmailResponse) GetIsValid() string {
	if m != nil {
		return m.IsValid
	}
	return ""
}

type GenerateJWTRequest struct {
	UserID               string   `protobuf:"bytes,1,opt,name=userID,proto3" json:"userID,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *GenerateJWTRequest) Reset()         { *m = GenerateJWTRequest{} }
func (m *GenerateJWTRequest) String() string { return proto.CompactTextString(m) }
func (*GenerateJWTRequest) ProtoMessage()    {}
func (*GenerateJWTRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_a0b84a42fa06f626, []int{4}
}

func (m *GenerateJWTRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_GenerateJWTRequest.Unmarshal(m, b)
}
func (m *GenerateJWTRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_GenerateJWTRequest.Marshal(b, m, deterministic)
}
func (m *GenerateJWTRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_GenerateJWTRequest.Merge(m, src)
}
func (m *GenerateJWTRequest) XXX_Size() int {
	return xxx_messageInfo_GenerateJWTRequest.Size(m)
}
func (m *GenerateJWTRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_GenerateJWTRequest.DiscardUnknown(m)
}

var xxx_messageInfo_GenerateJWTRequest proto.InternalMessageInfo

func (m *GenerateJWTRequest) GetUserID() string {
	if m != nil {
		return m.UserID
	}
	return ""
}

type GenerateJWTResponse struct {
	ResponseCode         int32    `protobuf:"varint,1,opt,name=response_code,json=responseCode,proto3" json:"response_code,omitempty"`
	ResponseMessage      string   `protobuf:"bytes,2,opt,name=response_message,json=responseMessage,proto3" json:"response_message,omitempty"`
	Token                string   `protobuf:"bytes,3,opt,name=token,proto3" json:"token,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *GenerateJWTResponse) Reset()         { *m = GenerateJWTResponse{} }
func (m *GenerateJWTResponse) String() string { return proto.CompactTextString(m) }
func (*GenerateJWTResponse) ProtoMessage()    {}
func (*GenerateJWTResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_a0b84a42fa06f626, []int{5}
}

func (m *GenerateJWTResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_GenerateJWTResponse.Unmarshal(m, b)
}
func (m *GenerateJWTResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_GenerateJWTResponse.Marshal(b, m, deterministic)
}
func (m *GenerateJWTResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_GenerateJWTResponse.Merge(m, src)
}
func (m *GenerateJWTResponse) XXX_Size() int {
	return xxx_messageInfo_GenerateJWTResponse.Size(m)
}
func (m *GenerateJWTResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_GenerateJWTResponse.DiscardUnknown(m)
}

var xxx_messageInfo_GenerateJWTResponse proto.InternalMessageInfo

func (m *GenerateJWTResponse) GetResponseCode() int32 {
	if m != nil {
		return m.ResponseCode
	}
	return 0
}

func (m *GenerateJWTResponse) GetResponseMessage() string {
	if m != nil {
		return m.ResponseMessage
	}
	return ""
}

func (m *GenerateJWTResponse) GetToken() string {
	if m != nil {
		return m.Token
	}
	return ""
}

type ValidateJWTRequest struct {
	Token                string   `protobuf:"bytes,1,opt,name=token,proto3" json:"token,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *ValidateJWTRequest) Reset()         { *m = ValidateJWTRequest{} }
func (m *ValidateJWTRequest) String() string { return proto.CompactTextString(m) }
func (*ValidateJWTRequest) ProtoMessage()    {}
func (*ValidateJWTRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_a0b84a42fa06f626, []int{6}
}

func (m *ValidateJWTRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ValidateJWTRequest.Unmarshal(m, b)
}
func (m *ValidateJWTRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ValidateJWTRequest.Marshal(b, m, deterministic)
}
func (m *ValidateJWTRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ValidateJWTRequest.Merge(m, src)
}
func (m *ValidateJWTRequest) XXX_Size() int {
	return xxx_messageInfo_ValidateJWTRequest.Size(m)
}
func (m *ValidateJWTRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_ValidateJWTRequest.DiscardUnknown(m)
}

var xxx_messageInfo_ValidateJWTRequest proto.InternalMessageInfo

func (m *ValidateJWTRequest) GetToken() string {
	if m != nil {
		return m.Token
	}
	return ""
}

type ValidateJWTResponse struct {
	ResponseCode         int32    `protobuf:"varint,1,opt,name=response_code,json=responseCode,proto3" json:"response_code,omitempty"`
	ResponseMessage      string   `protobuf:"bytes,2,opt,name=response_message,json=responseMessage,proto3" json:"response_message,omitempty"`
	IsValid              string   `protobuf:"bytes,3,opt,name=is_valid,json=isValid,proto3" json:"is_valid,omitempty"`
	IsAdmin              string   `protobuf:"bytes,4,opt,name=is_admin,json=isAdmin,proto3" json:"is_admin,omitempty"`
	UserId               string   `protobuf:"bytes,5,opt,name=user_id,json=userId,proto3" json:"user_id,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *ValidateJWTResponse) Reset()         { *m = ValidateJWTResponse{} }
func (m *ValidateJWTResponse) String() string { return proto.CompactTextString(m) }
func (*ValidateJWTResponse) ProtoMessage()    {}
func (*ValidateJWTResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_a0b84a42fa06f626, []int{7}
}

func (m *ValidateJWTResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ValidateJWTResponse.Unmarshal(m, b)
}
func (m *ValidateJWTResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ValidateJWTResponse.Marshal(b, m, deterministic)
}
func (m *ValidateJWTResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ValidateJWTResponse.Merge(m, src)
}
func (m *ValidateJWTResponse) XXX_Size() int {
	return xxx_messageInfo_ValidateJWTResponse.Size(m)
}
func (m *ValidateJWTResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_ValidateJWTResponse.DiscardUnknown(m)
}

var xxx_messageInfo_ValidateJWTResponse proto.InternalMessageInfo

func (m *ValidateJWTResponse) GetResponseCode() int32 {
	if m != nil {
		return m.ResponseCode
	}
	return 0
}

func (m *ValidateJWTResponse) GetResponseMessage() string {
	if m != nil {
		return m.ResponseMessage
	}
	return ""
}

func (m *ValidateJWTResponse) GetIsValid() string {
	if m != nil {
		return m.IsValid
	}
	return ""
}

func (m *ValidateJWTResponse) GetIsAdmin() string {
	if m != nil {
		return m.IsAdmin
	}
	return ""
}

func (m *ValidateJWTResponse) GetUserId() string {
	if m != nil {
		return m.UserId
	}
	return ""
}

func init() {
	proto.RegisterType((*ValidatePasswordRequest)(nil), "auth_service.ValidatePasswordRequest")
	proto.RegisterType((*ValidatePasswordResponse)(nil), "auth_service.ValidatePasswordResponse")
	proto.RegisterType((*ValidateEmailRequest)(nil), "auth_service.ValidateEmailRequest")
	proto.RegisterType((*ValidateEmailResponse)(nil), "auth_service.ValidateEmailResponse")
	proto.RegisterType((*GenerateJWTRequest)(nil), "auth_service.GenerateJWTRequest")
	proto.RegisterType((*GenerateJWTResponse)(nil), "auth_service.GenerateJWTResponse")
	proto.RegisterType((*ValidateJWTRequest)(nil), "auth_service.ValidateJWTRequest")
	proto.RegisterType((*ValidateJWTResponse)(nil), "auth_service.ValidateJWTResponse")
}

func init() { proto.RegisterFile("service.proto", fileDescriptor_a0b84a42fa06f626) }

var fileDescriptor_a0b84a42fa06f626 = []byte{
	// 468 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xc4, 0x94, 0xdf, 0x8a, 0xd3, 0x40,
	0x14, 0xc6, 0x49, 0x6d, 0x76, 0xd7, 0xb3, 0x5b, 0x5c, 0x66, 0xab, 0x1b, 0xe3, 0x1f, 0xea, 0x14,
	0x17, 0x15, 0x69, 0x50, 0xf1, 0x01, 0xd6, 0x3f, 0x88, 0x82, 0x20, 0x55, 0x14, 0xbc, 0x09, 0xb3,
	0x9b, 0x43, 0x76, 0xb0, 0xcd, 0xc4, 0xcc, 0x24, 0x7b, 0x21, 0xde, 0x14, 0xbc, 0xd0, 0x5b, 0x5f,
	0xc5, 0x37, 0xf1, 0x15, 0x7c, 0x10, 0xc9, 0x64, 0xa6, 0x26, 0x69, 0x8d, 0x57, 0xea, 0x5d, 0xcf,
	0x99, 0xdf, 0xf4, 0xfb, 0xe6, 0xf0, 0x9d, 0xc0, 0x40, 0x62, 0x56, 0xf0, 0x63, 0x9c, 0xa4, 0x99,
	0x50, 0x82, 0xec, 0xb0, 0x5c, 0x9d, 0x84, 0xa6, 0xe7, 0x5f, 0x8e, 0x85, 0x88, 0x67, 0x18, 0xb0,
	0x94, 0x07, 0x2c, 0x49, 0x84, 0x62, 0x8a, 0x8b, 0x44, 0x56, 0x2c, 0xbd, 0x0f, 0xfb, 0xaf, 0xd9,
	0x8c, 0x47, 0x4c, 0xe1, 0x0b, 0x26, 0xe5, 0xa9, 0xc8, 0xa2, 0x29, 0xbe, 0xcf, 0x51, 0x2a, 0xe2,
	0xc3, 0x56, 0x6a, 0x5a, 0x9e, 0x33, 0x72, 0x6e, 0x9c, 0x9d, 0x2e, 0x6b, 0xfa, 0xc9, 0x01, 0x6f,
	0xf5, 0x9e, 0x4c, 0x45, 0x22, 0x91, 0x8c, 0x61, 0x90, 0x99, 0xdf, 0xe1, 0xb1, 0x88, 0x50, 0xdf,
	0x76, 0xa7, 0x3b, 0xb6, 0xf9, 0x50, 0x44, 0x48, 0x6e, 0xc2, 0xee, 0x12, 0x9a, 0xa3, 0x94, 0x2c,
	0x46, 0xaf, 0xa7, 0x55, 0xce, 0xd9, 0xfe, 0xf3, 0xaa, 0x4d, 0x2e, 0xc2, 0x16, 0x97, 0x61, 0x51,
	0xca, 0x79, 0x67, 0x34, 0xb2, 0xc9, 0xa5, 0x56, 0xa7, 0xb7, 0x61, 0x68, 0x6d, 0x3c, 0x9e, 0x33,
	0x3e, 0xb3, 0xde, 0x87, 0xe0, 0x62, 0x59, 0x1b, 0xe3, 0x55, 0x41, 0x17, 0x0e, 0x9c, 0x6f, 0xe1,
	0xff, 0xc3, 0x32, 0x79, 0x82, 0x09, 0x66, 0x4c, 0xe1, 0xb3, 0x37, 0xaf, 0xac, 0xe1, 0x0b, 0xb0,
	0x91, 0x4b, 0xcc, 0x9e, 0x3e, 0x32, 0x8e, 0x4d, 0x45, 0x3f, 0xc0, 0x5e, 0x83, 0xfe, 0x4b, 0x7e,
	0x87, 0xe0, 0x2a, 0xf1, 0x0e, 0x13, 0x63, 0xb6, 0x2a, 0xe8, 0x2d, 0x20, 0x76, 0x5c, 0x35, 0xab,
	0x4b, 0xd6, 0xa9, 0xb3, 0xdf, 0x1c, 0xd8, 0x6b, 0xc0, 0xff, 0x7c, 0xb2, 0xe6, 0x88, 0x45, 0x73,
	0x9e, 0x78, 0x7d, 0x7b, 0x74, 0x58, 0x96, 0x64, 0x1f, 0x36, 0xcb, 0x81, 0x86, 0x3c, 0xf2, 0xdc,
	0xda, 0x7c, 0xa3, 0xbb, 0x5f, 0xfa, 0xb0, 0x7d, 0x98, 0xab, 0x93, 0x97, 0xd5, 0xb6, 0x90, 0xcf,
	0x0e, 0xec, 0xb6, 0x83, 0x4d, 0xae, 0x4f, 0xea, 0x1b, 0x35, 0xf9, 0xcd, 0xc2, 0xf8, 0x07, 0x7f,
	0xc2, 0xaa, 0x97, 0xd0, 0x83, 0xc5, 0xf7, 0x1f, 0x5f, 0x7b, 0x23, 0x72, 0x35, 0x28, 0x79, 0xbd,
	0x98, 0xc5, 0x9d, 0xc0, 0xee, 0x56, 0x50, 0x98, 0x7b, 0xe4, 0x23, 0x0c, 0x1a, 0x69, 0x25, 0x74,
	0xbd, 0x40, 0x3d, 0xf9, 0xfe, 0xb8, 0x93, 0x31, 0x0e, 0xc6, 0xda, 0xc1, 0x15, 0x72, 0xa9, 0xe1,
	0x40, 0x2f, 0xc9, 0x2f, 0xf9, 0x53, 0xd8, 0xae, 0x45, 0x8f, 0x8c, 0x9a, 0x7f, 0xbc, 0x9a, 0x61,
	0xff, 0x5a, 0x07, 0xd1, 0x29, 0xac, 0x13, 0x14, 0xc4, 0x86, 0x2f, 0x85, 0x6b, 0x49, 0x6a, 0x0b,
	0xaf, 0x26, 0xb2, 0x2d, 0xbc, 0x26, 0x86, 0x9d, 0xc2, 0xf6, 0xc5, 0x0f, 0xfa, 0x6f, 0x7b, 0xe9,
	0xd1, 0xd1, 0x86, 0xfe, 0x32, 0xde, 0xfb, 0x19, 0x00, 0x00, 0xff, 0xff, 0xe9, 0x1f, 0x4d, 0x62,
	0x56, 0x05, 0x00, 0x00,
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// AuthServiceClient is the client API for AuthService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type AuthServiceClient interface {
	ValidatePassword(ctx context.Context, in *ValidatePasswordRequest, opts ...grpc.CallOption) (*ValidatePasswordResponse, error)
	ValidateEmail(ctx context.Context, in *ValidateEmailRequest, opts ...grpc.CallOption) (*ValidateEmailResponse, error)
	GenerateJWT(ctx context.Context, in *GenerateJWTRequest, opts ...grpc.CallOption) (*GenerateJWTResponse, error)
	ValidateJWT(ctx context.Context, in *ValidateJWTRequest, opts ...grpc.CallOption) (*ValidateJWTResponse, error)
}

type authServiceClient struct {
	cc *grpc.ClientConn
}

func NewAuthServiceClient(cc *grpc.ClientConn) AuthServiceClient {
	return &authServiceClient{cc}
}

func (c *authServiceClient) ValidatePassword(ctx context.Context, in *ValidatePasswordRequest, opts ...grpc.CallOption) (*ValidatePasswordResponse, error) {
	out := new(ValidatePasswordResponse)
	err := c.cc.Invoke(ctx, "/auth_service.AuthService/ValidatePassword", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *authServiceClient) ValidateEmail(ctx context.Context, in *ValidateEmailRequest, opts ...grpc.CallOption) (*ValidateEmailResponse, error) {
	out := new(ValidateEmailResponse)
	err := c.cc.Invoke(ctx, "/auth_service.AuthService/ValidateEmail", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *authServiceClient) GenerateJWT(ctx context.Context, in *GenerateJWTRequest, opts ...grpc.CallOption) (*GenerateJWTResponse, error) {
	out := new(GenerateJWTResponse)
	err := c.cc.Invoke(ctx, "/auth_service.AuthService/GenerateJWT", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *authServiceClient) ValidateJWT(ctx context.Context, in *ValidateJWTRequest, opts ...grpc.CallOption) (*ValidateJWTResponse, error) {
	out := new(ValidateJWTResponse)
	err := c.cc.Invoke(ctx, "/auth_service.AuthService/ValidateJWT", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// AuthServiceServer is the server API for AuthService service.
type AuthServiceServer interface {
	ValidatePassword(context.Context, *ValidatePasswordRequest) (*ValidatePasswordResponse, error)
	ValidateEmail(context.Context, *ValidateEmailRequest) (*ValidateEmailResponse, error)
	GenerateJWT(context.Context, *GenerateJWTRequest) (*GenerateJWTResponse, error)
	ValidateJWT(context.Context, *ValidateJWTRequest) (*ValidateJWTResponse, error)
}

func RegisterAuthServiceServer(s *grpc.Server, srv AuthServiceServer) {
	s.RegisterService(&_AuthService_serviceDesc, srv)
}

func _AuthService_ValidatePassword_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ValidatePasswordRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AuthServiceServer).ValidatePassword(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/auth_service.AuthService/ValidatePassword",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AuthServiceServer).ValidatePassword(ctx, req.(*ValidatePasswordRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AuthService_ValidateEmail_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ValidateEmailRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AuthServiceServer).ValidateEmail(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/auth_service.AuthService/ValidateEmail",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AuthServiceServer).ValidateEmail(ctx, req.(*ValidateEmailRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AuthService_GenerateJWT_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GenerateJWTRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AuthServiceServer).GenerateJWT(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/auth_service.AuthService/GenerateJWT",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AuthServiceServer).GenerateJWT(ctx, req.(*GenerateJWTRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AuthService_ValidateJWT_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ValidateJWTRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AuthServiceServer).ValidateJWT(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/auth_service.AuthService/ValidateJWT",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AuthServiceServer).ValidateJWT(ctx, req.(*ValidateJWTRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _AuthService_serviceDesc = grpc.ServiceDesc{
	ServiceName: "auth_service.AuthService",
	HandlerType: (*AuthServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "ValidatePassword",
			Handler:    _AuthService_ValidatePassword_Handler,
		},
		{
			MethodName: "ValidateEmail",
			Handler:    _AuthService_ValidateEmail_Handler,
		},
		{
			MethodName: "GenerateJWT",
			Handler:    _AuthService_GenerateJWT_Handler,
		},
		{
			MethodName: "ValidateJWT",
			Handler:    _AuthService_ValidateJWT_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "service.proto",
}