// Code generated by protoc-gen-go. DO NOT EDIT.
// source: baap_meta.proto

/*
Package protos is a generated protocol buffer package.

It is generated from these files:
	baap_meta.proto

It has these top-level messages:
	Meta
*/
package protos

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

type Meta struct {
	Meta map[string][]byte `protobuf:"bytes,1,rep,name=meta" json:"meta,omitempty" protobuf_key:"bytes,1,opt,name=key" protobuf_val:"bytes,2,opt,name=value,proto3"`
}

func (m *Meta) Reset()                    { *m = Meta{} }
func (m *Meta) String() string            { return proto.CompactTextString(m) }
func (*Meta) ProtoMessage()               {}
func (*Meta) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{0} }

func (m *Meta) GetMeta() map[string][]byte {
	if m != nil {
		return m.Meta
	}
	return nil
}

func init() {
	proto.RegisterType((*Meta)(nil), "protos.Meta")
}

func init() { proto.RegisterFile("baap_meta.proto", fileDescriptor0) }

var fileDescriptor22 = []byte{
	// 135 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xe2, 0xe2, 0x4f, 0x4a, 0x4c, 0x2c,
	0x88, 0xcf, 0x4d, 0x2d, 0x49, 0xd4, 0x2b, 0x28, 0xca, 0x2f, 0xc9, 0x17, 0x62, 0x03, 0x53, 0xc5,
	0x4a, 0xd9, 0x5c, 0x2c, 0xbe, 0xa9, 0x25, 0x89, 0x42, 0x5a, 0x5c, 0x2c, 0x20, 0x59, 0x09, 0x46,
	0x05, 0x66, 0x0d, 0x6e, 0x23, 0x31, 0x88, 0xaa, 0x62, 0x3d, 0x90, 0x1c, 0x98, 0x70, 0xcd, 0x2b,
	0x29, 0xaa, 0x0c, 0x02, 0xab, 0x91, 0x32, 0xe7, 0xe2, 0x84, 0x0b, 0x09, 0x09, 0x70, 0x31, 0x67,
	0xa7, 0x56, 0x4a, 0x30, 0x2a, 0x30, 0x6a, 0x70, 0x06, 0x81, 0x98, 0x42, 0x22, 0x5c, 0xac, 0x65,
	0x89, 0x39, 0xa5, 0xa9, 0x12, 0x4c, 0x0a, 0x8c, 0x1a, 0x3c, 0x41, 0x10, 0x8e, 0x15, 0x93, 0x05,
	0xa3, 0x13, 0x47, 0x14, 0xd4, 0xda, 0x24, 0x08, 0x6d, 0x0c, 0x08, 0x00, 0x00, 0xff, 0xff, 0x78,
	0x82, 0xa5, 0xff, 0x98, 0x00, 0x00, 0x00,
}