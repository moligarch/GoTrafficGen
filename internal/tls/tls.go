package tls

import (
	"github.com/google/gopacket"
)

// MyTLSLayer is a custom TLS record layer.
// It produces a 5-byte TLS header followed by the payload in Data.
type MyTLSLayer struct {
	ContentType uint8  // e.g. 20,21,22,23,24
	Version     uint16 // e.g. 0x0303 for TLS1.2
	Data        []byte // payload
}

// Ensure MyTLSLayer satisfies gopacket interfaces.
var _ gopacket.Layer = (*MyTLSLayer)(nil)
var _ gopacket.SerializableLayer = (*MyTLSLayer)(nil)
var _ gopacket.ApplicationLayer = (*MyTLSLayer)(nil)

// LayerTypeMyTLS is the registered LayerType for MyTLSLayer.
var LayerTypeMyTLS = gopacket.RegisterLayerType(
	12345,
	gopacket.LayerTypeMetadata{
		Name:    "MyTLS",
		Decoder: gopacket.DecodeFunc(decodeMyTLS),
	},
)

func decodeMyTLS(data []byte, p gopacket.PacketBuilder) error {
	layer := &MyTLSLayer{Data: data}
	p.AddLayer(layer)
	p.SetApplicationLayer(layer)
	return nil
}

func (m *MyTLSLayer) LayerType() gopacket.LayerType { return LayerTypeMyTLS }
func (m *MyTLSLayer) LayerContents() []byte         { return m.serializeHeader() }
func (m *MyTLSLayer) LayerPayload() []byte          { return m.Data }
func (m *MyTLSLayer) Payload() []byte               { return m.Data }
func (m *MyTLSLayer) serializeHeader() []byte {
	hdr := make([]byte, 5)
	hdr[0] = m.ContentType
	hdr[1] = byte(m.Version >> 8)
	hdr[2] = byte(m.Version)
	hdr[3] = byte(len(m.Data) >> 8)
	hdr[4] = byte(len(m.Data))
	return hdr
}
func (m *MyTLSLayer) SerializeTo(buf gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	bytes, err := buf.PrependBytes(5 + len(m.Data))
	if err != nil {
		return err
	}
	copy(bytes, m.serializeHeader())
	copy(bytes[5:], m.Data)
	return nil
}

// Build creates a MyTLSLayer for the given record type.
// 22 → dummy "ClientHello", 23 → "TLSMSG", others → empty payload.
func Build(recordType int) *MyTLSLayer {
	var data []byte
	switch recordType {
	case 22:
		data = []byte("ClientHello")
	case 23:
		data = []byte("TLSMSG")
	default:
		data = nil
	}
	return &MyTLSLayer{
		ContentType: uint8(recordType),
		Version:     0x0303,
		Data:        data,
	}
}
