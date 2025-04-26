package snmp

import (
	"fmt"
	"math/rand"
	"time"

	"github.com/gosnmp/gosnmp"
)

// GenerateSNMPPacket generates a properly encoded SNMP packet for the given request type and version.
// versionStr: "v1", "2c", "v3", or "unknown"; community: SNMP community string
// v3User, v3SecLevel, v3AuthProto, v3AuthPass, v3PrivProto, v3PrivPass: SNMPv3 params
func GenerateSNMPPacket(
	reqType, versionStr, community,
	v3User, v3SecLevel, v3AuthProto, v3AuthPass, v3PrivProto, v3PrivPass string,
) ([]byte, error) {
	// Determine SNMP version constant
	var version gosnmp.SnmpVersion
	switch versionStr {
	case "v1":
		version = gosnmp.Version1
	case "v2", "v2c":
		version = gosnmp.Version2c
	case "v3":
		version = gosnmp.Version3
	default:
		version = gosnmp.Version2c
		versionStr = "unknown"
	}

	packet := gosnmp.SnmpPacket{Version: version, Community: community}

	// SNMPv3 security parameters
	if version == gosnmp.Version3 {
		sp := &gosnmp.UsmSecurityParameters{UserName: v3User}
		// Auth protocol
		switch v3AuthProto {
		case "MD5":
			sp.AuthenticationProtocol = gosnmp.MD5
		case "SHA":
			sp.AuthenticationProtocol = gosnmp.SHA
		default:
			sp.AuthenticationProtocol = gosnmp.NoAuth
		}
		sp.AuthenticationPassphrase = v3AuthPass
		// Priv protocol
		switch v3PrivProto {
		case "DES":
			sp.PrivacyProtocol = gosnmp.DES
		case "AES":
			sp.PrivacyProtocol = gosnmp.AES
		default:
			sp.PrivacyProtocol = gosnmp.NoPriv
		}
		sp.PrivacyPassphrase = v3PrivPass
		packet.SecurityParameters = sp
		// MsgFlags
		switch v3SecLevel {
		case "noAuthNoPriv":
			packet.MsgFlags = gosnmp.NoAuthNoPriv
		case "authNoPriv":
			packet.MsgFlags = gosnmp.AuthNoPriv
		case "authPriv":
			packet.MsgFlags = gosnmp.AuthPriv
		default:
			return nil, fmt.Errorf("unknown SNMPv3 security level: %s", v3SecLevel)
		}
		packet.ContextEngineID = ""
		packet.ContextName = ""
	}

	switch reqType {
	case "get":
		packet.PDUType = gosnmp.GetRequest
		packet.RequestID = 1
		packet.Variables = []gosnmp.SnmpPDU{{Name: ".1.3.6.1.2.1.1.1.0", Type: gosnmp.Null}}

	case "getnext":
		packet.PDUType = gosnmp.GetNextRequest
		packet.RequestID = 1
		packet.Variables = []gosnmp.SnmpPDU{{Name: ".1.3.6.1.2.1.1.1.0", Type: gosnmp.Null}}

	case "set":
		packet.PDUType = gosnmp.SetRequest
		packet.RequestID = 1
		packet.Variables = []gosnmp.SnmpPDU{{Name: ".1.3.6.1.2.1.1.4.0", Type: gosnmp.OctetString, Value: "test"}}

	case "trap":
		if version == gosnmp.Version1 {
			packet.PDUType = gosnmp.Trap
			packet.Enterprise = ".1.3.6.1.4.1.8072.2.3"
			packet.AgentAddress = "0.0.0.0"
			packet.GenericTrap = 6
			packet.SpecificTrap = rand.Int()
			packet.Timestamp = uint(time.Now().Unix())
			packet.Variables = []gosnmp.SnmpPDU{{Name: ".1.3.6.1.2.1.1.1.0", Type: gosnmp.OctetString, Value: "SNMPv1 Trap"}}
		} else {
			packet.PDUType = gosnmp.SNMPv2Trap
			packet.RequestID = 1
			packet.Variables = []gosnmp.SnmpPDU{
				{Name: ".1.3.6.1.2.1.1.3.0", Type: gosnmp.TimeTicks, Value: uint32(12345)},
				{Name: ".1.3.6.1.6.3.1.1.4.1.0", Type: gosnmp.OctetString, Value: ".1.3.6.1.4.1.8072.2.3.0.1"},
				{Name: ".1.3.6.1.2.1.1.1.0", Type: gosnmp.OctetString, Value: "SNMP Trap"},
			}
		}

	case "getbulk":
		packet.PDUType = gosnmp.GetBulkRequest
		packet.RequestID = 1
		packet.NonRepeaters = 0
		packet.MaxRepetitions = 10
		packet.Variables = []gosnmp.SnmpPDU{{Name: ".1.3.6.1.2.1.1.1.0", Type: gosnmp.Null}}

	case "inform":
		packet.PDUType = gosnmp.InformRequest
		packet.RequestID = 1
		packet.Variables = []gosnmp.SnmpPDU{
			{Name: ".1.3.6.1.2.1.1.3.0", Type: gosnmp.TimeTicks, Value: uint32(12345)},
			{Name: ".1.3.6.1.6.3.1.1.4.1.0", Type: gosnmp.OctetString, Value: ".1.3.6.1.4.1.8072.2.3.0.1"},
			{Name: ".1.3.6.1.2.1.1.1.0", Type: gosnmp.OctetString, Value: "SNMP Inform"},
		}

	case "report":
		packet.PDUType = gosnmp.Report
		packet.RequestID = 1
		packet.Variables = []gosnmp.SnmpPDU{{Name: ".1.3.6.1.2.1.1.1.0", Type: gosnmp.OctetString, Value: "SNMP Report"}}

	default:
		return nil, fmt.Errorf("unsupported request type: %s", reqType)
	}

	// Marshal and patch unknown
	data, err := packet.MarshalMsg()
	if err != nil {
		return nil, err
	}
	if versionStr == "unknown" {
		if len(data) >= 5 {
			data[4] = byte(rand.Intn(98) + 4)
		}
	}
	return data, nil
}
