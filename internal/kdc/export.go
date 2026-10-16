package kdc

import (
	"time"

	"openpak/x360-kdc/internal/der"
)

// Exported views of the Kerberos helpers the security gateway shares with the
// KDC: it parses the same AP-REQ, ticket and authenticator structures and
// verifies tickets this server issued, so the decoding lives in one place.

// Application tags of the structures inside an AP-REQ.
const (
	TagAPReq  = tagAPReq
	TagTicket = tagTicket
	TagAuth   = tagAuth
	TagEncTkt = tagEncTkt
)

// AP-REQ constants.
const (
	PVNO     = pvno
	MsgAPReq = msgAPReq
)

// AppSeqFields decodes [APPLICATION n] SEQUENCE { context fields }.
func AppSeqFields(b []byte, tag byte) (map[int]der.TLV, error) { return appSeqFields(b, tag) }

// EncryptedData decodes an etype-23 EncryptedData and returns its cipher.
func EncryptedData(b []byte) ([]byte, error) { return encryptedData(b) }

// EncodeEncryptedData is EncryptedData { [0] etype 23, [2] cipher }.
func EncodeEncryptedData(cipher []byte) []byte { return encEncryptedData(cipher) }

// Principal decodes a PrincipalName into its components.
func Principal(v der.TLV) ([]string, error) { return principal(v) }

// UintField reads an INTEGER context field.
func UintField(f map[int]der.TLV, n int) (uint64, error) { return uintField(f, n) }

// TimeField reads a GeneralizedTime context field.
func TimeField(f map[int]der.TLV, n int) (time.Time, error) { return timeField(f, n) }

// KeyValue reads EncryptionKey { [0] etype 23, [1] keyvalue[16] }.
func KeyValue(v der.TLV) ([]byte, error) { return keyValue(v) }

// SG service principal (sg/S0) the gateway ticket is issued for.
var SGService = []string{sgService, sgInstance}
