package accountcore

import (
	"context"
	"encoding/binary"
)

// Avatar is the account core's current PNG and its content version.
type Avatar struct {
	PNG           []byte
	Version       string
	UpdatedAtUnix int64
	NotModified   bool
}

// GetAvatar fetches a 256px or 512px PNG. A missing avatar is CodeNotFound.
func (c *Client) GetAvatar(ctx context.Context, accountID string, size uint32, ifNoneMatch string) (*Avatar, error) {
	var req pb
	req.str(1, accountID)
	req = binary.AppendUvarint(req, 2<<3)
	req = binary.AppendUvarint(req, uint64(size))
	req.str(3, ifNoneMatch)
	response, err := c.call(ctx, "/openpak.account.v1.Media/GetAvatar", req)
	if err != nil {
		return nil, err
	}
	f := parseFields(response)
	return &Avatar{PNG: []byte(f.str(1)), Version: f.str(2), UpdatedAtUnix: int64(f.num(3)), NotModified: f.num(4) != 0}, nil
}
