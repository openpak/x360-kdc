package accountcore

import (
	"context"
	"encoding/binary"
	"errors"
)

// Friend is a minimal projection of the account core's authoritative graph.
type Friend struct {
	AccountID   string
	DisplayName string
}

// ListFriends returns accepted friendships. Requests remain separate core data.
func (c *Client) ListFriends(ctx context.Context, account string) ([]Friend, error) {
	return c.socialList(ctx, "ListFriends", account)
}

// ListBlocks returns the caller's own directional block list.
func (c *Client) ListBlocks(ctx context.Context, account string) ([]Friend, error) {
	return c.socialList(ctx, "ListBlocks", account)
}

func (c *Client) socialList(ctx context.Context, method, account string) ([]Friend, error) {
	var req pb
	req.str(1, account)
	response, err := c.call(ctx, "/openpak.account.v1.Social/"+method, req)
	if err != nil {
		return nil, err
	}
	messages, err := socialMessages(response)
	if err != nil {
		return nil, err
	}
	out := make([]Friend, 0, len(messages))
	for _, message := range messages {
		if _, err := socialMessages(message); err != nil {
			return nil, err
		}
		f := parseFields(message)
		if f.str(1) == "" {
			return nil, errors.New("account core: social entry has no account id")
		}
		out = append(out, Friend{AccountID: f.str(1), DisplayName: f.str(2)})
	}
	return out, nil
}

// CanDiscover applies the core's friendship, block and active-account rules.
func (c *Client) CanDiscover(ctx context.Context, account, other string) (bool, error) {
	var req pb
	req.str(1, account)
	req.str(2, other)
	req = append(req, 0x18, 0x01) // INTERACTION_KIND_DISCOVER
	response, err := c.call(ctx, "/openpak.account.v1.Social/CheckInteraction", req)
	if err != nil {
		return false, err
	}
	if _, err := socialMessages(response); err != nil {
		return false, err
	}
	return parseFields(response).num(1) == 1, nil
}

// socialMessages preserves repeated embedded messages, and rejects malformed
// framing rather than interpreting a truncated friend list as an empty list.
func socialMessages(b []byte) ([][]byte, error) {
	var out [][]byte
	for len(b) > 0 {
		tag, n := binary.Uvarint(b)
		if n <= 0 || tag>>3 == 0 {
			return nil, errors.New("account core: malformed social response")
		}
		b = b[n:]
		switch tag & 7 {
		case 0:
			_, n = binary.Uvarint(b)
			if n <= 0 {
				return nil, errors.New("account core: malformed social varint")
			}
			b = b[n:]
		case 1, 5:
			size := 8
			if tag&7 == 5 {
				size = 4
			}
			if len(b) < size {
				return nil, errors.New("account core: truncated social field")
			}
			b = b[size:]
		case 2:
			size, n := binary.Uvarint(b)
			if n <= 0 || size > uint64(len(b)-n) {
				return nil, errors.New("account core: truncated social message")
			}
			if tag>>3 == 1 {
				out = append(out, b[n:n+int(size)])
			}
			b = b[n+int(size):]
		default:
			return nil, errors.New("account core: unsupported social wire type")
		}
	}
	return out, nil
}
