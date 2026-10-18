package accountcore

import (
	"context"
	"encoding/binary"
)

const sessionsService = "/openpak.account.v1.Sessions/"

// RegisterSession opens (or replaces) the account's presence lease in a
// namespace and title; an empty title means signed in, not in a game.
func (c *Client) RegisterSession(ctx context.Context, accountID, namespace, titleID, endpointRef string, leaseSeconds int, client, os string) (sessionID string, lease int, err error) {
	var req pb
	req.str(1, accountID)
	req.str(2, namespace)
	req.str(3, titleID)
	req.str(4, endpointRef)
	if leaseSeconds > 0 {
		req = binary.AppendUvarint(req, 5<<3)
		req = binary.AppendUvarint(req, uint64(leaseSeconds))
	}
	req.str(6, client)
	req.str(7, os)
	resp, err := c.call(ctx, sessionsService+"RegisterSession", req)
	if err != nil {
		return "", 0, err
	}
	f := parseFields(resp)
	return f.str(1), int(f.num(2)), nil
}

// Heartbeat renews a lease; an error means it lapsed (register again).
func (c *Client) Heartbeat(ctx context.Context, sessionID string) error {
	var req pb
	req.str(1, sessionID)
	_, err := c.call(ctx, sessionsService+"Heartbeat", req)
	return err
}

// ExpireSession ends a lease (the person went offline).
func (c *Client) ExpireSession(ctx context.Context, sessionID string) error {
	var req pb
	req.str(1, sessionID)
	_, err := c.call(ctx, sessionsService+"ExpireSession", req)
	return err
}
