package accountcore

import (
	"context"
	"errors"
)

var ErrInactive = errors.New("account is not active")

// Handle reads the immutable account identifier. Field 9 is additive to the
// account-core GetAccount response; legacy accounts may still have none.
func (c *Client) Handle(ctx context.Context, account string) (string, error) {
	var req pb
	req.str(1, account)
	response, err := c.call(ctx, identityService+"GetAccount", req)
	if IsNotFound(err) {
		return "", ErrInactive
	}
	if err != nil {
		return "", err
	}
	f := parseFields(response)
	if f.str(1) != account || f.num(2) != StatusActive {
		return "", ErrInactive
	}
	return f.str(9), nil
}
