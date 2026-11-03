package accountcore

import "context"

// Profile is the core's public profile of an active account. Country is the
// ISO 3166-1 alpha-2 code; Version increases on every profile change.
type Profile struct {
	Name, Country, Bio, Motto string
	Version                   uint64
}

// ProfilePatch carries only the fields to change; nil keeps the stored value
// and a pointer to "" clears it.
type ProfilePatch struct {
	Name, Country, Bio, Motto *string
}

// Profile reads GetAccount fields 4 name, 5 country, 10 bio, 11 motto,
// 12 profile_version.
func (c *Client) Profile(ctx context.Context, account string) (*Profile, error) {
	var req pb
	req.str(1, account)
	response, err := c.call(ctx, identityService+"GetAccount", req)
	if IsNotFound(err) {
		return nil, ErrInactive
	}
	if err != nil {
		return nil, err
	}
	f := parseFields(response)
	if f.str(1) != account || f.num(2) != StatusActive {
		return nil, ErrInactive
	}
	return &Profile{Name: f.str(4), Country: f.str(5), Bio: f.str(10), Motto: f.str(11), Version: f.num(12)}, nil
}

// UpdateProfile applies Identity.UpdatePublicProfile. Empty values are encoded
// as present zero-length fields (pb.str would drop them), which the core reads
// as an explicit clear.
func (c *Client) UpdateProfile(ctx context.Context, account string, p ProfilePatch) error {
	_, err := c.call(ctx, identityService+"UpdatePublicProfile", profileRequest(account, p))
	return err
}

func profileRequest(account string, p ProfilePatch) pb {
	var req pb
	req.str(1, account)
	for i, v := range []*string{p.Name, p.Country, p.Bio, p.Motto} {
		if v == nil {
			continue
		}
		if *v == "" {
			req = append(req, byte(i+2)<<3|2, 0)
		} else {
			req.str(i+2, *v)
		}
	}
	return req
}
