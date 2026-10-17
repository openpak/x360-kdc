package kdc

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// HTTPDirectory is UserDirectory over x360-xuacs's internal API
// (internal/xuacs/internal.go), authenticated with X-Internal-Key.
type HTTPDirectory struct {
	URL    string // e.g. http://10.212.63.196:20005
	Key    string
	Client *http.Client
}

func (d *HTTPDirectory) post(ctx context.Context, path string, in, out any) error {
	b, _ := json.Marshal(in)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(d.URL, "/")+path, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Internal-Key", d.Key)
	cl := d.Client
	if cl == nil {
		cl = &http.Client{Timeout: 5 * time.Second}
	}
	resp, err := cl.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		json.NewDecoder(resp.Body).Decode(&e)
		return fmt.Errorf("xuacs %s: %d %s", path, resp.StatusCode, e.Error)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (d *HTTPDirectory) Profiles(ctx context.Context, console, gamertag string) ([]Profile, error) {
	type one struct {
		Account string `json:"account"`
		Online  string `json:"online_xuid"`
		Key     string `json:"xenon_key"`
	}
	var out struct {
		one
		Profiles []one `json:"profiles"`
	}
	if err := d.post(ctx, "/internal/v1/user-key", map[string]string{"console": console, "gamertag": gamertag}, &out); err != nil {
		return nil, err
	}
	list := out.Profiles
	if out.Account != "" {
		list = append(list, out.one)
	}
	var ps []Profile
	for _, p := range list {
		x, err1 := strconv.ParseUint(p.Online, 16, 64)
		k, err2 := hex.DecodeString(p.Key)
		if err1 != nil || err2 != nil || len(k) != 16 {
			return nil, fmt.Errorf("xuacs user-key: malformed reply")
		}
		ps = append(ps, Profile{Account: p.Account, Online: x, XenonKey: k})
	}
	return ps, nil
}

func (d *HTTPDirectory) VerifyTicket(ctx context.Context, ticket []byte) (string, uint64, error) {
	var out struct {
		Account string `json:"account"`
		Online  string `json:"online_xuid"`
	}
	if err := d.post(ctx, "/internal/v1/wlid-ticket", map[string]string{"ticket": base64.StdEncoding.EncodeToString(ticket)}, &out); err != nil {
		return "", 0, err
	}
	x, err := strconv.ParseUint(out.Online, 16, 64)
	if err != nil {
		return "", 0, fmt.Errorf("xuacs wlid-ticket: malformed reply")
	}
	return out.Account, x, nil
}
