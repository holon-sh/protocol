// Package invitation is the one operation Holon defines itself. SCIM 2.0 has no invitation and each backend
// invites differently, so no standard applies.
package invitation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"math"
	"net/mail"
	"slices"
	"time"

	"github.com/holon-sh/protocol/identity/internal/adapter"
)

var (
	ErrInvalid     = errors.New("invitation invalid")
	ErrUnavailable = errors.New("invitation unavailable")
)

// Invitation asks the backend to make sure the person exists, place them in Groups, which are SCIM Group ids,
// and send them a way to finish setting up. The link is valid for Lifetime and no longer, and is refused once
// the person has finished setting up. On the wire Lifetime is an integer number of seconds.
type Invitation struct {
	Email    string        `json:"email"`
	Groups   []string      `json:"groups,omitempty"`
	Lifetime time.Duration `json:"lifetime"`
}

// Result says what happened. Sent is false only when the backend cannot send mail; the user still exists and
// holds the groups.
type Result struct {
	UserID    string    `json:"userId"`
	Sent      bool      `json:"sent"`
	ExpiresAt time.Time `json:"expiresAt,omitzero"`
}

// Backend sends invitations. Invite is idempotent on Email: a repeat re-sends. ErrInvalid reports an address
// or group the backend refuses.
type Backend interface {
	Invite(context.Context, Invitation) (Result, error)
}

func (i Invitation) MarshalJSON() ([]byte, error) {
	type plain Invitation
	return json.Marshal(struct {
		plain

		Lifetime int64 `json:"lifetime"`
	}{plain(i), int64(i.Lifetime / time.Second)})
}

func (i *Invitation) UnmarshalJSON(data []byte) error {
	type plain Invitation
	var wire struct {
		plain

		Lifetime int64 `json:"lifetime"`
	}
	if err := adapter.Decode(bytes.NewReader(data), &wire); err != nil {
		return err
	}
	if wire.Lifetime > math.MaxInt64/int64(time.Second) {
		return errors.New("invitation lifetime is out of range")
	}
	*i = Invitation(wire.plain)
	i.Lifetime = time.Duration(wire.Lifetime) * time.Second
	return nil
}

func (i Invitation) valid() bool {
	address, err := mail.ParseAddress(i.Email)
	return err == nil && address.Address == i.Email && i.Lifetime >= time.Second && !slices.Contains(i.Groups, "")
}
