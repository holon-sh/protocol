package conformance

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/holon-sh/protocol/identity/invitation"
	"github.com/holon-sh/protocol/identity/scim"
)

const (
	invitationLifetime = time.Hour
	expiringLifetime   = time.Second
)

func (s *suite) checkInvitation(ctx context.Context) error {
	capabilities, err := s.users.Capabilities(ctx)
	if err != nil {
		return err
	}
	group, err := s.permissionGroup(ctx)
	if err != nil {
		return err
	}
	request := invitation.Invitation{Email: uniqueEmail(), Groups: []string{group.ID}, Lifetime: invitationLifetime}
	result, err := s.invitations.Invite(ctx, request)
	if err != nil {
		return fmt.Errorf("invite: %w", err)
	}
	defer s.deleteUser(ctx, result.UserID)
	if err := validateResult(result, capabilities, request.Lifetime, time.Now()); err != nil {
		return err
	}
	user, err := s.users.GetUser(ctx, result.UserID)
	if err != nil {
		return fmt.Errorf("get the invited user: %w", err)
	}
	if user.UserName != request.Email || !holdsRef(user.Groups, group.ID) {
		return fmt.Errorf("invited user %s holds groups %+v", user.UserName, user.Groups)
	}
	repeated, err := s.invitations.Invite(ctx, request)
	if err != nil {
		return fmt.Errorf("repeat invite: %w", err)
	}
	if repeated.UserID != result.UserID {
		return fmt.Errorf("a repeat invited user %q, want %q", repeated.UserID, result.UserID)
	}
	return nil
}

func validateResult(result invitation.Result, capabilities scim.Capabilities, lifetime time.Duration, now time.Time) error {
	switch {
	case result.UserID == "":
		return errors.New("result has no userId")
	case result.Sent != capabilities.Invitations:
		return fmt.Errorf("sent is %v but the capabilities say invitations %v", result.Sent, capabilities.Invitations)
	case result.Sent && !result.ExpiresAt.After(now):
		return fmt.Errorf("expiresAt %s is not in the future", result.ExpiresAt)
	case result.Sent && result.ExpiresAt.After(now.Add(lifetime+time.Minute)):
		return fmt.Errorf("expiresAt %s outlives the lifetime %s", result.ExpiresAt, lifetime)
	}
	return nil
}

func (s *suite) checkTemporaryPassword(ctx context.Context) error {
	password := temporaryPassword()
	person, err := s.createPerson(ctx, password)
	if err != nil {
		return err
	}
	defer s.deleteUser(ctx, person.ID)
	signIn := SignInRequest{UserName: person.UserName, Password: password, NewPassword: password, Name: &personName}
	if _, err := s.authorize(ctx, signIn); err == nil {
		return errors.New("the issuer accepted the temporary password as the new one")
	}
	signIn.NewPassword = temporaryPassword()
	if _, err := s.authorize(ctx, signIn); err != nil {
		return fmt.Errorf("first sign-in with a new password: %w", err)
	}
	return s.wantSetUp(ctx, person.ID)
}

func (s *suite) wantSetUp(ctx context.Context, userID string) error {
	user, err := s.users.GetUser(ctx, userID)
	if err != nil {
		return fmt.Errorf("get: %w", err)
	}
	if user.Holon == nil || user.Holon.PendingSetup {
		return fmt.Errorf("the person finished setting up but pendingSetup is %+v", user.Holon)
	}
	if user.Name == nil || *user.Name != personName {
		return fmt.Errorf("the name collected at sign-in is %+v, want %+v", user.Name, personName)
	}
	return nil
}

func (s *suite) checkInvitationLink(ctx context.Context) error {
	email := uniqueEmail()
	result, err := s.invitations.Invite(ctx, invitation.Invitation{Email: email, Lifetime: invitationLifetime})
	if err != nil {
		return fmt.Errorf("invite: %w", err)
	}
	defer s.deleteUser(ctx, result.UserID)
	if !result.Sent {
		return skipReason("the backend cannot send mail, so there is no link to follow")
	}
	link := SignInRequest{Invitation: true, UserName: email, NewPassword: temporaryPassword(), Name: &personName}
	if _, err := s.cfg.SignIn(ctx, link); err != nil {
		return fmt.Errorf("following the link: %w", err)
	}
	if err := s.wantSetUp(ctx, result.UserID); err != nil {
		return err
	}
	link.NewPassword = temporaryPassword()
	if _, err := s.cfg.SignIn(ctx, link); err == nil {
		return errors.New("the link was accepted after the person finished setting up")
	}
	expiring := uniqueEmail()
	short, err := s.invitations.Invite(ctx, invitation.Invitation{Email: expiring, Lifetime: expiringLifetime})
	if err != nil {
		return fmt.Errorf("invite: %w", err)
	}
	defer s.deleteUser(ctx, short.UserID)
	if err := s.wait(ctx, time.Until(short.ExpiresAt)+time.Second); err != nil {
		return err
	}
	link.UserName = expiring
	if _, err := s.cfg.SignIn(ctx, link); err == nil {
		return errors.New("the link was accepted after its lifetime")
	}
	return nil
}
