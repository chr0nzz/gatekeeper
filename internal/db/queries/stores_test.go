package queries

import (
	"context"
	"testing"
)

func TestUserStoreLifecycle(t *testing.T) {
	ctx := context.Background()
	store := NewUserStore(queriesTestDB(t))

	id, err := store.Create(ctx, "user@example.com", "hash", false)
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	byEmail, err := store.GetByEmail(ctx, "user@example.com")
	if err != nil || byEmail == nil {
		t.Fatalf("GetByEmail = %v, %v", byEmail, err)
	}
	if byEmail.ID != id {
		t.Errorf("GetByEmail returned id %q, want %q", byEmail.ID, id)
	}

	byID, err := store.GetByID(ctx, id)
	if err != nil || byID == nil || byID.Email != "user@example.com" {
		t.Fatalf("GetByID = %v, %v", byID, err)
	}

	if missing, _ := store.GetByEmail(ctx, "nobody@example.com"); missing != nil {
		t.Error("GetByEmail returned a user for an unknown address")
	}

	if err := store.Delete(ctx, id); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if gone, _ := store.GetByID(ctx, id); gone != nil {
		t.Error("user still present after delete")
	}
}

func TestUserStoreRejectsDuplicateEmail(t *testing.T) {
	ctx := context.Background()
	store := NewUserStore(queriesTestDB(t))

	if _, err := store.Create(ctx, "dup@example.com", "hash", false); err != nil {
		t.Fatalf("first create: %v", err)
	}
	if _, err := store.Create(ctx, "dup@example.com", "hash", false); err == nil {
		t.Error("duplicate email was accepted")
	}
}

func TestUserStoreDisableAndApprove(t *testing.T) {
	ctx := context.Background()
	store := NewUserStore(queriesTestDB(t))

	id, _ := store.Create(ctx, "u@example.com", "hash", false)

	if err := store.SetDisabled(ctx, id, true); err != nil {
		t.Fatalf("disable: %v", err)
	}
	u, _ := store.GetByID(ctx, id)
	if !u.Disabled {
		t.Error("user is not disabled after SetDisabled(true)")
	}

	store.SetDisabled(ctx, id, false)
	u, _ = store.GetByID(ctx, id)
	if u.Disabled {
		t.Error("user still disabled after SetDisabled(false)")
	}
}

func TestUserStoreEmailVerification(t *testing.T) {
	ctx := context.Background()
	conn := queriesTestDB(t)
	store := NewUserStore(conn)

	id, _ := store.Create(ctx, "u@example.com", "hash", false)

	var verified int
	conn.QueryRow(`SELECT email_verified FROM users WHERE id=?`, id).Scan(&verified)
	if verified != 0 {
		t.Error("a new account is marked email verified before proving control")
	}

	if err := store.MarkEmailVerified(ctx, id); err != nil {
		t.Fatalf("mark verified: %v", err)
	}
	conn.QueryRow(`SELECT email_verified FROM users WHERE id=?`, id).Scan(&verified)
	if verified != 1 {
		t.Error("account not marked verified after MarkEmailVerified")
	}
}

func TestPolicyMembership(t *testing.T) {
	ctx := context.Background()
	conn := queriesTestDB(t)
	users := NewUserStore(conn)
	policies := NewPolicyStore(conn)

	userID, _ := users.Create(ctx, "member@example.com", "hash", false)
	otherID, _ := users.Create(ctx, "outsider@example.com", "hash", false)

	if err := policies.Create(ctx, "media", "Media apps"); err != nil {
		t.Fatalf("create policy: %v", err)
	}
	policy, err := policies.GetByName(ctx, "media")
	if err != nil || policy == nil {
		t.Fatalf("GetByName = %v, %v", policy, err)
	}

	if err := policies.AddMember(ctx, policy.ID, userID); err != nil {
		t.Fatalf("add member: %v", err)
	}

	in, err := policies.IsUserInPolicy(ctx, "media", userID)
	if err != nil || !in {
		t.Errorf("IsUserInPolicy(member) = %v, %v; want true", in, err)
	}
	out, _ := policies.IsUserInPolicy(ctx, "media", otherID)
	if out {
		t.Error("a non-member passed the policy check")
	}

	unknown, _ := policies.IsUserInPolicy(ctx, "does-not-exist", userID)
	if unknown {
		t.Error("an unknown policy name granted access")
	}

	policies.RemoveMember(ctx, policy.ID, userID)
	removed, _ := policies.IsUserInPolicy(ctx, "media", userID)
	if removed {
		t.Error("removed member still passes the policy check")
	}
}

func TestInviteTokenLifecycle(t *testing.T) {
	ctx := context.Background()
	conn := queriesTestDB(t)
	store := NewInviteStore(conn)

	token, err := store.Create(ctx, "invitee@example.com", "note", "admin-1", 7)
	if err != nil {
		t.Fatalf("create invite: %v", err)
	}

	var rawCount int
	conn.QueryRow(`SELECT COUNT(*) FROM invites WHERE token_hash=?`, token).Scan(&rawCount)
	if rawCount != 0 {
		t.Error("invite token stored unhashed")
	}

	inv, err := store.GetByToken(ctx, token)
	if err != nil || inv == nil {
		t.Fatalf("GetByToken = %v, %v", inv, err)
	}
	if inv.Email != "invitee@example.com" {
		t.Errorf("invite email = %q", inv.Email)
	}
	if inv.IsUsed() {
		t.Error("a fresh invite reports as used")
	}
	if inv.IsExpired() {
		t.Error("a 7 day invite reports as expired")
	}

	if err := store.MarkUsed(ctx, inv.ID); err != nil {
		t.Fatalf("mark used: %v", err)
	}
	used, _ := store.GetByToken(ctx, token)
	if used == nil || !used.IsUsed() {
		t.Error("invite not marked used")
	}

	if unknown, _ := store.GetByToken(ctx, "not-a-real-token"); unknown != nil {
		t.Error("an unknown invite token was accepted")
	}
}

func TestExpiredInviteIsRejected(t *testing.T) {
	ctx := context.Background()
	conn := queriesTestDB(t)
	store := NewInviteStore(conn)

	token, _ := store.Create(ctx, "invitee@example.com", "", "admin-1", 1)
	conn.Exec(`UPDATE invites SET expires_at = 1`)

	inv, _ := store.GetByToken(ctx, token)
	if inv != nil && !inv.IsExpired() {
		t.Error("an expired invite did not report as expired")
	}
}

func TestGroupMembership(t *testing.T) {
	ctx := context.Background()
	conn := queriesTestDB(t)
	users := NewUserStore(conn)
	groups := NewGroupStore(conn)

	userID, _ := users.Create(ctx, "member@example.com", "hash", false)

	if err := groups.Create(ctx, "admins", "Administrators"); err != nil {
		t.Fatalf("create group: %v", err)
	}
	list, err := groups.List(ctx)
	if err != nil || len(list) != 1 {
		t.Fatalf("List = %v, %v", list, err)
	}

	if err := groups.AddMember(ctx, list[0].ID, userID); err != nil {
		t.Fatalf("add member: %v", err)
	}

	names, err := groups.GetUserGroups(ctx, userID)
	if err != nil {
		t.Fatalf("GetUserGroups: %v", err)
	}
	if len(names) != 1 || names[0] != "admins" {
		t.Errorf("GetUserGroups = %v, want [admins]", names)
	}

	groups.RemoveMember(ctx, list[0].ID, userID)
	names, _ = groups.GetUserGroups(ctx, userID)
	if len(names) != 0 {
		t.Errorf("groups after removal = %v, want none", names)
	}
}
