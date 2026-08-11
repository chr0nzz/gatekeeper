package admin

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/chr0nzz/gatekeeper/internal/auth"
)

const (
	admUsersShortPassword = "Short1!aaaaa"
	admUsersLongPassword  = "correct-horse-battery-staple-20"
)

func admUsersCountByEmail(t *testing.T, a *adminHarness, email string) int {
	t.Helper()
	var n int
	if err := a.db.QueryRow(`SELECT COUNT(*) FROM users WHERE email=?`, email).Scan(&n); err != nil {
		t.Fatalf("count users: %v", err)
	}
	return n
}

func admUsersDisabled(t *testing.T, a *adminHarness, id string) bool {
	t.Helper()
	var disabled int
	if err := a.db.QueryRow(`SELECT disabled FROM users WHERE id=?`, id).Scan(&disabled); err != nil {
		t.Fatalf("read disabled: %v", err)
	}
	return disabled == 1
}

func admUsersPasswordHash(t *testing.T, a *adminHarness, id string) string {
	t.Helper()
	user, err := a.users.GetByID(context.Background(), id)
	if err != nil || user == nil {
		t.Fatalf("load user %s: %v", id, err)
	}
	return user.PasswordHash
}

func admUsersSessionCount(t *testing.T, a *adminHarness, userID string) int {
	t.Helper()
	var n int
	if err := a.db.QueryRow(`SELECT COUNT(*) FROM sessions WHERE user_id=?`, userID).Scan(&n); err != nil {
		t.Fatalf("count sessions: %v", err)
	}
	return n
}

func admUsersSeedSession(t *testing.T, a *adminHarness, userID, id string) {
	t.Helper()
	now := time.Now().Unix()
	_, err := a.db.Exec(
		`INSERT INTO sessions (id, user_id, data, created_at, expires_at, last_seen) VALUES (?,?,?,?,?,?)`,
		id, userID, `{"user_id":"`+userID+`"}`, now, now+3600, now,
	)
	if err != nil {
		t.Fatalf("seed session: %v", err)
	}
}

func TestAdminCreateUserStoresHashedPassword(t *testing.T) {
	a := newAdminHarness(t)
	cookie := a.signIn(t)

	rec := a.postForm("/users", url.Values{
		"email":    {"new@example.com"},
		"password": {admUsersLongPassword},
	}, cookie)
	if rec.Code != http.StatusFound || adminLocation(rec) != "/users" {
		t.Fatalf("create user: status %d location %q", rec.Code, adminLocation(rec))
	}

	user, err := a.users.GetByEmail(context.Background(), "new@example.com")
	if err != nil || user == nil {
		t.Fatalf("user was not created: %v", err)
	}
	if user.PasswordHash == admUsersLongPassword {
		t.Fatal("password stored in clear")
	}
	if err := auth.VerifyPassword(admUsersLongPassword, user.PasswordHash); err != nil {
		t.Errorf("stored hash does not verify the chosen password: %v", err)
	}
	if !user.ForcePasswordChange {
		t.Error("admin-set password should force a change on first sign in")
	}
}

func TestAdminCreateUserRejectsDuplicateEmail(t *testing.T) {
	a := newAdminHarness(t)
	cookie := a.signIn(t)

	form := url.Values{"email": {"dupe@example.com"}, "password": {admUsersLongPassword}}
	if rec := a.postForm("/users", form, cookie); rec.Code != http.StatusFound {
		t.Fatalf("first create: status %d", rec.Code)
	}

	rec := a.postForm("/users", url.Values{
		"email":    {"dupe@example.com"},
		"password": {admUsersLongPassword + "-other"},
	}, cookie)
	if rec.Code == http.StatusFound {
		t.Errorf("duplicate email redirected as success, want the form re-rendered with an error")
	}
	if n := admUsersCountByEmail(t, a, "dupe@example.com"); n != 1 {
		t.Errorf("rows for duplicated email = %d, want 1", n)
	}
}

func TestAdminCreateUserEnforcesConfiguredPasswordPolicy(t *testing.T) {
	a := newAdminHarness(t)
	cookie := a.signIn(t)
	a.set(t, "password_min_length", "20")

	rec := a.postForm("/users", url.Values{
		"email":    {"weak@example.com"},
		"password": {admUsersShortPassword},
	}, cookie)
	if rec.Code == http.StatusFound {
		t.Errorf("12 character password accepted under a 20 character policy (status %d)", rec.Code)
	}
	if n := admUsersCountByEmail(t, a, "weak@example.com"); n != 0 {
		t.Errorf("user created despite failing the password policy (%d rows)", n)
	}

	compliant := "abcdefghij0123456789"
	if len(compliant) < 20 {
		t.Fatalf("test password is only %d characters", len(compliant))
	}
	rec = a.postForm("/users", url.Values{
		"email":    {"strong@example.com"},
		"password": {compliant},
	}, cookie)
	if rec.Code != http.StatusFound {
		t.Fatalf("compliant password rejected: status %d", rec.Code)
	}
	if n := admUsersCountByEmail(t, a, "strong@example.com"); n != 1 {
		t.Errorf("rows for compliant user = %d, want 1", n)
	}
}

func TestAdminSetPasswordEnforcesConfiguredPasswordPolicy(t *testing.T) {
	a := newAdminHarness(t)
	cookie := a.signIn(t)
	id := a.addUser(t, "target@example.com")
	a.set(t, "password_min_length", "20")

	before := admUsersPasswordHash(t, a, id)
	rec := a.postForm("/users/"+id+"/password", url.Values{"password": {admUsersShortPassword}}, cookie)
	if loc := adminLocation(rec); !strings.Contains(loc, "err=") {
		t.Errorf("short password accepted: status %d location %q", rec.Code, loc)
	}
	if got := admUsersPasswordHash(t, a, id); got != before {
		t.Error("password changed even though it failed the policy")
	}

	compliant := "zyxwvutsrq9876543210"
	rec = a.postForm("/users/"+id+"/password", url.Values{"password": {compliant}}, cookie)
	if rec.Code != http.StatusFound {
		t.Fatalf("compliant password rejected: status %d location %q", rec.Code, adminLocation(rec))
	}
	after := admUsersPasswordHash(t, a, id)
	if after == before {
		t.Fatal("compliant password was not applied")
	}
	if after == compliant {
		t.Fatal("password stored in clear")
	}
	if err := auth.VerifyPassword(compliant, after); err != nil {
		t.Errorf("stored hash does not verify the new password: %v", err)
	}
}

func TestAdminSetPasswordRevokesExistingSessions(t *testing.T) {
	a := newAdminHarness(t)
	cookie := a.signIn(t)
	id := a.addUser(t, "rotate@example.com")
	admUsersSeedSession(t, a, id, "rotate-session")

	rec := a.postForm("/users/"+id+"/password", url.Values{"password": {admUsersLongPassword}}, cookie)
	if rec.Code != http.StatusFound {
		t.Fatalf("set password: status %d location %q", rec.Code, adminLocation(rec))
	}
	if n := admUsersSessionCount(t, a, id); n != 0 {
		t.Errorf("sessions surviving a password change = %d, want 0", n)
	}
}

func TestAdminDisableUserBlocksActiveStateAndEnableRestoresIt(t *testing.T) {
	a := newAdminHarness(t)
	cookie := a.signIn(t)
	id := a.addUser(t, "disable@example.com")
	admUsersSeedSession(t, a, id, "disable-session")

	if rec := a.postForm("/users/"+id+"/disable", nil, cookie); rec.Code != http.StatusFound {
		t.Fatalf("disable: status %d", rec.Code)
	}
	if !admUsersDisabled(t, a, id) {
		t.Error("user is still active after being disabled")
	}
	if n := admUsersSessionCount(t, a, id); n != 0 {
		t.Errorf("disabled user kept %d sessions, want 0", n)
	}

	if rec := a.postForm("/users/"+id+"/enable", nil, cookie); rec.Code != http.StatusFound {
		t.Fatalf("enable: status %d", rec.Code)
	}
	if admUsersDisabled(t, a, id) {
		t.Error("user is still disabled after being enabled")
	}
}

func TestAdminDeleteUserRemovesRow(t *testing.T) {
	a := newAdminHarness(t)
	cookie := a.signIn(t)
	id := a.addUser(t, "gone@example.com")

	if rec := a.postForm("/users/"+id+"/delete", nil, cookie); rec.Code != http.StatusFound {
		t.Fatalf("delete: status %d", rec.Code)
	}
	if n := admUsersCountByEmail(t, a, "gone@example.com"); n != 0 {
		t.Errorf("rows left after delete = %d, want 0", n)
	}
	user, err := a.users.GetByID(context.Background(), id)
	if err == nil && user != nil {
		t.Error("deleted user is still readable by ID")
	}
}

func TestAdminRevokeSessionsOnlyClearsThatUser(t *testing.T) {
	a := newAdminHarness(t)
	cookie := a.signIn(t)
	id := a.addUser(t, "revoke@example.com")
	other := a.addUser(t, "bystander@example.com")
	admUsersSeedSession(t, a, id, "revoke-one")
	admUsersSeedSession(t, a, id, "revoke-two")
	admUsersSeedSession(t, a, other, "bystander-one")

	if rec := a.postForm("/users/"+id+"/revoke-sessions", nil, cookie); rec.Code != http.StatusFound {
		t.Fatalf("revoke sessions: status %d", rec.Code)
	}
	if n := admUsersSessionCount(t, a, id); n != 0 {
		t.Errorf("sessions left for the target user = %d, want 0", n)
	}
	if n := admUsersSessionCount(t, a, other); n != 1 {
		t.Errorf("bystander sessions = %d, want 1", n)
	}
}

func TestAdminUserWritesRequireAnAdminSession(t *testing.T) {
	a := newAdminHarness(t)
	a.signIn(t)
	id := a.addUser(t, "victim@example.com")
	before := admUsersPasswordHash(t, a, id)

	cases := []struct {
		path string
		form url.Values
	}{
		{"/users", url.Values{"email": {"intruder@example.com"}, "password": {admUsersLongPassword}}},
		{"/users/" + id + "/password", url.Values{"password": {admUsersLongPassword}}},
		{"/users/" + id + "/delete", nil},
		{"/users/" + id + "/disable", nil},
	}
	for _, tc := range cases {
		rec := a.postForm(tc.path, tc.form)
		if loc := adminLocation(rec); loc != "/login" {
			t.Errorf("%s without an admin session: status %d location %q, want /login", tc.path, rec.Code, loc)
		}
	}

	if n := admUsersCountByEmail(t, a, "intruder@example.com"); n != 0 {
		t.Error("unauthenticated request created a user")
	}
	if got := admUsersPasswordHash(t, a, id); got != before {
		t.Error("unauthenticated request changed a password")
	}
	if admUsersDisabled(t, a, id) {
		t.Error("unauthenticated request disabled a user")
	}
	if n := admUsersCountByEmail(t, a, "victim@example.com"); n != 1 {
		t.Error("unauthenticated request deleted a user")
	}
}
