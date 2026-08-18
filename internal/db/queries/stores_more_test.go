package queries

import (
	"context"
	"github.com/chr0nzz/gatekeeper/internal/auth"
	"testing"
	"time"
)

func q2inviteUsable(inv *Invite) bool {
	return inv != nil && !inv.IsUsed() && !inv.IsExpired()
}

func q2adminID(t *testing.T, store *AdminStore, email string) string {
	t.Helper()
	admin, err := store.GetByEmail(context.Background(), email)
	if err != nil || admin == nil {
		t.Fatalf("GetByEmail(%q) = %v, %v", email, admin, err)
	}
	return admin.ID
}

func q2webhookID(t *testing.T, store *WebhookStore, name string) string {
	t.Helper()
	list, err := store.ListWebhooks(context.Background())
	if err != nil {
		t.Fatalf("ListWebhooks: %v", err)
	}
	for _, w := range list {
		if w.Name == name {
			return w.ID
		}
	}
	t.Fatalf("webhook %q not found in %v", name, list)
	return ""
}

func TestUserStoreListIsOrderedAndComplete(t *testing.T) {
	ctx := context.Background()
	store := NewUserStore(queriesTestDB(t))

	for _, email := range []string{"carol@example.com", "alice@example.com", "bob@example.com"} {
		if _, err := store.Create(ctx, email, "hash", false); err != nil {
			t.Fatalf("create %s: %v", email, err)
		}
	}

	list, err := store.List(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	got := []string{}
	for _, u := range list {
		got = append(got, u.Email)
	}
	want := []string{"alice@example.com", "bob@example.com", "carol@example.com"}
	if len(got) != len(want) {
		t.Fatalf("List returned %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("List[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestUserStoreSetDisplayNameDoesNotChangeIdentity(t *testing.T) {
	ctx := context.Background()
	store := NewUserStore(queriesTestDB(t))

	id, _ := store.Create(ctx, "u@example.com", "hash", false)
	if err := store.SetDisplayName(ctx, id, "Ada Lovelace"); err != nil {
		t.Fatalf("set display name: %v", err)
	}

	u, _ := store.GetByID(ctx, id)
	if u == nil || u.DisplayName != "Ada Lovelace" {
		t.Fatalf("display name = %v", u)
	}
	if u.Email != "u@example.com" {
		t.Errorf("email changed to %q", u.Email)
	}
}

func TestUserStorePendingApprovalGatesSignIn(t *testing.T) {
	ctx := context.Background()
	store := NewUserStore(queriesTestDB(t))

	pendingID, err := store.CreatePending(ctx, "new@example.com", "hash")
	if err != nil {
		t.Fatalf("create pending: %v", err)
	}
	invitedID, _ := store.Create(ctx, "invited@example.com", "hash", false)

	pending, _ := store.GetByID(ctx, pendingID)
	if pending == nil || !pending.PendingApproval {
		t.Fatalf("new signup is not pending approval: %v", pending)
	}
	if !pending.Disabled {
		t.Error("a pending signup is enabled before an admin approves it")
	}

	waiting, err := store.ListPendingApproval(ctx)
	if err != nil {
		t.Fatalf("list pending: %v", err)
	}
	if len(waiting) != 1 || waiting[0].ID != pendingID {
		t.Fatalf("ListPendingApproval = %v, want only %s", waiting, pendingID)
	}

	if err := store.Approve(ctx, pendingID); err != nil {
		t.Fatalf("approve: %v", err)
	}
	approved, _ := store.GetByID(ctx, pendingID)
	if approved.PendingApproval || approved.Disabled {
		t.Errorf("after approval pending=%v disabled=%v, want both false", approved.PendingApproval, approved.Disabled)
	}

	waiting, _ = store.ListPendingApproval(ctx)
	if len(waiting) != 0 {
		t.Errorf("approved user still queued: %v", waiting)
	}

	other, _ := store.GetByID(ctx, invitedID)
	if other.PendingApproval {
		t.Error("an admin created user was queued for approval")
	}
}

func TestUserStoreSetPasswordReplacesHashAndClearsForceChange(t *testing.T) {
	ctx := context.Background()
	store := NewUserStore(queriesTestDB(t))

	id, _ := store.Create(ctx, "u@example.com", "old-hash", true)
	before, _ := store.GetByID(ctx, id)
	if !before.ForcePasswordChange {
		t.Fatal("force password change was not recorded at creation")
	}

	if err := store.SetPassword(ctx, id, "new-hash", false); err != nil {
		t.Fatalf("set password: %v", err)
	}

	after, _ := store.GetByID(ctx, id)
	if after.PasswordHash != "new-hash" {
		t.Errorf("password hash = %q, want new-hash", after.PasswordHash)
	}
	if after.ForcePasswordChange {
		t.Error("force password change still set after the user chose a new password")
	}
}

func TestUserStoreAvatarRoundTrip(t *testing.T) {
	ctx := context.Background()
	store := NewUserStore(queriesTestDB(t))

	id, _ := store.Create(ctx, "u@example.com", "hash", false)
	fresh, _ := store.GetByID(ctx, id)
	if fresh.HasAvatar {
		t.Error("a new user reports having an avatar")
	}

	png := []byte{0x89, 'P', 'N', 'G', 0x0d}
	if err := store.SetAvatar(ctx, id, png, "image/png"); err != nil {
		t.Fatalf("set avatar: %v", err)
	}

	withAvatar, _ := store.GetByID(ctx, id)
	if !withAvatar.HasAvatar {
		t.Error("HasAvatar is false after storing image data")
	}
	data, mime := store.GetAvatar(ctx, id)
	if string(data) != string(png) || mime != "image/png" {
		t.Errorf("GetAvatar = %v, %q", data, mime)
	}
}

func TestUserStorePasswordlessToggle(t *testing.T) {
	ctx := context.Background()
	store := NewUserStore(queriesTestDB(t))

	id, _ := store.Create(ctx, "u@example.com", "hash", false)
	fresh, _ := store.GetByID(ctx, id)
	if fresh.PasswordlessEnabled {
		t.Error("passwordless is on by default, which would skip the password check")
	}

	store.SetPasswordless(ctx, id, true)
	on, _ := store.GetByID(ctx, id)
	if !on.PasswordlessEnabled {
		t.Error("passwordless not enabled")
	}

	store.SetPasswordless(ctx, id, false)
	off, _ := store.GetByID(ctx, id)
	if off.PasswordlessEnabled {
		t.Error("passwordless still enabled after being turned off")
	}
}

func TestAdminStoreLifecycle(t *testing.T) {
	ctx := context.Background()
	store := NewAdminStore(queriesTestDB(t))

	if store.Exists(ctx) || store.Count(ctx) != 0 {
		t.Fatal("a fresh database reports an existing admin, setup would be skipped")
	}

	if err := store.Create(ctx, "root@example.com", "hash", "Root"); err != nil {
		t.Fatalf("create: %v", err)
	}
	if !store.Exists(ctx) || store.Count(ctx) != 1 {
		t.Fatalf("Exists=%v Count=%d after create", store.Exists(ctx), store.Count(ctx))
	}

	id := q2adminID(t, store, "root@example.com")
	byID, err := store.GetByID(ctx, id)
	if err != nil || byID == nil {
		t.Fatalf("GetByID = %v, %v", byID, err)
	}
	if byID.Email != "root@example.com" || byID.DisplayName != "Root" || byID.PasswordHash != "hash" {
		t.Errorf("GetByID returned %+v", *byID)
	}

	if missing, _ := store.GetByEmail(ctx, "nobody@example.com"); missing != nil {
		t.Error("GetByEmail returned an admin for an unknown address")
	}
	if missing, _ := store.GetByID(ctx, "not-an-id"); missing != nil {
		t.Error("GetByID returned an admin for an unknown id")
	}

	store.Create(ctx, "second@example.com", "hash", "Second")
	list, err := store.List(ctx)
	if err != nil || len(list) != 2 {
		t.Fatalf("List = %v, %v", list, err)
	}

	if err := store.Delete(ctx, id); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if gone, _ := store.GetByEmail(ctx, "root@example.com"); gone != nil {
		t.Error("admin still present after delete")
	}
	if store.Count(ctx) != 1 {
		t.Errorf("Count = %d after deleting one of two admins", store.Count(ctx))
	}
}

func TestAdminStoreRejectsDuplicateEmail(t *testing.T) {
	ctx := context.Background()
	store := NewAdminStore(queriesTestDB(t))

	if err := store.Create(ctx, "root@example.com", "hash", "Root"); err != nil {
		t.Fatalf("first create: %v", err)
	}
	if err := store.Create(ctx, "root@example.com", "other-hash", "Impostor"); err == nil {
		t.Error("a second admin was created with an existing email")
	}
}

func TestAdminAPIKeyLookupRejectsEmptyAndUnknownKeys(t *testing.T) {
	ctx := context.Background()
	conn := queriesTestDB(t)
	store := NewAdminStore(conn)

	store.Create(ctx, "keyed@example.com", "hash", "Keyed")
	store.Create(ctx, "keyless@example.com", "hash", "Keyless")
	keyedID := q2adminID(t, store, "keyed@example.com")
	keylessID := q2adminID(t, store, "keyless@example.com")

	if store.HasAPIKey(ctx, keyedID) {
		t.Error("a new admin already has an API key")
	}
	if err := store.SetAPIKey(ctx, keyedID, "gk_live_secret"); err != nil {
		t.Fatalf("set api key: %v", err)
	}
	if !store.HasAPIKey(ctx, keyedID) {
		t.Error("HasAPIKey is false after setting one")
	}
	var stored string
	conn.QueryRow(`SELECT api_key FROM admin_users WHERE id=?`, keyedID).Scan(&stored)
	if stored == "gk_live_secret" {
		t.Error("the API key is stored in clear text")
	}
	if stored != auth.HashToken("gk_live_secret") {
		t.Error("the stored API key is not the hash of the issued key")
	}

	if got := store.GetByAPIKey(ctx, "gk_live_secret"); got != keyedID {
		t.Errorf("GetByAPIKey(valid) = %q, want %q", got, keyedID)
	}
	if got := store.GetByAPIKey(ctx, ""); got != "" {
		t.Errorf("an empty API key resolved to admin %q", got)
	}
	if got := store.GetByAPIKey(ctx, "gk_live_wrong"); got != "" {
		t.Errorf("an unknown API key resolved to admin %q", got)
	}
	if got := store.GetByAPIKey(ctx, "gk_live_secret "); got != "" {
		t.Errorf("a key with trailing whitespace was accepted as %q", got)
	}
	if store.GetByAPIKey(ctx, "gk_live_secret") == keylessID {
		t.Error("the key resolved to the admin who never set one")
	}

	if err := store.SetAPIKey(ctx, keyedID, ""); err != nil {
		t.Fatalf("clear api key: %v", err)
	}
	if got := store.GetByAPIKey(ctx, "gk_live_secret"); got != "" {
		t.Errorf("a revoked API key still resolved to %q", got)
	}
}

func TestAdminAPIKeyIsRemovedWithTheAdmin(t *testing.T) {
	ctx := context.Background()
	store := NewAdminStore(queriesTestDB(t))

	store.Create(ctx, "root@example.com", "hash", "Root")
	id := q2adminID(t, store, "root@example.com")
	store.SetAPIKey(ctx, id, "gk_live_secret")

	if err := store.Delete(ctx, id); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if got := store.GetByAPIKey(ctx, "gk_live_secret"); got != "" {
		t.Errorf("the API key of a deleted admin still authenticates as %q", got)
	}
}

func TestInviteIsRedeemableExactlyOnce(t *testing.T) {
	ctx := context.Background()
	store := NewInviteStore(queriesTestDB(t))

	token, err := store.Create(ctx, "invitee@example.com", "", "admin-1", 7)
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	first, _ := store.GetByToken(ctx, token)
	if !q2inviteUsable(first) {
		t.Fatal("a fresh invite was rejected")
	}
	if err := store.MarkUsed(ctx, first.ID); err != nil {
		t.Fatalf("mark used: %v", err)
	}

	second, _ := store.GetByToken(ctx, token)
	if q2inviteUsable(second) {
		t.Fatal("the same invite was accepted a second time")
	}
	if second.UsedAt == nil || *second.UsedAt <= 0 {
		t.Errorf("redemption time not recorded: %v", second.UsedAt)
	}
}

func TestExpiredInviteIsNotRedeemableEvenWhenUnused(t *testing.T) {
	ctx := context.Background()
	conn := queriesTestDB(t)
	store := NewInviteStore(conn)

	token, _ := store.Create(ctx, "invitee@example.com", "", "admin-1", 7)
	if _, err := conn.Exec(`UPDATE invites SET expires_at=?`, time.Now().Unix()-1); err != nil {
		t.Fatalf("backdate: %v", err)
	}

	inv, _ := store.GetByToken(ctx, token)
	if inv == nil {
		t.Fatal("expired invite disappeared from the store")
	}
	if inv.IsUsed() {
		t.Error("an unused invite reports as used")
	}
	if q2inviteUsable(inv) {
		t.Error("an expired invite was accepted")
	}
}

func TestInviteTokensAreDistinctAndRevocable(t *testing.T) {
	ctx := context.Background()
	store := NewInviteStore(queriesTestDB(t))

	first, _ := store.Create(ctx, "one@example.com", "n1", "admin-1", 7)
	second, _ := store.Create(ctx, "two@example.com", "n2", "admin-1", 7)
	if first == second {
		t.Fatal("two invites share the same token")
	}

	list, err := store.List(ctx)
	if err != nil || len(list) != 2 {
		t.Fatalf("List = %v, %v", list, err)
	}

	target, _ := store.GetByToken(ctx, first)
	if err := store.Revoke(ctx, target.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if revoked, _ := store.GetByToken(ctx, first); revoked != nil {
		t.Error("a revoked invite token still resolves")
	}
	if survivor, _ := store.GetByToken(ctx, second); survivor == nil {
		t.Error("revoking one invite removed another")
	}
}

func TestClaimStoreIsScopedToItsClient(t *testing.T) {
	ctx := context.Background()
	store := NewClaimStore(queriesTestDB(t))

	if err := store.Create(ctx, "client-a", "role", "groups"); err != nil {
		t.Fatalf("create: %v", err)
	}
	store.Create(ctx, "client-a", "department", "display_name")
	store.Create(ctx, "client-b", "role", "email")

	a, err := store.List(ctx, "client-a")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(a) != 2 || a[0].ClaimKey != "department" || a[1].ClaimKey != "role" {
		t.Fatalf("List(client-a) = %+v, want department then role", a)
	}
	if a[1].ValueSource != "groups" {
		t.Errorf("value source = %q, want groups", a[1].ValueSource)
	}
	if a[0].ClientID != "client-a" {
		t.Errorf("claim leaked from client %q", a[0].ClientID)
	}

	if err := store.Delete(ctx, a[0].ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	a, _ = store.List(ctx, "client-a")
	if len(a) != 1 || a[0].ClaimKey != "role" {
		t.Fatalf("after delete List(client-a) = %+v", a)
	}

	if err := store.DeleteByClient(ctx, "client-a"); err != nil {
		t.Fatalf("delete by client: %v", err)
	}
	if a, _ = store.List(ctx, "client-a"); len(a) != 0 {
		t.Errorf("client-a still has claims: %+v", a)
	}
	b, _ := store.List(ctx, "client-b")
	if len(b) != 1 {
		t.Errorf("deleting client-a removed client-b claims: %+v", b)
	}
}

func TestWebhookStoreLifecycle(t *testing.T) {
	ctx := context.Background()
	store := NewWebhookStore(queriesTestDB(t))

	if err := store.CreateWebhook(ctx, Webhook{Name: "ops", Type: "slack", URL: "https://hooks.example.com/a", Events: "all"}); err != nil {
		t.Fatalf("create: %v", err)
	}
	id := q2webhookID(t, store, "ops")

	w, err := store.GetWebhook(ctx, id)
	if err != nil || w == nil {
		t.Fatalf("GetWebhook = %v, %v", w, err)
	}
	if !w.Enabled {
		t.Error("a new webhook is not enabled, so it would never fire")
	}
	if w.URL != "https://hooks.example.com/a" || w.Type != "slack" {
		t.Errorf("GetWebhook returned %+v", *w)
	}

	if missing, _ := store.GetWebhook(ctx, "not-an-id"); missing != nil {
		t.Error("GetWebhook returned a webhook for an unknown id")
	}

	w.Name = "ops-renamed"
	w.URL = "https://hooks.example.com/b"
	w.Token = "bot-token"
	if err := store.UpdateWebhook(ctx, *w); err != nil {
		t.Fatalf("update: %v", err)
	}
	updated, _ := store.GetWebhook(ctx, id)
	if updated.Name != "ops-renamed" || updated.URL != "https://hooks.example.com/b" || updated.Token != "bot-token" {
		t.Errorf("update did not persist: %+v", *updated)
	}
	if !updated.Enabled {
		t.Error("updating a webhook silently disabled it")
	}

	if err := store.SetEnabled(ctx, id, false); err != nil {
		t.Fatalf("set enabled: %v", err)
	}
	off, _ := store.GetWebhook(ctx, id)
	if off.Enabled {
		t.Error("webhook still enabled after SetEnabled(false)")
	}

	if err := store.DeleteWebhook(ctx, id); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if gone, _ := store.GetWebhook(ctx, id); gone != nil {
		t.Error("webhook still present after delete")
	}
	list, _ := store.ListWebhooks(ctx)
	if len(list) != 0 {
		t.Errorf("ListWebhooks = %+v after deleting the only webhook", list)
	}
}

func TestWebhookDispatchRespectsSubscriptionAndEnabledFlag(t *testing.T) {
	ctx := context.Background()
	store := NewWebhookStore(queriesTestDB(t))

	store.CreateWebhook(ctx, Webhook{Name: "everything", Type: "generic", Events: "all"})
	store.CreateWebhook(ctx, Webhook{Name: "logins", Type: "generic", Events: "user.login, user.deleted"})
	store.CreateWebhook(ctx, Webhook{Name: "muted", Type: "generic", Events: "all"})
	store.SetEnabled(ctx, q2webhookID(t, store, "muted"), false)

	names := func(event string) []string {
		hooks, err := store.ListEnabledForEvent(ctx, event)
		if err != nil {
			t.Fatalf("ListEnabledForEvent(%s): %v", event, err)
		}
		var out []string
		for _, h := range hooks {
			out = append(out, h.Name)
		}
		return out
	}

	login := names("user.login")
	if len(login) != 2 {
		t.Fatalf("user.login matched %v, want everything and logins", login)
	}
	for _, n := range login {
		if n == "muted" {
			t.Fatal("a disabled webhook was selected for dispatch")
		}
	}

	created := names("user.created")
	if len(created) != 1 || created[0] != "everything" {
		t.Errorf("user.created matched %v, want only everything", created)
	}

	deleted := names("user.deleted")
	if len(deleted) != 2 {
		t.Errorf("user.deleted matched %v, want everything and logins", deleted)
	}
}

func TestWebhookNotificationLogAndUnreadCount(t *testing.T) {
	ctx := context.Background()
	store := NewWebhookStore(queriesTestDB(t))

	since := time.Now().Unix() - 1
	for _, status := range []string{"ok", "error", "ok"} {
		err := store.LogNotification(ctx, Notification{
			WebhookID: "wh-1", WebhookName: "ops", Event: "user.login",
			UserID: "user-1", IP: "10.0.0.1", Status: status, Detail: "d", Error: "",
		})
		if err != nil {
			t.Fatalf("log: %v", err)
		}
	}

	all, err := store.ListNotifications(ctx, 10)
	if err != nil || len(all) != 3 {
		t.Fatalf("ListNotifications = %v, %v", all, err)
	}
	if all[0].WebhookName != "ops" || all[0].UserID != "user-1" || all[0].IP != "10.0.0.1" {
		t.Errorf("notification fields not persisted: %+v", all[0])
	}

	limited, _ := store.ListNotifications(ctx, 2)
	if len(limited) != 2 {
		t.Errorf("limit ignored, got %d rows", len(limited))
	}

	if n := store.UnreadCount(ctx, since); n != 3 {
		t.Errorf("UnreadCount(since) = %d, want 3", n)
	}
	if n := store.UnreadCount(ctx, time.Now().Unix()+3600); n != 0 {
		t.Errorf("UnreadCount(future) = %d, want 0", n)
	}
}

func TestBackupStoreLifecycle(t *testing.T) {
	ctx := context.Background()
	store := NewBackupStore(queriesTestDB(t))

	now := time.Now().Unix()
	oldID, err := store.Create(ctx, "old.db", "local", 100, now-60)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	newID, _ := store.Create(ctx, "new.db", "local", 200, now)

	list, err := store.List(ctx)
	if err != nil || len(list) != 2 {
		t.Fatalf("List = %v, %v", list, err)
	}
	if list[0].ID != newID || list[1].ID != oldID {
		t.Errorf("List is not newest first: %+v", list)
	}

	b, err := store.GetByID(ctx, oldID)
	if err != nil || b == nil {
		t.Fatalf("GetByID = %v, %v", b, err)
	}
	if b.Name != "old.db" || b.Size != 100 || b.Storage != "local" || b.CreatedAt != now-60 {
		t.Errorf("GetByID returned %+v", *b)
	}

	if missing, _ := store.GetByID(ctx, "not-an-id"); missing != nil {
		t.Error("GetByID returned a backup for an unknown id")
	}

	if err := store.Delete(ctx, oldID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if gone, _ := store.GetByID(ctx, oldID); gone != nil {
		t.Error("backup still present after delete")
	}
	if list, _ = store.List(ctx); len(list) != 1 {
		t.Errorf("List = %+v after deleting one of two", list)
	}
}

func TestBackupPruneKeepsNewestPerStorage(t *testing.T) {
	ctx := context.Background()
	store := NewBackupStore(queriesTestDB(t))

	now := time.Now().Unix()
	for i, name := range []string{"local-1.db", "local-2.db", "local-3.db", "local-4.db"} {
		store.Create(ctx, name, "local", 10, now+int64(i))
	}
	store.Create(ctx, "s3-1.db", "s3", 10, now)
	store.Create(ctx, "s3-2.db", "s3", 10, now+1)

	pruned, err := store.PruneOldest(ctx, "local", 2)
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if len(pruned) != 2 {
		t.Fatalf("PruneOldest returned %v, want the two oldest local backups", pruned)
	}
	for _, name := range pruned {
		if name != "local-1.db" && name != "local-2.db" {
			t.Errorf("PruneOldest deleted %q, which is not among the oldest", name)
		}
	}

	remaining := map[string]bool{}
	list, _ := store.List(ctx)
	for _, b := range list {
		remaining[b.Name] = true
	}
	if len(remaining) != 4 {
		t.Fatalf("remaining backups = %v, want 4", remaining)
	}
	for _, name := range []string{"local-3.db", "local-4.db", "s3-1.db", "s3-2.db"} {
		if !remaining[name] {
			t.Errorf("%q was pruned but should have been kept", name)
		}
	}
}

func TestSocialAccountLinkAndUnlink(t *testing.T) {
	ctx := context.Background()
	conn := queriesTestDB(t)
	users := NewUserStore(conn)
	social := NewSocialStore(conn)

	userID, _ := users.Create(ctx, "u@example.com", "hash", false)

	if n := social.CountByUser(ctx, userID); n != 0 {
		t.Fatalf("CountByUser = %d for a user with no links", n)
	}
	if a, _ := social.FindByProvider(ctx, "github", "gh-1"); a != nil {
		t.Error("FindByProvider matched before any link existed")
	}

	if err := social.Create(ctx, userID, "github", "gh-1", "u@github.example"); err != nil {
		t.Fatalf("create: %v", err)
	}
	social.Create(ctx, userID, "google", "goog-1", "u@gmail.example")

	byProvider, err := social.FindByProvider(ctx, "github", "gh-1")
	if err != nil || byProvider == nil {
		t.Fatalf("FindByProvider = %v, %v", byProvider, err)
	}
	if byProvider.UserID != userID || byProvider.ProviderEmail != "u@github.example" {
		t.Errorf("FindByProvider returned %+v", *byProvider)
	}

	byUser, _ := social.FindByUserAndProvider(ctx, userID, "google")
	if byUser == nil || byUser.ProviderUserID != "goog-1" {
		t.Fatalf("FindByUserAndProvider = %v", byUser)
	}
	if none, _ := social.FindByUserAndProvider(ctx, userID, "gitlab"); none != nil {
		t.Error("FindByUserAndProvider matched an unlinked provider")
	}

	links, err := social.ListByUser(ctx, userID)
	if err != nil || len(links) != 2 {
		t.Fatalf("ListByUser = %v, %v", links, err)
	}
	if links[0].Provider != "github" || links[1].Provider != "google" {
		t.Errorf("ListByUser is not ordered by provider: %+v", links)
	}
	if n := social.CountByUser(ctx, userID); n != 2 {
		t.Errorf("CountByUser = %d, want 2", n)
	}

	if err := social.Delete(ctx, byProvider.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if gone, _ := social.FindByProvider(ctx, "github", "gh-1"); gone != nil {
		t.Error("unlinked social account still resolves, sign in would still work")
	}
	if n := social.CountByUser(ctx, userID); n != 1 {
		t.Errorf("CountByUser = %d after unlinking one of two", n)
	}
}

func TestSocialProviderIdentityCannotBeLinkedTwice(t *testing.T) {
	ctx := context.Background()
	conn := queriesTestDB(t)
	users := NewUserStore(conn)
	social := NewSocialStore(conn)

	first, _ := users.Create(ctx, "first@example.com", "hash", false)
	second, _ := users.Create(ctx, "second@example.com", "hash", false)

	if err := social.Create(ctx, first, "github", "gh-1", "shared@github.example"); err != nil {
		t.Fatalf("first link: %v", err)
	}
	if err := social.Create(ctx, second, "github", "gh-1", "shared@github.example"); err == nil {
		t.Fatal("the same GitHub identity was linked to a second account")
	}

	owner, _ := social.FindByProvider(ctx, "github", "gh-1")
	if owner == nil || owner.UserID != first {
		t.Errorf("identity owner = %v, want %s", owner, first)
	}

	if err := social.Create(ctx, second, "google", "gh-1", ""); err != nil {
		t.Errorf("linking the same id on another provider failed: %v", err)
	}
}

func TestQRTokenCleanupRemovesExpiredAndUsedTokens(t *testing.T) {
	ctx := context.Background()
	conn := queriesTestDB(t)
	store := NewQRTokenStore(conn)

	live, _ := store.Create(ctx, "", "", "binding-live")

	expired, _ := store.Create(ctx, "", "", "binding-expired")
	if _, err := conn.Exec(`UPDATE qr_login_tokens SET expires_at=? WHERE id=?`, time.Now().Unix()-1, expired); err != nil {
		t.Fatalf("backdate: %v", err)
	}

	consumed, _ := store.Create(ctx, "", "", "binding-used")
	store.Approve(ctx, consumed, "user-1")
	if tok, _ := store.Consume(ctx, consumed, "binding-used"); tok == nil {
		t.Fatal("could not consume the token under test")
	}

	store.Cleanup(ctx)

	if tok, _ := store.Get(ctx, live); tok == nil {
		t.Error("Cleanup removed a live pending token")
	}
	if tok, _ := store.Get(ctx, expired); tok != nil {
		t.Error("an expired QR token survived Cleanup")
	}
	if tok, _ := store.Get(ctx, consumed); tok != nil {
		t.Error("a consumed QR token survived Cleanup")
	}
}

func TestQRTokenApproveOnlyAffectsPendingTokens(t *testing.T) {
	ctx := context.Background()
	store := NewQRTokenStore(queriesTestDB(t))

	id, _ := store.Create(ctx, "", "", goodBinding)
	if err := store.Approve(ctx, id, "user-1"); err != nil {
		t.Fatalf("approve: %v", err)
	}
	if err := store.Approve(ctx, id, "attacker"); err != nil {
		t.Fatalf("second approve: %v", err)
	}

	tok, _ := store.Get(ctx, id)
	if tok == nil || tok.UserID != "user-1" {
		t.Fatalf("token owner = %v, want user-1", tok)
	}

	if _, err := store.Consume(ctx, id, goodBinding); err != nil {
		t.Fatalf("consume: %v", err)
	}
	if err := store.Approve(ctx, id, "attacker"); err != nil {
		t.Fatalf("approve after consume: %v", err)
	}
	after, _ := store.Get(ctx, id)
	if after.Status != "used" || after.UserID != "user-1" {
		t.Errorf("a consumed token was reopened: status=%q user=%q", after.Status, after.UserID)
	}
}
