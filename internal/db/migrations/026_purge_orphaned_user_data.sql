DELETE FROM passkeys WHERE user_id NOT LIKE 'admin:%' AND user_id NOT IN (SELECT id FROM users);
DELETE FROM social_accounts WHERE user_id NOT IN (SELECT id FROM users);
DELETE FROM trusted_devices WHERE user_id NOT LIKE 'admin:%' AND user_id NOT IN (SELECT id FROM users);
DELETE FROM totp_recovery_codes WHERE user_id NOT LIKE 'admin:%' AND user_id NOT IN (SELECT id FROM users);
