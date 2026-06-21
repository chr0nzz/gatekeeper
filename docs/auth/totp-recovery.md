---
title: TOTP recovery codes
description: What recovery codes are, how to use them, and what to do if you lose them.
---

When you enroll a TOTP authenticator app, GateKeeper generates 8 recovery codes. These are backup codes you can use to log in if you lose access to your authenticator app.

## Using a recovery code

On the TOTP challenge page (`/login/totp`), click **Use a recovery code instead**. Enter one of your saved codes at `/login/totp/recovery`.

Each code works exactly once. After you use it, it is permanently invalidated.

## Format

Recovery codes look like this: `aB-3x-Qz-7m-Kp`. They are case-sensitive. GateKeeper stores only the argon2id hash of each code, so they cannot be recovered from the database.

## What to do if you run out of codes

If you have used all your recovery codes and cannot log in, an admin can revoke your TOTP enrollment from `/users/:id`. After that, you can log in with email OTP and re-enroll TOTP if you want.

If you are the only admin and have lost access, you will need to manually update the database. Connect to the SQLite file and set `totp_enabled=0` for your admin user record.

## What to do if you lose your codes

If you still have access to your authenticator app, log in normally and then go to `/profile/totp/enroll` to re-enroll. This generates a new set of recovery codes and invalidates the old ones.

If you have neither your authenticator app nor your recovery codes, contact your admin to revoke your TOTP enrollment.

## Keeping codes safe

Store recovery codes in a password manager, printed and locked away, or another secure offline location. The goal is to have them available even if the device with your authenticator app is lost or broken.
