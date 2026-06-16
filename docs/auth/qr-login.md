---
title: QR code sign-in
description: Sign in to GateKeeper by scanning a QR code with your phone.
---

QR code sign-in lets you authenticate on a PC or shared device by scanning a code with your phone. You approve the login on your phone, and the other device signs in automatically - no password or email code required.

## How it works

1. On the device you want to sign in to, open the GateKeeper login page and click the **QR code** tab.
2. A QR code appears. Open your phone's camera and scan it.
3. Your browser opens a GateKeeper approval page. If your phone does not already have an active GateKeeper session, you are asked to sign in first.
4. Tap **Approve sign-in**. Your phone shows a confirmation.
5. The PC detects the approval and signs you in automatically.

## Requirements

Your phone must have an active GateKeeper session. Sign in on your phone once using any method (password, passkey, or email code). After that you can use QR sign-in to authenticate on any other device without re-entering credentials.

## QR code expiry

Each QR code is valid for 5 minutes. If it expires before you scan it, a new code loads automatically after a short pause.

## Security

The QR code encodes a one-time token. Approving the token creates a new session on the device that displayed the code. The token is deleted from the database once it is used or after it expires.

Only approve a sign-in if you were the one who opened the QR code tab. If you receive the approval page unexpectedly, tap **Deny** to close it without approving.
