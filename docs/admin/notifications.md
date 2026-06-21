---
title: Notification log
description: View the history of all dispatched webhook notifications.
---

The notification log at `/notifications` shows every webhook dispatch attempt - what was sent, to which webhook, and whether it succeeded.

## Reading the log

Each row shows:

- **Time** - `HH:MM:SS` when the notification was dispatched
- **Webhook** - the name of the destination channel
- **Event** - the audit event that triggered the notification
- **Status** - `Sent` (green) or `Failed` (red)
- **Error** - the error message if delivery failed (hover for full text)

## Filtering

Use the **Sent / Failed** filter chips to narrow the log. Type in the search box to filter by webhook name, event, or error text.

## Bell icon

The bell icon in the topbar shows a red dot when there are new notifications since you last viewed the log. Clicking the bell opens a dropdown with the 8 most recent notifications and a "View all" link. The dot clears when you open the dropdown.

## Debugging failed deliveries

If a webhook shows `Failed`:

1. Check the error column for the HTTP status code or error message.
2. Go to **Webhooks** and use the test button to re-send a test notification and see the live error.
3. Common causes:
   - Wrong URL or token
   - Bot not added to Telegram chat
   - ntfy topic not accessible
   - SMTP not configured (for email webhooks)
