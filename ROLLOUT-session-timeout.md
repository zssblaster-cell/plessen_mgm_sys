# Session timeout + new system headers — rollout

No rule changes and no new accounts. About 10 minutes.

## 1. Deploy these files in ONE commit

`index.html` (portal), `crypto.js`, `config-tool.html`, `equipment/index.html`,
`inventory/index.html`, `credentialing/index.html`. Wait for Vercel **Ready**, then hard-refresh.

**Expect:** everyone who is signed in is signed out once, with the message
"New sign-in security settings are in effect. Please sign in again." That happens only once.

## 2. Check the Security screen (superuser)

Portal → gear → **Security**. It shows the starting values:

| Setting | Starting value |
|---|---|
| Idle sign-out, people | 30 min |
| Idle sign-out, shared devices | 10 min |
| Maximum session | 8 h |
| Warning before sign-out | 60 s |
| Sign out when the browser closes | On |

Press **Save** once, even without changes, so the settings are stored in `system/sessionPolicy`.
If Save says *permission-denied*, the plessen-auth rule for `system/{doc}` must allow superusers to write.
The Activity Log records every change under **security**, showing the old value and the new value.

## 3. Test

1. Each system shows the gear at the top left and **← Portal** at the top right. The gear lists your name, role and location, then "Auto sign-out after 30 min idle", then that system's tools, then **Sign Out** in red as the last item.
2. Inventory viewer: the gear has no Settings item. Credentialing viewer: the gear has no Admin item.
3. Security → set idle to **2 min** → Save. On another device, leave a system untouched. The countdown appears at 1:00. Moving the mouse does not dismiss it; only **Stay signed in** does.
4. Let the countdown run out. You are taken to the portal with "signed out after 2 minutes without activity". The Activity Log shows **signin · timeout · reason idle**.
5. Shared-device (generic) account: it signs out after the shared-device limit.
6. Close the browser completely, reopen it and go to the portal. You are asked to sign in.
7. Set the values back (or press **Use starting values**) and Save.

Note: browsers set to "Continue where you left off" can keep the session after closing. The idle limit still applies.
