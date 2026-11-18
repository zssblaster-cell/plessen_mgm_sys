# Inventory update — rollout

This package also contains the session-timeout / header update. If that is not
deployed yet, deploy everything here in ONE commit and you're covered for both.

## 1. Deploy (one commit)

`index.html` (portal), `crypto.js`, `config-tool.html`, `equipment/index.html`,
`inventory/index.html`, `credentialing/index.html`. Wait for Vercel **Ready**, hard-refresh.

## 2. Publish the Inventory rules

Firebase console → **plessen-inventory** → Firestore → Rules → replace everything with
`rules/plessen-inventory.rules` → **Publish**. (Adds staff undo; nothing else changes.
The TEMPORARY block is still there — it goes in rollout step 8 as before.)

## 3. Security screen (superuser)

Portal → gear → **Security** → new **Inventory** section:
"Staff can undo their removals" (on) and "Undo window for staff" (30 min). Press **Save** once.

## 4. Test

1. Inventory → an item with lots → click **Lots**: only the lots panel opens. Clicking the item name still opens the edit menu.
2. As staff (tech PIN): remove 1 unit → Transaction log shows **↩ Undo** → Undo → PIN → quantity goes back, row shows REVERSED. No "refused" message.
3. As admin: no Undo buttons in the Transaction log.
4. Security → set the window to 1 min → as staff, a removal older than 1 minute has no Undo. Turn "Staff can undo" off → no Undo at all. Put it back to 30 / on.
5. Mark an item inactive → it disappears from Analytics → Overview, Needs Restock and Expiring.
6. Analytics → click an item name (Overview table, Needs Restock card, Expiring row) → its edit menu opens.
7. Needs Restock → **+ Add Stock** → New Transaction opens with that item.
8. **⬇ Excel** on Overview, Needs Restock and Expiring → an .xlsx downloads with what's on screen (current tab and filters).

Note: removals made before this update can't be undone by staff (they have no exact time
stamp the rules can check). Every removal from now on can.
