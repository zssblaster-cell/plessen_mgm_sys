v1.3 — Session timeout, Security screen, Inventory fixes

Features
- All systems: automatic sign-out (idle 30 min, shared devices 10 min, 8 h max, 60 s warning, browser close)
- All systems: shared gear menu showing who you are, with Sign Out last
- Activity Log: records timeouts and security setting changes
- Portal: Security screen for all session limits (superusers)
- Portal: Security screen controls Inventory staff undo (on/off, minutes)
- Portal: sign-in screen explains why someone was signed out
- Inventory: undo is staff-only, within the window set in Security
- Inventory: click an item name in Analytics to open its edit menu
- Inventory: Excel export on Overview, Needs Restock and Expiring
- Config tool: automatic sign-out and sign-out notice
Fixes
- Inventory: Lots button opens only the lots panel
- Inventory: inactive items left out of Analytics
- Inventory: "+ Add Stock" on Needs Restock opens New Transaction with the item
- Inventory: Needs Restock "All" lists each item once
Changes
- All systems: gear menu top left, ← Portal top right
- Portal: Sign Out shown in red
- Equipment: header fits phones
- Inventory: Settings moved into the gear; Logout button removed
- Credentialing: Admin moved into the gear; ↩ removed; "Staff" renamed "Viewer"
Firebase (not in this upload)
- plessen-inventory rules: staff undo, 24 h ceiling
- plessen-repair and plessen-inventory rules: temporary legacy blocks removed
- Old service accounts deleted: equipment-admin@, equipment-viewer@, inventory-admin@, inventory-tech@
Excluded from this build
- none
