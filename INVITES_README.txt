===========================================
INVITE SYSTEM - ADMIN GUIDE
===========================================

The registration system is now INVITE-ONLY.

To manage invite codes:
1. Edit the file: backend/invites.json
2. Add or remove invite codes in the "invites" array
3. Restart the server for changes to take effect

Example invites.json:
{
  "invites": [
    "INVITE-2024-ALPHA",
    "INVITE-2024-BETA",
    "YOUR-CUSTOM-CODE"
  ]
}

IMPORTANT:
- This file is NOT accessible via the web
- It's in the backend root, not in the public folder
- Keep it secure and don't commit it to public repos
- The .gitignore already excludes this file

To add new invites:
1. Open backend/invites.json
2. Add your invite code to the "invites" array
3. Save the file
4. Restart the server

Current invite codes are in: backend/invites.json


