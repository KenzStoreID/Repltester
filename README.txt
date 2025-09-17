Bot + Web Project
=================

Contents:
- server.js         (web server + telegram bot)
- index.html        (web UI)
- settings.js       (configuration - replace tokens and IDs)
- users.json        (local users database - contains hashed passwords)
- package.json      (dependencies)
- README.txt        (this file)

Setup:
1. Extract zip and `cd` into the folder.
2. Edit settings.js: set TELEGRAM_BOT_TOKEN, ADMINS (Telegram IDs), GITHUB_REPO, GITHUB_PAT.
3. Run `npm install`.
4. Run `node server.js`.
5. Open `http://localhost:3000` to use the web UI.
Note: numbers.json is expected to live in the GitHub repo defined in settings.js (raw & API access).

Security notes:
- This template logs failed web login attempts to failed_log.json (IP & timestamp).
- It does NOT implement any hidden camera or secret photo capture - that would be illegal.
- Use strong tokens and keep GITHUB_PAT secret.
