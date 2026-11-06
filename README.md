# Akuma Discord authentication service

A small HTTPS-backed HTTP service for Discord OAuth2 and guild membership checks. It does not need a Discord Gateway connection. The bot must be installed in the guild. No bot/client secrets or Discord user tokens go into the desktop app. This prototype has not been validated with an actual Discord account or production traffic.

## Security: rotate any exposed token first

In Discord Developer Portal > Application > Bot > Reset Token. Never commit a token or OAuth client secret to source, logs, or the client. The original token shared in chat must not be used. If that bot had elevated permissions, review server Audit Log and its roles. Use minimum bot permissions.

## Render deployment

1. Create a private Git repository with the `auth-server` directory, and deploy it as a **Web Service** on Render. Use Node 20+; root directory `auth-server` (or project root if only that folder is uploaded), build command `npm install`, start command `npm start`. Use HTTPS origin provided by Render.
2. In Discord Developer Portal, configure OAuth2 redirect URL exactly `https://YOUR-SERVICE.onrender.com/oauth/callback`. Configure user installation if required for OAuth. Install the bot in the Akuma server; `bot` scope is needed at installation time. The user login requests only `identify`. No privileged server-members gateway intent is needed for the per-user REST lookup.
3. Add environment variables in Render: `PUBLIC_URL=https://YOUR-SERVICE.onrender.com`, `DISCORD_CLIENT_ID` (the application's **Application ID**, not the server ID), `DISCORD_CLIENT_SECRET` (OAuth2 client secret), `DISCORD_BOT_TOKEN` (new token after reset), and `DISCORD_GUILD_ID=1558780910634147892`. Set secrets as Render secret environment variables; do not put their values into the repository or desktop distribution. Render supplies `PORT`. Restart/redeploy after changes.
4. Check `https://YOUR-SERVICE.onrender.com/health`, then set the file `auth-server.txt` beside `Akuma.exe` to **only** that HTTPS origin, e.g. `https://YOUR-SERVICE.onrender.com` followed by a newline. Only an HTTPS *.onrender.com origin is accepted by the desktop build. Replace before distributing; do not include a token.
5. Run the full flow with an account in the server, one not in the server, join and retry, sign out, and check removal after sign-in. Test real Discord errors and restarts. Do not ship as a production security boundary without a security review and real acceptance testing.

Run local tests using `npm test`; tests use fake Discord responses and no credentials. The service stores sessions and pending flows only in memory. Free Render web services sleep after inactivity and may restart at any time, so users can need to sign in again; waking may take around a minute. No persistent database or guaranteed availability is included. Session maximum lifetime is 12 hours, with membership rechecked by the client roughly every two minutes. Network failure stops queues and requires sign-in again. Signing out immediately removes the local session and makes a best-effort server logout; the session expires at most 12 hours after issuance. Browser authorization can separately be revoked in Discord Settings > Authorized Apps.

The server performs authorization code exchange with state and PKCE, keeps Discord secrets server-side, checks membership using Discord REST, and distinguishes an unknown member from service/configuration failures. The desktop EXE is user-controlled and can be modified; local gating is not tamper-proof. If future services run on your server, enforce authorization and membership on those service endpoints too. No guarantee is made for uninterrupted service on Render's free tier.
