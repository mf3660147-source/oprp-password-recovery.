const express = require("express");
const crypto = require("crypto");
const db = require("../config/database");

const router = express.Router();
router.use(express.urlencoded({ extended: false }));
router.use(express.json());

const APP_URL = (process.env.APP_URL || "").replace(/\/$/, "");
const DISCORD_CLIENT_ID = process.env.DISCORD_CLIENT_ID;
const DISCORD_CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET;
const DISCORD_REDIRECT_URI = process.env.DISCORD_REDIRECT_URI;
const RECOVERY_SECRET = process.env.RECOVERY_SECRET;

function requireConfig(res) {
  if (!APP_URL || !DISCORD_CLIENT_ID || !DISCORD_CLIENT_SECRET ||
      !DISCORD_REDIRECT_URI || !RECOVERY_SECRET) {
    res.status(500).send("Recovery service is not configured.");
    return false;
  }
  return true;
}

function hmac(value) {
  return crypto.createHmac("sha256", RECOVERY_SECRET).update(value).digest("hex");
}

function createState(token) {
  const payload = Buffer.from(JSON.stringify({
    token,
    exp: Date.now() + 10 * 60 * 1000
  })).toString("base64url");
  return `${payload}.${hmac(payload)}`;
}

function readState(state) {
  const [payload, signature] = String(state || "").split(".");
  if (!payload || !signature ||
      !crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(hmac(payload)))) {
    throw new Error("Invalid state");
  }
  const data = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
  if (!data.exp || Date.now() > data.exp) throw new Error("Expired state");
  return data;
}

function hashToken(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}

router.get("/", (req, res) => {
  const token = String(req.query.token || "");
  if (!token) return res.status(400).send("Missing recovery token.");
  res.send(`<!doctype html><meta name="viewport" content="width=device-width,initial-scale=1">
  <title>OPRP Password Recovery</title>
  <body style="font-family:Arial;max-width:420px;margin:40px auto;padding:20px;background:#09090d;color:white">
  <h2>OPRP Password Recovery</h2>
  <p>Continue with Discord to verify your identity.</p>
  <a href="/recovery/discord?token=${encodeURIComponent(token)}"
     style="display:inline-block;padding:12px 18px;background:#e21b2d;color:white;text-decoration:none;border-radius:6px">
     Continue with Discord
  </a></body>`);
});

router.get("/discord", (req, res) => {
  if (!requireConfig(res)) return;
  const token = String(req.query.token || "");
  if (!/^[A-Za-z0-9_-]{32,}$/.test(token)) {
    return res.status(400).send("Invalid token format.");
  }
  const state = createState(token);
  const params = new URLSearchParams({
    client_id: DISCORD_CLIENT_ID,
    response_type: "code",
    redirect_uri: DISCORD_REDIRECT_URI,
    scope: "identify",
    state
  });
  res.redirect(`https://discord.com/oauth2/authorize?${params.toString()}`);
});

router.get("/callback", async (req, res) => {
  try {
    if (!requireConfig(res)) return;
    const { code, state } = req.query;
    const { token } = readState(state);

    const tokenResponse = await fetch("https://discord.com/api/oauth2/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: DISCORD_CLIENT_ID,
        client_secret: DISCORD_CLIENT_SECRET,
        grant_type: "authorization_code",
        code: String(code || ""),
        redirect_uri: DISCORD_REDIRECT_URI
      })
    });
    if (!tokenResponse.ok) return res.status(401).send("Discord authorization failed.");
    const oauth = await tokenResponse.json();

    const userResponse = await fetch("https://discord.com/api/users/@me", {
      headers: { Authorization: `${oauth.token_type} ${oauth.access_token}` }
    });
    if (!userResponse.ok) return res.status(401).send("Could not verify Discord account.");
    const discordUser = await userResponse.json();

    const tokenHash = hashToken(token);
    const [rows] = await db.query(
      `SELECT id, uid, discord_id, expires_at, used_at
       FROM password_recovery_tokens
       WHERE token_hash = ? LIMIT 1`, [tokenHash]
    );
    if (!rows.length) return res.status(403).send("Invalid recovery token.");
    const record = rows[0];

    if (record.used_at || new Date(record.expires_at).getTime() <= Date.now()) {
      return res.status(403).send("This recovery token is expired or already used.");
    }
    if (String(record.discord_id) !== String(discordUser.id)) {
      return res.status(403).send("This Discord account is not authorized for this recovery request.");
    }

    // Deliberately no password update is performed here.
    // Connect the game's verified WP_Hash-compatible reset adapter only after testing.
    res.send(`<!doctype html><meta name="viewport" content="width=device-width,initial-scale=1">
    <title>OPRP Recovery Verification</title>
    <body style="font-family:Arial;max-width:420px;margin:40px auto;padding:20px">
    <h2>Discord verified ✅</h2>
    <p>Recovery token is valid for user ID ${record.uid}.</p>
    <p>The password reset adapter is not enabled yet. This prevents incompatible hashing from breaking game login.</p>
    </body>`);
  } catch (error) {
    console.error("Recovery callback error:", error.message);
    res.status(400).send("Recovery verification failed.");
  }
});

module.exports = router;
