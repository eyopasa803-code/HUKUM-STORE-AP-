const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
app.use(cors());
app.use(express.json());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

const JWT_SECRET = process.env.JWT_SECRET;
const ROLE_ORDER = ["uye", "admin", "kidemli_admin", "bas_admin", "co_owner", "owner", "kurucu"];
const BOOST_COST = 2000;
const PUBLISH_COST = 10000;

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'uye',
      points INTEGER NOT NULL DEFAULT 1000,
      plan TEXT DEFAULT '',
      free_slots_used INTEGER NOT NULL DEFAULT 0,
      created_at TIMESTAMP DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS apps (
      id SERIAL PRIMARY KEY,
      owner_id INTEGER REFERENCES users(id),
      name TEXT NOT NULL,
      description TEXT,
      cat TEXT DEFAULT 'uygulama',
      icon TEXT DEFAULT '📦',
      code TEXT,
      ver TEXT DEFAULT '1.0',
      token TEXT,
      distribution TEXT DEFAULT 'free',
      price INTEGER DEFAULT 0,
      boosted_until TIMESTAMP,
      approved BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMP DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS reports (
      id SERIAL PRIMARY KEY,
      reporter_id INTEGER REFERENCES users(id),
      app_id INTEGER REFERENCES apps(id),
      reason TEXT,
      status TEXT NOT NULL DEFAULT 'open',
      created_at TIMESTAMP DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS logs (
      id SERIAL PRIMARY KEY,
      actor TEXT,
      action TEXT,
      created_at TIMESTAMP DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS requests (
      id SERIAL PRIMARY KEY,
      requester_id INTEGER REFERENCES users(id),
      type TEXT NOT NULL,
      target_app_id INTEGER REFERENCES apps(id),
      amount INTEGER DEFAULT 0,
      reason TEXT,
      status TEXT NOT NULL DEFAULT 'pending',
      handled_by TEXT,
      created_at TIMESTAMP DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS installs (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id),
      app_id INTEGER REFERENCES apps(id),
      installed_at TIMESTAMP DEFAULT NOW(),
      UNIQUE(user_id, app_id)
    );
  `);

  const founderUser = process.env.FOUNDER_USERNAME;
  const founderPass = process.env.FOUNDER_PASSWORD;
  if (founderUser && founderPass) {
    const exists = await pool.query("SELECT id FROM users WHERE username=$1", [founderUser]);
    if (exists.rows.length === 0) {
      const hash = await bcrypt.hash(founderPass, 10);
      await pool.query(
        "INSERT INTO users (username, password_hash, role, points) VALUES ($1,$2,'kurucu',999999)",
        [founderUser, hash]
      );
      console.log("Kurucu hesabı oluşturuldu:", founderUser);
    }
  }
}

async function logAction(actor, action) {
  await pool.query("INSERT INTO logs (actor, action) VALUES ($1,$2)", [actor, action]);
}

function authMiddleware(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ error: "Giriş gerekli" });
  const token = header.replace("Bearer ", "");
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (e) {
    return res.status(401).json({ error: "Geçersiz oturum" });
  }
}

function requireRole(minRole) {
  return (req, res, next) => {
    const userLevel = ROLE_ORDER.indexOf(req.user.role);
    const minLevel = ROLE_ORDER.indexOf(minRole);
    if (userLevel < minLevel) return res.status(403).json({ error: "Yetkin yok" });
    next();
  };
}

// ============ AUTH ============
app.post("/auth/register", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password || password.length < 6) {
    return res.status(400).json({ error: "Kullanıcı adı ve en az 6 karakterli şifre gerekli" });
  }
  const exists = await pool.query("SELECT id FROM users WHERE username=$1", [username]);
  if (exists.rows.length > 0) return res.status(400).json({ error: "Bu kullanıcı adı alınmış" });
  const hash = await bcrypt.hash(password, 10);
  const result = await pool.query(
    "INSERT INTO users (username, password_hash) VALUES ($1,$2) RETURNING id, username, role, points, plan",
    [username, hash]
  );
  await logAction(username, "Kayıt oldu");
  const token = jwt.sign({ id: result.rows[0].id, username, role: "uye" }, JWT_SECRET, { expiresIn: "30d" });
  res.json({ token, user: result.rows[0] });
});

app.post("/auth/login", async (req, res) => {
  const { username, password } = req.body;
  const result = await pool.query("SELECT * FROM users WHERE username=$1", [username]);
  if (result.rows.length === 0) return res.status(400).json({ error: "Kullanıcı bulunamadı" });
  const user = result.rows[0];
  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) return res.status(400).json({ error: "Şifre yanlış" });
  await logAction(username, "Giriş yaptı");
  const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: "30d" });
  res.json({ token, user: { id: user.id, username: user.username, role: user.role, points: user.points, plan: user.plan } });
});

app.get("/auth/me", authMiddleware, async (req, res) => {
  const result = await pool.query(
    "SELECT id, username, role, points, plan, free_slots_used FROM users WHERE id=$1",
    [req.user.id]
  );
  if (result.rows.length === 0) return res.status(404).json({ error: "Bulunamadı" });
  res.json(result.rows[0]);
});

// ============ USERS / ROLES ============
app.get("/users", authMiddleware, requireRole("admin"), async (req, res) => {
  const result = await pool.query(
    "SELECT id, username, role, points, plan, created_at FROM users ORDER BY id"
  );
  res.json(result.rows);
});

app.patch("/users/:id/role", authMiddleware, requireRole("co_owner"), async (req, res) => {
  const { role } = req.body;
  if (!ROLE_ORDER.includes(role)) return res.status(400).json({ error: "Geçersiz rol" });
  const myLevel = ROLE_ORDER.indexOf(req.user.role);
  const targetLevel = ROLE_ORDER.indexOf(role);
  if (targetLevel >= myLevel && req.user.role !== "kurucu") {
    return res.status(403).json({ error: "Kendinden yüksek veya eşit rol atayamazsın" });
  }
  await pool.query("UPDATE users SET role=$1 WHERE id=$2", [role, req.params.id]);
  await logAction(req.user.username, `Kullanıcı #${req.params.id} rolünü ${role} yaptı`);
  res.json({ ok: true });
});

app.patch("/users/:id/points", authMiddleware, requireRole("bas_admin"), async (req, res) => {
  const { amount, reason } = req.body;
  if (typeof amount !== "number") return res.status(400).json({ error: "Geçersiz miktar" });
  await pool.query("UPDATE users SET points = GREATEST(points + $1, 0) WHERE id=$2", [amount, req.params.id]);
  await logAction(req.user.username, `Kullanıcı #${req.params.id} puanını ${amount >= 0 ? "+" : ""}${amount} değiştirdi (${reason || "sebep yok"})`);
  res.json({ ok: true });
});

// ============ APPS ============
app.get("/apps", async (req, res) => {
  const result = await pool.query(
    `SELECT apps.*, users.username AS dev FROM apps
     JOIN users ON apps.owner_id = users.id
     WHERE approved = TRUE
     ORDER BY (boosted_until IS NOT NULL AND boosted_until > NOW()) DESC, apps.id DESC`
  );
  res.json(result.rows);
});

// Kendi uygulamalarım: onaylı/beklemede hepsini görürüm
app.get("/apps/mine", authMiddleware, async (req, res) => {
  const result = await pool.query(
    `SELECT apps.*, users.username AS dev FROM apps
     JOIN users ON apps.owner_id = users.id
     WHERE owner_id = $1 ORDER BY apps.id DESC`,
    [req.user.id]
  );
  res.json(result.rows);
});

// Moderasyon kuyruğu (admin+)
app.get("/apps/pending", authMiddleware, requireRole("admin"), async (req, res) => {
  const result = await pool.query(
    `SELECT apps.*, users.username AS dev FROM apps
     JOIN users ON apps.owner_id = users.id
     WHERE approved = FALSE ORDER BY apps.id ASC`
  );
  res.json(result.rows);
});

app.patch("/apps/:id/approve", authMiddleware, requireRole("admin"), async (req, res) => {
  const { approve } = req.body; // true onayla, false reddet(sil)
  if (approve) {
    await pool.query("UPDATE apps SET approved = TRUE WHERE id=$1", [req.params.id]);
    await logAction(req.user.username, `Uygulama #${req.params.id} onaylandı`);
  } else {
    await pool.query("DELETE FROM apps WHERE id=$1", [req.params.id]);
    await logAction(req.user.username, `Uygulama #${req.params.id} reddedildi/silindi`);
  }
  res.json({ ok: true });
});

// Şikayet sistemi
app.post("/reports", authMiddleware, async (req, res) => {
  const { appId, reason } = req.body;
  await pool.query("INSERT INTO reports (reporter_id, app_id, reason) VALUES ($1,$2,$3)", [req.user.id, appId, reason || ""]);
  await logAction(req.user.username, `Uygulama #${appId} şikayet edildi: ${reason || "sebep yok"}`);
  res.json({ ok: true });
});

app.get("/reports", authMiddleware, requireRole("admin"), async (req, res) => {
  const result = await pool.query(
    `SELECT reports.*, u.username AS reporter, a.name AS app_name FROM reports
     JOIN users u ON reports.reporter_id = u.id
     JOIN apps a ON reports.app_id = a.id
     WHERE status='open' ORDER BY reports.id DESC`
  );
  res.json(result.rows);
});

app.patch("/reports/:id/resolve", authMiddleware, requireRole("admin"), async (req, res) => {
  await pool.query("UPDATE reports SET status='resolved' WHERE id=$1", [req.params.id]);
  res.json({ ok: true });
});

app.post("/apps", authMiddleware, async (req, res) => {
  const { name, description, cat, icon, code, distribution, price } = req.body;
  if (!name) return res.status(400).json({ error: "İsim gerekli" });

  const userRes = await pool.query("SELECT * FROM users WHERE id=$1", [req.user.id]);
  const user = userRes.rows[0];
  const freeSlotsByPlan = { bronz: 1, plus: 3, premium: 7, gold: 15, elmas: 999 };
  const freeSlots = freeSlotsByPlan[user.plan] || 0;

  if (user.free_slots_used < freeSlots) {
    await pool.query("UPDATE users SET free_slots_used = free_slots_used + 1 WHERE id=$1", [user.id]);
  } else {
    if (user.points < PUBLISH_COST) {
      return res.status(400).json({ error: `Yetersiz puan. Gereken: ${PUBLISH_COST}` });
    }
    await pool.query("UPDATE users SET points = points - $1 WHERE id=$2", [PUBLISH_COST, user.id]);
  }

  const token = "HKM-" + Math.random().toString(16).slice(2, 10).toUpperCase();
  const dist = ["free", "paid", "gift", "offer"].includes(distribution) ? distribution : "free";
  const result = await pool.query(
    `INSERT INTO apps (owner_id,name,description,cat,icon,code,token,distribution,price,approved)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,FALSE) RETURNING *`,
    [user.id, name, description, cat || "uygulama", icon || "📦", code || "", token, dist, Math.min(price || 0, 30000)]
  );
  await logAction(req.user.username, `Yeni uygulama yayınladı (onay bekliyor): ${name}`);
  res.json(result.rows[0]);
});

app.patch("/apps/:id/code", authMiddleware, async (req, res) => {
  const { token, code } = req.body;
  const appRes = await pool.query("SELECT * FROM apps WHERE id=$1", [req.params.id]);
  if (appRes.rows.length === 0) return res.status(404).json({ error: "Uygulama bulunamadı" });
  const appRow = appRes.rows[0];
  if (appRow.token !== token) return res.status(403).json({ error: "Token yanlış" });
  const parts = appRow.ver.split(".");
  const newVer = parts[0] + "." + (parseInt(parts[1] || "0", 10) + 1);
  await pool.query("UPDATE apps SET code=$1, ver=$2 WHERE id=$3", [code, newVer, req.params.id]);
  await logAction(req.user.username, `Uygulama güncellendi: ${appRow.name} (v${newVer})`);
  res.json({ ok: true, ver: newVer });
});

app.post("/apps/:id/boost", authMiddleware, async (req, res) => {
  const userRes = await pool.query("SELECT * FROM users WHERE id=$1", [req.user.id]);
  const user = userRes.rows[0];
  if (user.points < BOOST_COST) return res.status(400).json({ error: "Yetersiz puan" });
  await pool.query("UPDATE users SET points = points - $1 WHERE id=$2", [BOOST_COST, user.id]);
  await pool.query("UPDATE apps SET boosted_until = NOW() + INTERVAL '24 hours' WHERE id=$1", [req.params.id]);
  await logAction(req.user.username, `Uygulama #${req.params.id} öne çıkarıldı`);
  res.json({ ok: true });
});

// ============ INSTALLS ============
app.post("/installs", authMiddleware, async (req, res) => {
  const { appId } = req.body;
  await pool.query(
    "INSERT INTO installs (user_id, app_id) VALUES ($1,$2) ON CONFLICT DO NOTHING",
    [req.user.id, appId]
  );
  res.json({ ok: true });
});

app.delete("/installs/:appId", authMiddleware, async (req, res) => {
  await pool.query("DELETE FROM installs WHERE user_id=$1 AND app_id=$2", [req.user.id, req.params.appId]);
  res.json({ ok: true });
});

app.get("/installs", authMiddleware, async (req, res) => {
  const result = await pool.query("SELECT app_id FROM installs WHERE user_id=$1", [req.user.id]);
  res.json(result.rows.map(r => r.app_id));
});

// ============ REQUESTS (talep sistemi: puan talebi, ücretli uygulama talebi) ============
app.post("/requests", authMiddleware, async (req, res) => {
  const { type, targetAppId, amount, reason } = req.body;
  if (!["points", "app_access"].includes(type)) return res.status(400).json({ error: "Geçersiz talep türü" });
  const result = await pool.query(
    `INSERT INTO requests (requester_id, type, target_app_id, amount, reason)
     VALUES ($1,$2,$3,$4,$5) RETURNING *`,
    [req.user.id, type, targetAppId || null, amount || 0, reason || ""]
  );
  await logAction(req.user.username, `Talep oluşturdu: ${type} (${reason || "sebep yok"})`);
  res.json(result.rows[0]);
});

app.get("/requests", authMiddleware, requireRole("admin"), async (req, res) => {
  const result = await pool.query(
    `SELECT requests.*, users.username AS requester FROM requests
     JOIN users ON requests.requester_id = users.id
     WHERE status='pending' ORDER BY requests.id DESC`
  );
  res.json(result.rows);
});

app.patch("/requests/:id", authMiddleware, requireRole("admin"), async (req, res) => {
  const { action } = req.body; // "approve" | "deny"
  const reqRes = await pool.query("SELECT * FROM requests WHERE id=$1", [req.params.id]);
  if (reqRes.rows.length === 0) return res.status(404).json({ error: "Talep bulunamadı" });
  const request = reqRes.rows[0];
  if (request.status !== "pending") return res.status(400).json({ error: "Talep zaten işlendi" });

  if (action === "approve") {
    if (request.type === "points") {
      await pool.query("UPDATE users SET points = points + $1 WHERE id=$2", [request.amount, request.requester_id]);
    } else if (request.type === "app_access") {
      await pool.query(
        "INSERT INTO installs (user_id, app_id) VALUES ($1,$2) ON CONFLICT DO NOTHING",
        [request.requester_id, request.target_app_id]
      );
    }
  }
  await pool.query(
    "UPDATE requests SET status=$1, handled_by=$2 WHERE id=$3",
    [action === "approve" ? "approved" : "denied", req.user.username, req.params.id]
  );
  await logAction(req.user.username, `Talep #${req.params.id} ${action === "approve" ? "onaylandı" : "reddedildi"}`);
  res.json({ ok: true });
});

// ============ PLANS ============
app.post("/plans/:planId", authMiddleware, async (req, res) => {
  const plans = {
    bronz: 2000, plus: 5000, premium: 10000, gold: 20000, elmas: 40000
  };
  const planId = req.params.planId;
  if (!plans[planId]) return res.status(400).json({ error: "Geçersiz paket" });
  await pool.query("UPDATE users SET plan=$1, free_slots_used=0, points = points + $2 WHERE id=$3",
    [planId, plans[planId], req.user.id]);
  await logAction(req.user.username, `${planId} paketini seçti`);
  res.json({ ok: true });
});

// ============ LOGS ============
app.get("/logs", authMiddleware, requireRole("admin"), async (req, res) => {
  const result = await pool.query("SELECT * FROM logs ORDER BY id DESC LIMIT 150");
  res.json(result.rows);
});

app.get("/", (req, res) => res.json({ status: "HÜKÜM API çalışıyor" }));

const PORT = process.env.PORT || 3000;
initDb().then(() => {
  app.listen(PORT, () => console.log("Sunucu çalışıyor, port:", PORT));
}).catch(err => console.error("DB başlatma hatası:", err));
