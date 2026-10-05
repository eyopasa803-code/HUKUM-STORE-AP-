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

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'uye',
      points INTEGER NOT NULL DEFAULT 1000,
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
      created_at TIMESTAMP DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS logs (
      id SERIAL PRIMARY KEY,
      actor TEXT,
      action TEXT,
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);

  // Kurucu hesabını güvenli şekilde oluştur (şifre kodda değil, Render env değişkeninde)
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

// --- AUTH ---
app.post("/auth/register", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password || password.length < 6) {
    return res.status(400).json({ error: "Kullanıcı adı ve en az 6 karakterli şifre gerekli" });
  }
  const exists = await pool.query("SELECT id FROM users WHERE username=$1", [username]);
  if (exists.rows.length > 0) return res.status(400).json({ error: "Bu kullanıcı adı alınmış" });
  const hash = await bcrypt.hash(password, 10);
  const result = await pool.query(
    "INSERT INTO users (username, password_hash) VALUES ($1,$2) RETURNING id, username, role, points",
    [username, hash]
  );
  await logAction(username, "Kayıt oldu");
  const token = jwt.sign({ id: result.rows[0].id, username, role: "uye" }, JWT_SECRET, { expiresIn: "7d" });
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
  const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: "7d" });
  res.json({ token, user: { id: user.id, username: user.username, role: user.role, points: user.points } });
});

// --- USERS ---
app.get("/users", authMiddleware, requireRole("admin"), async (req, res) => {
  const result = await pool.query("SELECT id, username, role, points, created_at FROM users ORDER BY id");
  res.json(result.rows);
});

app.patch("/users/:id/role", authMiddleware, requireRole("co_owner"), async (req, res) => {
  const { role } = req.body;
  if (!ROLE_ORDER.includes(role)) return res.status(400).json({ error: "Geçersiz rol" });
  // kendinden yüksek rol atayamaz (kurucu hariç)
  const myLevel = ROLE_ORDER.indexOf(req.user.role);
  const targetLevel = ROLE_ORDER.indexOf(role);
  if (targetLevel >= myLevel && req.user.role !== "kurucu") {
    return res.status(403).json({ error: "Kendinden yüksek rol atayamazsın" });
  }
  await pool.query("UPDATE users SET role=$1 WHERE id=$2", [role, req.params.id]);
  await logAction(req.user.username, `Kullanıcı #${req.params.id} rolünü ${role} yaptı`);
  res.json({ ok: true });
});

// --- APPS ---
app.get("/apps", async (req, res) => {
  const result = await pool.query(
    "SELECT apps.*, users.username AS dev FROM apps JOIN users ON apps.owner_id = users.id ORDER BY apps.id DESC"
  );
  res.json(result.rows);
});

app.post("/apps", authMiddleware, async (req, res) => {
  const { name, description, cat, icon, code } = req.body;
  if (!name) return res.status(400).json({ error: "İsim gerekli" });
  const token = "HKM-" + Math.random().toString(16).slice(2, 10).toUpperCase();
  const result = await pool.query(
    "INSERT INTO apps (owner_id,name,description,cat,icon,code,token) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *",
    [req.user.id, name, description, cat || "uygulama", icon || "📦", code || "", token]
  );
  await logAction(req.user.username, `Yeni uygulama yayınladı: ${name}`);
  res.json(result.rows[0]);
});

// --- LOGS ---
app.get("/logs", authMiddleware, requireRole("admin"), async (req, res) => {
  const result = await pool.query("SELECT * FROM logs ORDER BY id DESC LIMIT 100");
  res.json(result.rows);
});

app.get("/", (req, res) => res.json({ status: "HÜKÜM API çalışıyor" }));

const PORT = process.env.PORT || 3000;
initDb().then(() => {
  app.listen(PORT, () => console.log("Sunucu çalışıyor, port:", PORT));
});
