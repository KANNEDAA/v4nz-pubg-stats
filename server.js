// ═══════════════════════════════════════════════
//  V4NZ PUBG Stats — Server + Clan API
//  Proxy PUBG API + PostgreSQL clan system
//  rivalidades-v1-sec-hotfix1 — whitelist estáticos solo sobre rutas de 1 segmento (arregla 404 en endpoints API con IDs con puntos: account., season., division., etc)
// ═══════════════════════════════════════════════

const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const compression = require('compression');
const crypto = require('crypto');
let sharp;
try { sharp = require('sharp'); } catch(e) { console.warn('⚠️  sharp not installed — OG images will serve as SVG fallback'); }

// Single dynamic import for node-fetch (ESM)
const fetch = (...args) => import('node-fetch').then(({default: f}) => f(...args));

// Cache index.html in memory (reload on file change in dev, or every 5min in prod)
let _cachedHtml = fs.readFileSync(path.join(__dirname, 'index.html'), 'utf8');
if (!process.env.RAILWAY_ENVIRONMENT) {
  fs.watchFile(path.join(__dirname, 'index.html'), { interval: 2000 }, () => {
    try { _cachedHtml = fs.readFileSync(path.join(__dirname, 'index.html'), 'utf8'); console.log('[HTML cache] reloaded'); } catch(e) {}
  });
} else {
  setInterval(() => { try { _cachedHtml = fs.readFileSync(path.join(__dirname, 'index.html'), 'utf8'); } catch(e) {} }, 300000);
}

const app = express();
const PORT = process.env.PORT || 3000;
const SERVER_API_KEY = process.env.PUBG_API_KEY || '';
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
const DISCORD_CLIENT_ID = process.env.DISCORD_CLIENT_ID || '';
const DISCORD_CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET || '';
const DISCORD_REDIRECT_URI = process.env.DISCORD_REDIRECT_URI || 'https://v4nz.com/auth/discord/callback';

// PostgreSQL connection (Railway provides DATABASE_URL automatically)
const pool = process.env.DATABASE_URL ? new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  max: 20,                        // Max connections (default was 10)
  idleTimeoutMillis: 30000,       // Close idle connections after 30s
  connectionTimeoutMillis: 5000   // Fail fast if can't connect in 5s
}) : null;

// ═══ PERFORMANCE: Fetch with timeout helper ═══
function fetchWithTimeout(fetchFn, url, options = {}, timeoutMs = 10000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  return fetchFn(url, { ...options, signal: controller.signal }).finally(() => clearTimeout(timer));
}

// ═══ PERFORMANCE: Gzip compression ═══
app.use(compression());

// ═══ SECURITY: CORS restricted to v4nz.com only ═══
app.use(cors({
  origin: ['https://v4nz.com', 'https://www.v4nz.com', 'http://localhost:3000'],
  credentials: true
}));
app.use(express.json());

// ═══ SECURITY HEADERS + CSP ═══
app.use((req, res, next) => {
  // Basic security headers
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), interest-cohort=()');
  // Content Security Policy
  const csp = [
    "default-src 'self'",
    "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://www.googletagmanager.com",
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
    "font-src 'self' https://fonts.gstatic.com",
    "img-src 'self' data: blob: https://cdn.discordapp.com https://v4nz.com https://www.googletagmanager.com https://www.google-analytics.com",
    "connect-src 'self' https://api.pubg.com https://telemetry-cdn.pubg.com https://api.pubg.report https://discord.com https://www.google-analytics.com https://analytics.google.com https://www.googletagmanager.com https://region1.google-analytics.com",
    "frame-src https://open.spotify.com https://discord.com",
    "media-src 'none'",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self' https://discord.com"
  ].join('; ');
  res.setHeader('Content-Security-Policy', csp);
  next();
});

// ═══ COOKIE HELPER ═══
function parseCookies(req) {
  const cookies = {};
  (req.headers.cookie || '').split(';').forEach(c => {
    const [k, ...v] = c.trim().split('=');
    if (k) cookies[k] = decodeURIComponent(v.join('='));
  });
  return cookies;
}
function setAuthCookie(res, token) {
  const isProduction = process.env.NODE_ENV === 'production' || process.env.RAILWAY_ENVIRONMENT;
  res.append('Set-Cookie', `v4nz_token=${token}; HttpOnly; ${isProduction ? 'Secure; ' : ''}SameSite=Lax; Path=/; Max-Age=${30 * 24 * 3600}`);
}
function clearAuthCookie(res) {
  const isProduction = process.env.NODE_ENV === 'production' || process.env.RAILWAY_ENVIRONMENT;
  res.append('Set-Cookie', `v4nz_token=; HttpOnly; ${isProduction ? 'Secure; ' : ''}SameSite=Lax; Path=/; Max-Age=0`);
}

// ═══ WHITELIST de estáticos (rivalidades-v1-sec) ═══
// Bloquea server.js, package.json, package-lock.json, .env, etc del express.static abajo.
// Permite solo extensiones legítimas de frontend + nombres concretos.
const ALLOWED_STATIC_EXT = /\.(html|css|js|mjs|map|png|jpg|jpeg|gif|svg|ico|webp|avif|woff2?|ttf|eot|mp3|mp4|webm|webmanifest|xml|txt|json)$/i;
const BLOCKED_STATIC_NAMES = new Set([
  'server.js',
  'package.json',
  'package-lock.json',
  'yarn.lock',
  'pnpm-lock.yaml',
  '.env',
  '.env.local',
  '.env.production',
  'railway.toml',
  'railway.json',
  'Dockerfile',
  'docker-compose.yml',
  'v4nz-deploy.ps1',
  'README.md',
  '.gitignore',
  '.dockerignore'
]);
app.use((req, res, next) => {
  const p = req.path;
  if (p === '/' || p.endsWith('/')) return next();
  // Solo vigilar rutas de un único segmento (archivos del root tipo /server.js).
  // Las rutas anidadas como /api/shards/psn/players/account.XXX/seasons/division.bro.official.console-41
  // contienen IDs con puntos (account., division., match., etc) y NO deben bloquearse aquí —
  // son endpoints API que van a su propio handler.
  const segments = p.split('/').filter(Boolean);
  if (segments.length !== 1) return next();
  const name = decodeURIComponent(segments[0]).toLowerCase();
  // Dotfiles (.env, .git, etc) — bloqueo explícito
  if (name.startsWith('.')) return res.status(404).type('text').send('Not found');
  // Archivos con nombres sensibles conocidos — bloqueo explícito
  if (BLOCKED_STATIC_NAMES.has(name)) return res.status(404).type('text').send('Not found');
  // Si el path tiene un punto (parece archivo) y la extensión NO está permitida — bloquear
  if (name.includes('.') && !ALLOWED_STATIC_EXT.test(name)) {
    return res.status(404).type('text').send('Not found');
  }
  next();
});

app.use(express.static(path.join(__dirname), {
  maxAge: '7d',
  dotfiles: 'deny',
  setHeaders: (res, filePath) => {
    // HTML always fresh (SPA with dynamic meta)
    if (filePath.endsWith('.html')) {
      res.setHeader('Cache-Control', 'no-cache');
    }
    // Service worker must not be cached aggressively
    else if (filePath.endsWith('sw.js')) {
      res.setHeader('Cache-Control', 'no-cache');
    }
  }
}));

// ═══ AUTO-CREATE TABLES ═══
async function initDB() {
  if (!pool) { console.log('⚠ No DATABASE_URL — clan API disabled (localStorage mode)'); return; }
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS clans (
        tag VARCHAR(20) PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        member_count INT DEFAULT 0,
        level INT DEFAULT 0,
        platform VARCHAR(10) DEFAULT 'psn',
        registered_by VARCHAR(50),
        total_kills INT DEFAULT 0,
        total_wins INT DEFAULT 0,
        avg_kd NUMERIC(6,2) DEFAULT 0,
        avg_damage NUMERIC(12,1) DEFAULT 0,
        total_rounds INT DEFAULT 0,
        win_rate NUMERIC(6,2) DEFAULT 0,
        active_members INT DEFAULT 0,
        stats_updated_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        updated_at TIMESTAMPTZ DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS clan_members (
        id SERIAL PRIMARY KEY,
        clan_tag VARCHAR(20) REFERENCES clans(tag) ON DELETE CASCADE,
        player_name VARCHAR(50) NOT NULL,
        kills INT DEFAULT 0,
        wins INT DEFAULT 0,
        kd NUMERIC(6,2) DEFAULT 0,
        damage NUMERIC(12,1) DEFAULT 0,
        rounds INT DEFAULT 0,
        active BOOLEAN DEFAULT true,
        added_by VARCHAR(50),
        created_at TIMESTAMPTZ DEFAULT NOW(),
        UNIQUE(clan_tag, player_name)
      );
      CREATE INDEX IF NOT EXISTS idx_clan_members_tag ON clan_members(clan_tag);
      CREATE INDEX IF NOT EXISTS idx_clans_kills ON clans(total_kills DESC);
      CREATE INDEX IF NOT EXISTS idx_clans_kd ON clans(avg_kd DESC);
      CREATE TABLE IF NOT EXISTS member_requests (
        id SERIAL PRIMARY KEY,
        clan_tag VARCHAR(20) NOT NULL,
        player_name VARCHAR(50) NOT NULL,
        requested_by VARCHAR(50) DEFAULT 'web_user',
        status VARCHAR(20) DEFAULT 'pending',
        reviewed_by VARCHAR(50),
        created_at TIMESTAMPTZ DEFAULT NOW(),
        reviewed_at TIMESTAMPTZ,
        UNIQUE(clan_tag, player_name, status)
      );
      CREATE INDEX IF NOT EXISTS idx_member_requests_pending ON member_requests(status) WHERE status = 'pending';
      CREATE TABLE IF NOT EXISTS api_cache (
        cache_key VARCHAR(500) PRIMARY KEY,
        response_data TEXT NOT NULL,
        status_code INT DEFAULT 200,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
      CREATE INDEX IF NOT EXISTS idx_api_cache_created ON api_cache(created_at);
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) UNIQUE,
        password_hash VARCHAR(255),
        discord_id VARCHAR(50) UNIQUE,
        discord_name VARCHAR(100),
        display_name VARCHAR(50) NOT NULL,
        gamertag VARCHAR(50),
        platform VARCHAR(10) DEFAULT 'psn',
        avatar_url TEXT,
        news_opt_in BOOLEAN DEFAULT false,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        last_login TIMESTAMPTZ DEFAULT NOW()
      );
      CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
      CREATE INDEX IF NOT EXISTS idx_users_discord ON users(discord_id);
      -- Migration: add news_opt_in column if missing
      ALTER TABLE users ADD COLUMN IF NOT EXISTS news_opt_in BOOLEAN DEFAULT false;
      CREATE TABLE IF NOT EXISTS user_favorites (
        id SERIAL PRIMARY KEY,
        user_id INT REFERENCES users(id) ON DELETE CASCADE,
        fav_type VARCHAR(10) DEFAULT 'player',
        name VARCHAR(50) NOT NULL,
        platform VARCHAR(10) DEFAULT 'psn',
        fav_group VARCHAR(30) DEFAULT '',
        added_at TIMESTAMPTZ DEFAULT NOW(),
        UNIQUE(user_id, fav_type, name)
      );
      CREATE INDEX IF NOT EXISTS idx_user_favorites_user ON user_favorites(user_id);
      CREATE TABLE IF NOT EXISTS player_snapshots (
        id SERIAL PRIMARY KEY,
        player_name VARCHAR(50) NOT NULL,
        platform VARCHAR(10) DEFAULT 'psn',
        squad_mode VARCHAR(20) DEFAULT 'squad',
        game_mode VARCHAR(10) DEFAULT 'tpp',
        kd NUMERIC(6,2) DEFAULT 0,
        win_rate NUMERIC(6,2) DEFAULT 0,
        avg_damage NUMERIC(10,1) DEFAULT 0,
        hs_rate NUMERIC(6,2) DEFAULT 0,
        kills INT DEFAULT 0,
        wins INT DEFAULT 0,
        rounds INT DEFAULT 0,
        top10_rate NUMERIC(6,2) DEFAULT 0,
        longest_kill NUMERIC(8,1) DEFAULT 0,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
      CREATE INDEX IF NOT EXISTS idx_snapshots_player ON player_snapshots(player_name, platform, squad_mode, game_mode);
      CREATE INDEX IF NOT EXISTS idx_snapshots_created ON player_snapshots(created_at);

      CREATE TABLE IF NOT EXISTS clan_snapshots (
        id SERIAL PRIMARY KEY,
        clan_tag VARCHAR(20) NOT NULL,
        total_kills INT DEFAULT 0,
        total_wins INT DEFAULT 0,
        avg_kd NUMERIC(6,2) DEFAULT 0,
        avg_damage NUMERIC(12,1) DEFAULT 0,
        win_rate NUMERIC(6,2) DEFAULT 0,
        active_members INT DEFAULT 0,
        total_rounds INT DEFAULT 0,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
      CREATE INDEX IF NOT EXISTS idx_clan_snapshots_tag ON clan_snapshots(clan_tag, created_at);

      CREATE TABLE IF NOT EXISTS clan_transfers (
        id SERIAL PRIMARY KEY,
        player_name VARCHAR(50) NOT NULL,
        from_clan VARCHAR(20),
        to_clan VARCHAR(20),
        platform VARCHAR(10) DEFAULT 'psn',
        detected_at TIMESTAMPTZ DEFAULT NOW()
      );
      CREATE INDEX IF NOT EXISTS idx_clan_transfers_clan ON clan_transfers(to_clan, detected_at);
      CREATE INDEX IF NOT EXISTS idx_clan_transfers_player ON clan_transfers(player_name);

      CREATE TABLE IF NOT EXISTS player_name_history (
        id SERIAL PRIMARY KEY,
        account_id VARCHAR(100) NOT NULL,
        old_name VARCHAR(50) NOT NULL,
        new_name VARCHAR(50) NOT NULL,
        platform VARCHAR(10) DEFAULT 'psn',
        detected_at TIMESTAMPTZ DEFAULT NOW()
      );
      CREATE INDEX IF NOT EXISTS idx_name_history_account ON player_name_history(account_id);
      CREATE INDEX IF NOT EXISTS idx_name_history_new ON player_name_history(new_name);
      CREATE INDEX IF NOT EXISTS idx_name_history_old ON player_name_history(old_name);

      CREATE TABLE IF NOT EXISTS player_accounts (
        account_id VARCHAR(100) PRIMARY KEY,
        player_name VARCHAR(50) NOT NULL,
        platform VARCHAR(10) DEFAULT 'psn',
        updated_at TIMESTAMPTZ DEFAULT NOW()
      );
      CREATE INDEX IF NOT EXISTS idx_player_accounts_name ON player_accounts(player_name);

      -- rivalidades-v1: kill_events entre jugadores de clanes registrados
      CREATE TABLE IF NOT EXISTS kill_events (
        id SERIAL PRIMARY KEY,
        match_id VARCHAR(50) NOT NULL,
        killer_name VARCHAR(50) NOT NULL,
        victim_name VARCHAR(50) NOT NULL,
        killer_clan VARCHAR(20),
        victim_clan VARCHAR(20),
        platform VARCHAR(10) DEFAULT 'psn',
        game_mode VARCHAR(20),
        occurred_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        UNIQUE(match_id, killer_name, victim_name)
      );
      CREATE INDEX IF NOT EXISTS idx_kill_events_killer_clan ON kill_events(killer_clan) WHERE killer_clan IS NOT NULL;
      CREATE INDEX IF NOT EXISTS idx_kill_events_victim_clan ON kill_events(victim_clan) WHERE victim_clan IS NOT NULL;
      CREATE INDEX IF NOT EXISTS idx_kill_events_match ON kill_events(match_id);

      -- match-insights-v1: Radiografia del match - cache por (match, jugador) del analisis profundo.
      -- I-0a crea la mesa con placeholders; I-1..I-6 iran rellenando calculos reales por bloques.
      CREATE TABLE IF NOT EXISTS match_insights (
        match_id    VARCHAR(50) NOT NULL,
        player_name VARCHAR(50) NOT NULL,
        platform    VARCHAR(10) NOT NULL DEFAULT 'psn',
        status      VARCHAR(12) NOT NULL DEFAULT 'pending',
        insights    JSONB,
        error_msg   TEXT,
        version     INT NOT NULL DEFAULT 1,
        computed_at TIMESTAMPTZ,
        created_at  TIMESTAMPTZ DEFAULT NOW(),
        PRIMARY KEY (match_id, player_name, platform)
      );
      CREATE INDEX IF NOT EXISTS idx_match_insights_inflight ON match_insights(status) WHERE status IN ('pending','computing');
      CREATE INDEX IF NOT EXISTS idx_match_insights_created ON match_insights(created_at);
    `);
    // Cleanup old cache entries on startup (older than 1 hour) — EXCLUYE telemetry_* que tiene vida de 30 días (rivalidades-v1)
    await pool.query("DELETE FROM api_cache WHERE created_at < NOW() - INTERVAL '1 hour' AND cache_key NOT LIKE 'telemetry\\_%' ESCAPE '\\'").catch(() => {});
    // Cleanup específico de telemetries > 30 días
    await pool.query("DELETE FROM api_cache WHERE created_at < NOW() - INTERVAL '30 days' AND cache_key LIKE 'telemetry\\_%' ESCAPE '\\'").catch(() => {});
    // Alter existing columns to support larger values (safe to run multiple times)
    await pool.query(`
      ALTER TABLE clans ALTER COLUMN avg_kd TYPE NUMERIC(6,2);
      ALTER TABLE clans ALTER COLUMN avg_damage TYPE NUMERIC(12,1);
      ALTER TABLE clans ALTER COLUMN win_rate TYPE NUMERIC(6,2);
      ALTER TABLE clan_members ALTER COLUMN kd TYPE NUMERIC(6,2);
      ALTER TABLE clan_members ALTER COLUMN damage TYPE NUMERIC(12,1);
    `).catch(() => {}); // Ignore if already correct type
    // Add pubg_clan_id column for auto-refresh (safe to run multiple times)
    await pool.query(`ALTER TABLE clans ADD COLUMN IF NOT EXISTS pubg_clan_id VARCHAR(100)`).catch(() => {});
    console.log('✓ Database tables ready');
  } catch (e) { console.error('DB init error:', e.message); }
}

// ═══ CLAN API ENDPOINTS ═══

// GET /clans/leaderboard — Top clans ranked
app.get('/clans/leaderboard', async (req, res) => {
  if (!pool) return res.json({ clans: [], mode: 'local' });
  try {
    const sort = req.query.sort || 'kills'; // kills, kd, wins, winrate, members
    const limit = Math.min(parseInt(req.query.limit) || 50, 100);
    const orderMap = {
      kills: 'total_kills DESC', kd: 'avg_kd DESC', wins: 'total_wins DESC',
      winrate: 'win_rate DESC', members: 'active_members DESC', rounds: 'total_rounds DESC',
      recent: 'created_at DESC'
    };
    const order = orderMap[sort] || 'total_kills DESC';
    const [{ rows }, countRes] = await Promise.all([
      pool.query(
        `SELECT tag, name, member_count, level, platform, total_kills, total_wins,
                avg_kd, avg_damage, total_rounds, win_rate, active_members,
                stats_updated_at, created_at
         FROM clans ORDER BY active_members > 0 DESC, ${order} LIMIT $1`, [limit]
      ),
      pool.query('SELECT COUNT(*)::int AS cnt, SUM(active_members)::int AS players, SUM(total_kills)::int AS kills FROM clans')
    ]);
    const stats = countRes.rows[0] || {};
    res.json({ clans: rows, total: stats.cnt || rows.length, totalPlayers: stats.players || 0, totalKills: stats.kills || 0 });
  } catch (e) { console.error(e.message); res.status(500).json({ error: 'Error interno del servidor' }); }
});

// GET /clans/requests/pending — Admin: list pending requests (MUST be before :tag wildcard)
app.get('/clans/requests/pending', requireAdmin, async (req, res) => {
  if (!pool) return res.json({ requests: [] });
  try {
    const { rows } = await pool.query(
      `SELECT id, clan_tag, player_name, requested_by, created_at
       FROM member_requests WHERE status = 'pending' ORDER BY created_at DESC LIMIT 50`
    );
    res.json({ requests: rows });
  } catch (e) { console.error(e.message); res.status(500).json({ error: 'Error interno del servidor' }); }
});

// GET /clans/search/:query — Search clans by name or tag (MUST be before :tag wildcard)
app.get('/clans/search/:query', async (req, res) => {
  if (!pool) return res.json({ clans: [] });
  try {
    const q = `%${req.params.query.toUpperCase()}%`;
    const { rows } = await pool.query(
      `SELECT tag, name, active_members, total_kills, avg_kd, platform
       FROM clans WHERE UPPER(tag) LIKE $1 OR UPPER(name) LIKE $1
       ORDER BY active_members DESC LIMIT 20`, [q]
    );
    res.json({ clans: rows });
  } catch (e) { console.error(e.message); res.status(500).json({ error: 'Error interno del servidor' }); }
});

// GET /clans/evolution/:tag — Clan stats evolution over time
app.get('/clans/evolution/:tag', async (req, res) => {
  if (!pool) return res.json({ snapshots: [] });
  const tag = req.params.tag.toUpperCase().replace(/[^A-Z0-9_]/g, '');
  try {
    const { rows } = await pool.query(
      `SELECT total_kills, total_wins, avg_kd, avg_damage, win_rate, active_members, total_rounds, created_at
       FROM clan_snapshots WHERE clan_tag = $1 ORDER BY created_at ASC LIMIT 100`, [tag]
    );
    res.json({ snapshots: rows });
  } catch (e) { console.error('[clan-evolution]', e.message); res.status(500).json({ error: 'Error interno del servidor' }); }
});

// GET /clans/transfers/:tag — Player transfers in/out of clan
app.get('/clans/transfers/:tag', async (req, res) => {
  if (!pool) return res.json({ transfers: [] });
  const tag = req.params.tag.toUpperCase().replace(/[^A-Z0-9_]/g, '');
  try {
    const { rows } = await pool.query(
      `SELECT player_name, from_clan, to_clan, platform, detected_at
       FROM clan_transfers WHERE from_clan = $1 OR to_clan = $1
       ORDER BY detected_at DESC LIMIT 50`, [tag]
    );
    res.json({ transfers: rows });
  } catch (e) { console.error('[clan-transfers]', e.message); res.status(500).json({ error: 'Error interno del servidor' }); }
});

// GET /clans/:tag — Get clan detail with members
app.get('/clans/:tag', async (req, res) => {
  if (!pool) return res.status(404).json({ error: 'No database' });
  try {
    const tag = req.params.tag.toUpperCase();
    const clan = await pool.query('SELECT * FROM clans WHERE tag = $1', [tag]);
    if (!clan.rows.length) return res.status(404).json({ error: 'Clan not found' });
    const members = await pool.query(
      'SELECT player_name, kills, wins, kd, damage, rounds, active FROM clan_members WHERE clan_tag = $1 ORDER BY kills DESC',
      [tag]
    );
    // Auto-refresh in background if stats are older than 24h and we have the pubg_clan_id
    const c = clan.rows[0];
    const statsAge = c.stats_updated_at ? (Date.now() - new Date(c.stats_updated_at).getTime()) : Infinity;
    if (statsAge > 24 * 60 * 60 * 1000 && c.pubg_clan_id) {
      // Fire and forget — don't block the response
      importClanByPubgId(c.pubg_clan_id).then(r => {
        console.log(`[auto-refresh] Updated [${tag}] in background (was ${Math.round(statsAge/3600000)}h old)`);
      }).catch(e => {
        console.error(`[auto-refresh] Failed for [${tag}]:`, e.message);
      });
    }
    res.json({ clan: c, members: members.rows });
  } catch (e) { console.error(e.message); res.status(500).json({ error: 'Error interno del servidor' }); }
});

// POST /clans/register — Register or update a clan with member stats
app.post('/clans/register', rateLimit, async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'No database configured' });
  try {
    const { tag, name, memberCount, level, platform, registeredBy, members, clanId } = req.body;
    if (!tag || !name) return res.status(400).json({ error: 'tag and name required' });

    const cleanTag = tag.toUpperCase().replace(/[^A-Z0-9_]/g, '').slice(0, 20);
    const cleanName = name.slice(0, 100);

    // Calculate aggregated stats from members
    let totalKills = 0, totalWins = 0, totalRounds = 0, totalDmg = 0, kdSum = 0;
    let activeCount = 0;
    const validMembers = (members || []).filter(m => m.name && m.stats);

    validMembers.forEach(m => {
      const s = m.stats;
      totalKills += s.kills || 0;
      totalWins += s.wins || 0;
      totalRounds += s.rounds || 0;
      totalDmg += s.damage || 0;
      kdSum += s.kd || 0;
      if (m.active !== false) activeCount++;
    });

    const avgKd = validMembers.length > 0 ? (kdSum / validMembers.length).toFixed(2) : 0;
    const avgDmg = validMembers.length > 0 ? (totalDmg / validMembers.length).toFixed(1) : 0;
    const winRate = totalRounds > 0 ? ((totalWins / totalRounds) * 100).toFixed(2) : 0;

    // Upsert clan (include pubg_clan_id if provided)
    await pool.query(`
      INSERT INTO clans (tag, name, member_count, level, platform, registered_by,
                         total_kills, total_wins, avg_kd, avg_damage, total_rounds,
                         win_rate, active_members, pubg_clan_id, stats_updated_at, updated_at)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,NOW(),NOW())
      ON CONFLICT (tag) DO UPDATE SET
        name=EXCLUDED.name, member_count=EXCLUDED.member_count, level=EXCLUDED.level,
        platform=EXCLUDED.platform, total_kills=EXCLUDED.total_kills, total_wins=EXCLUDED.total_wins,
        avg_kd=EXCLUDED.avg_kd, avg_damage=EXCLUDED.avg_damage, total_rounds=EXCLUDED.total_rounds,
        win_rate=EXCLUDED.win_rate, active_members=EXCLUDED.active_members,
        pubg_clan_id=COALESCE(EXCLUDED.pubg_clan_id, clans.pubg_clan_id),
        stats_updated_at=NOW(), updated_at=NOW()
    `, [cleanTag, cleanName, memberCount || 0, level || 0, platform || 'psn',
        registeredBy || 'anon', totalKills, totalWins, avgKd, avgDmg, totalRounds, winRate, activeCount,
        clanId || null]);

    // Upsert members
    for (const m of validMembers) {
      const s = m.stats;
      await pool.query(`
        INSERT INTO clan_members (clan_tag, player_name, kills, wins, kd, damage, rounds, active, added_by)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
        ON CONFLICT (clan_tag, player_name) DO UPDATE SET
          kills=EXCLUDED.kills, wins=EXCLUDED.wins, kd=EXCLUDED.kd,
          damage=EXCLUDED.damage, rounds=EXCLUDED.rounds, active=EXCLUDED.active
      `, [cleanTag, m.name, s.kills||0, s.wins||0, s.kd||0, s.damage||0, s.rounds||0,
          m.active !== false, registeredBy || 'anon']);
    }

    res.json({ ok: true, tag: cleanTag, members: validMembers.length, url: `/clan/${cleanTag}` });
  } catch (e) { console.error(e.message); res.status(500).json({ error: 'Error interno del servidor' }); }
});

// ═══ MEMBER REQUEST SYSTEM ═══
// POST /clans/request-member — Auto-add if player exists in PUBG API, otherwise queue for admin
app.post('/clans/request-member', rateLimit, async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'No database configured' });

  try {
    const { clanTag, playerName, requestedBy } = req.body;
    if (!clanTag || !playerName) return res.status(400).json({ error: 'clanTag and playerName required' });
    const cleanTag = clanTag.toUpperCase().replace(/[^A-Z0-9_]/g, '').slice(0, 20);
    const cleanName = playerName.trim().slice(0, 50);
    // Check if player already exists in clan
    const existing = await pool.query('SELECT id FROM clan_members WHERE clan_tag = $1 AND player_name = $2', [cleanTag, cleanName]);
    if (existing.rows.length) return res.json({ ok: true, message: 'Este jugador ya esta en el clan', autoAdded: false });
    // Get clan platform
    const clanRow = await pool.query('SELECT platform FROM clans WHERE tag = $1', [cleanTag]);
    const platform = clanRow.rows.length ? clanRow.rows[0].platform : 'psn';
    // Try to verify player exists in PUBG API
    let verified = false;
    let realName = cleanName;
    const headers = { 'Authorization': 'Bearer ' + SERVER_API_KEY, 'Accept': 'application/vnd.api+json' };
    const platforms = [platform, platform === 'psn' ? 'xbox' : 'psn'];
    for (const plat of platforms) {
      try {
        const pResp = await fetchWithTimeout(fetch, 'https://api.pubg.com/shards/' + plat + '/players?filter[playerNames]=' + encodeURIComponent(cleanName), { headers }, 8000);
        if (pResp.ok) {
          const pData = await pResp.json();
          if (pData.data && pData.data.length > 0) {
            realName = pData.data[0].attributes.name; // Use exact casing from API
            verified = true;
            break;
          }
        }
      } catch (e) { /* try next platform */ }
    }
    if (verified) {
      // Auto-add player directly — they exist in PUBG API
      await pool.query(`
        INSERT INTO clan_members (clan_tag, player_name, kills, wins, kd, damage, rounds, active, added_by)
        VALUES ($1, $2, 0, 0, 0, 0, 0, true, $3)
        ON CONFLICT (clan_tag, player_name) DO NOTHING
      `, [cleanTag, realName, 'auto_verified']);
      // Update clan active_members count
      const countResult = await pool.query('SELECT COUNT(*) FROM clan_members WHERE clan_tag = $1 AND active = true', [cleanTag]);
      await pool.query('UPDATE clans SET active_members = $1, updated_at = NOW() WHERE tag = $2', [countResult.rows[0].count, cleanTag]);
      // Log in member_requests for record-keeping
      await pool.query(`
        INSERT INTO member_requests (clan_tag, player_name, requested_by, status)
        VALUES ($1, $2, $3, 'approved')
        ON CONFLICT DO NOTHING
      `, [cleanTag, realName, requestedBy || 'web_auto']);
      console.log(`[request] Auto-added verified player: ${realName} -> [${cleanTag}]`);
      res.json({ ok: true, message: 'Jugador verificado y anadido al clan!', autoAdded: true, playerName: realName });
    } else {
      // Player not found in PUBG API — queue for manual review
      await pool.query(`
        INSERT INTO member_requests (clan_tag, player_name, requested_by)
        VALUES ($1, $2, $3)
        ON CONFLICT (clan_tag, player_name, status) DO NOTHING
      `, [cleanTag, cleanName, requestedBy || 'web_user']);
      console.log(`[request] Queued for review (not verified): ${cleanName} -> [${cleanTag}]`);
      res.json({ ok: true, message: 'Jugador no encontrado en PUBG — solicitud enviada para revision manual', autoAdded: false });
    }
  } catch (e) { console.error(e.message); res.status(500).json({ error: 'Error interno del servidor' }); }
});

// POST /clans/requests/:id/approve — Admin: approve a member request
app.post('/clans/requests/:id/approve', requireAdmin, async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'No database' });
  try {
    const requestId = parseInt(req.params.id);
    const request = await pool.query('SELECT * FROM member_requests WHERE id = $1', [requestId]);
    if (!request.rows.length) return res.status(404).json({ error: 'Request not found' });
    const r = request.rows[0];
    // Add player to clan_members with 0 stats (will be updated later)
    await pool.query(`
      INSERT INTO clan_members (clan_tag, player_name, kills, wins, kd, damage, rounds, active, added_by)
      VALUES ($1, $2, 0, 0, 0, 0, 0, true, $3)
      ON CONFLICT (clan_tag, player_name) DO NOTHING
    `, [r.clan_tag, r.player_name, 'approved_request']);
    // Update clan active_members count
    const countResult = await pool.query('SELECT COUNT(*) FROM clan_members WHERE clan_tag = $1 AND active = true', [r.clan_tag]);
    await pool.query('UPDATE clans SET active_members = $1, updated_at = NOW() WHERE tag = $2', [countResult.rows[0].count, r.clan_tag]);
    // Mark request as approved
    await pool.query("UPDATE member_requests SET status = 'approved', reviewed_at = NOW() WHERE id = $1", [requestId]);
    console.log(`[request] Approved: ${r.player_name} -> [${r.clan_tag}]`);
    res.json({ ok: true, playerName: r.player_name, clanTag: r.clan_tag });
  } catch (e) { console.error(e.message); res.status(500).json({ error: 'Error interno del servidor' }); }
});

// POST /clans/requests/:id/reject — Admin: reject a member request
app.post('/clans/requests/:id/reject', requireAdmin, async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'No database' });
  try {
    await pool.query("UPDATE member_requests SET status = 'rejected', reviewed_at = NOW() WHERE id = $1", [parseInt(req.params.id)]);
    res.json({ ok: true });
  } catch (e) { console.error(e.message); res.status(500).json({ error: 'Error interno del servidor' }); }
});

// ═══ IMPORT CLAN FROM PUBGCLANS.NET ═══

// Reusable import function — used by endpoint, refresh, auto-refresh, and cron
async function importClanByPubgId(clanId) {
  if (!pool) throw new Error('No database configured');
  if (!clanId) throw new Error('clanId required');

  const headers = { 'Authorization': 'Bearer ' + SERVER_API_KEY, 'Accept': 'application/vnd.api+json' };

  // Step 1: Fetch clan metadata from PUBG API (try xbox first, then psn)
  let clanMeta = null;
  let detectedPlatform = 'xbox';
  for (const shard of ['xbox', 'psn', 'steam']) {
    try {
      const clanResp = await fetchWithTimeout(fetch, `https://api.pubg.com/shards/${shard}/clans/${clanId}`, { headers }, 8000);
      if (clanResp.ok) {
        const clanData = await clanResp.json();
        clanMeta = clanData.data?.attributes;
        detectedPlatform = shard;
        break;
      }
    } catch (e) { /* try next shard */ }
  }
  if (!clanMeta) throw new Error('Clan not found on any platform');
  console.log(`[import] Found clan: [${clanMeta.clanTag}] ${clanMeta.clanName} (${detectedPlatform}, level ${clanMeta.clanLevel}, ${clanMeta.clanMemberCount} members)`);

  // Step 2: Get clan members + stats — PUBG API first (official), internal fallback second
  let members = [];

  // ── Path A (primary): PUBG API direct — roster + season stats ──
  console.log(`[import] Fetching members via PUBG API for clan ${clanId}`);
  let clanMembers = [];
  for (const shard of ['xbox', 'psn', 'steam']) {
    try {
      const cmResp = await fetchWithTimeout(fetch, `https://api.pubg.com/shards/${shard}/clans/${clanId}`, { headers }, 8000);
      if (cmResp.ok) {
        const cmData = await cmResp.json();
        const rels = cmData.data?.relationships?.members?.data || [];
        if (rels.length) {
          clanMembers = rels.map(r => ({ accountId: r.id }));
          const included = cmData.included || [];
          clanMembers.forEach(cm => {
            const inc = included.find(i => i.id === cm.accountId);
            if (inc) cm.name = inc.attributes?.name || cm.accountId;
          });
          break;
        }
      }
    } catch (e) { /* try next shard */ }
  }

  if (clanMembers.length > 0) {
    console.log(`[import] PUBG API found ${clanMembers.length} clan members`);
    // Get current season
    let seasonId = null;
    try {
      const sResp = await fetchWithTimeout(fetch, `https://api.pubg.com/shards/${detectedPlatform}/seasons`, { headers }, 8000);
      if (sResp.ok) {
        const sData = await sResp.json();
        const cur = (sData.data || []).find(s => s.attributes?.isCurrentSeason);
        if (cur) seasonId = cur.id;
      }
    } catch (e) { console.log('[import] Could not fetch current season:', e.message); }

    // rpm100-throttling-relax-v1: con 100 RPM (10 req/s) podemos paralelizar 25
    // simultáneos sin riesgo. Antes batch=10 + 1500ms delay, ahora batch=25 + 300ms.
    // Ganancia: clan de 60 miembros pasa de ~9s a ~3s.
    const batchSize = 25;
    for (let i = 0; i < clanMembers.length; i += batchSize) {
      const batch = clanMembers.slice(i, i + batchSize);
      const results = await Promise.allSettled(batch.map(async (cm) => {
        if (!seasonId) return { name: cm.name || cm.accountId, active: false, stats: { kills: 0, wins: 0, kd: 0, damage: 0, rounds: 0 } };
        try {
          const url = `https://api.pubg.com/shards/${detectedPlatform}/players/${cm.accountId}/seasons/${seasonId}`;
          const stResp = await fetchWithTimeout(fetch, url, { headers }, 8000);
          if (!stResp.ok) return { name: cm.name || cm.accountId, active: false, stats: { kills: 0, wins: 0, kd: 0, damage: 0, rounds: 0 } };
          const stData = await stResp.json();
          const attrs = stData.data?.attributes?.gameModeStats || {};
          let kills = 0, wins = 0, rounds = 0, damage = 0;
          for (const mode of Object.keys(attrs)) {
            const ms = attrs[mode];
            if (!ms) continue;
            kills += ms.kills || 0;
            wins += ms.wins || 0;
            rounds += ms.roundsPlayed || 0;
            damage += ms.damageDealt || 0;
          }
          const kd = rounds > 0 ? parseFloat((kills / rounds).toFixed(2)) : 0;
          return { name: cm.name || cm.accountId, active: rounds > 0, stats: { kills, wins, kd, damage, rounds } };
        } catch (e) {
          return { name: cm.name || cm.accountId, active: false, stats: { kills: 0, wins: 0, kd: 0, damage: 0, rounds: 0 } };
        }
      }));
      results.forEach(r => { if (r.status === 'fulfilled') members.push(r.value); });
      if (i + batchSize < clanMembers.length) await new Promise(r => setTimeout(r, 300));
    }
    members.sort((a, b) => b.stats.kills - a.stats.kills);
    console.log(`[import] PUBG API: got stats for ${members.length} members (${members.filter(m => m.active).length} active)`);
  }

  // ── Path B (internal fallback): secondary source — only if PUBG API returned 0 members ──
  if (!members.length) {
    console.log(`[import] PUBG API returned 0 members, trying internal fallback for ${clanId}`);
    const gameModes = ['squad', 'squad-fpp', 'solo', 'solo-fpp', 'duo', 'duo-fpp'];
    const mergedPlayers = {};
    for (const gm of gameModes) {
      try {
        const pcnUrl = `https://www.pubgclans.net/includes/getClanMemberDataAjax.php?clanId=${encodeURIComponent(clanId)}&mode=unranked&gameMode=${gm}`;
        const pcnResp = await fetchWithTimeout(fetch, pcnUrl, {}, 10000);
        if (!pcnResp.ok) continue;
        const pcnData = await pcnResp.json();
        if (!Array.isArray(pcnData)) continue;
        pcnData.forEach(p => {
          const name = p.player_name;
          if (!name) return;
          const kills = parseInt(p.kills) || 0;
          const rounds = parseInt(p.roundsplayed) || 0;
          const wins = parseInt(p.wins) || 0;
          const damage = parseFloat(p.damagedealt) || 0;
          if (mergedPlayers[name]) {
            mergedPlayers[name].kills += kills;
            mergedPlayers[name].wins += wins;
            mergedPlayers[name].rounds += rounds;
            mergedPlayers[name].damage += damage;
          } else {
            mergedPlayers[name] = { kills, wins, rounds, damage };
          }
        });
      } catch (e) { /* silent */ }
    }
    const deduped = {};
    for (const [name, stats] of Object.entries(mergedPlayers)) {
      const key = name.toLowerCase();
      if (deduped[key]) {
        if (stats.kills > deduped[key].stats.kills) deduped[key].displayName = name;
        deduped[key].stats.kills += stats.kills;
        deduped[key].stats.wins += stats.wins;
        deduped[key].stats.rounds += stats.rounds;
        deduped[key].stats.damage += stats.damage;
      } else {
        deduped[key] = { displayName: name, stats: { ...stats } };
      }
    }
    if (Object.keys(deduped).length > 0) {
      members = Object.values(deduped).map(p => {
        const s = p.stats;
        const kd = s.rounds > 0 ? parseFloat((s.kills / s.rounds).toFixed(2)) : 0;
        return { name: p.displayName, active: s.rounds > 0, stats: { kills: s.kills, wins: s.wins, kd, damage: s.damage, rounds: s.rounds } };
      }).sort((a, b) => b.stats.kills - a.stats.kills);
      console.log(`[import] Internal fallback: ${members.length} members`);
    }
  }

  if (!members.length) throw new Error('No se encontraron miembros del clan en ninguna fuente');

  // Step 4: Register the clan (upsert)
  const cleanTag = clanMeta.clanTag.toUpperCase().replace(/[^A-Z0-9_]/g, '').slice(0, 20);
  let totalKills = 0, totalWins = 0, totalRounds = 0, totalDmg = 0, kdSum = 0, activeCount = 0;
  members.forEach(m => {
    const s = m.stats;
    totalKills += s.kills; totalWins += s.wins; totalRounds += s.rounds;
    totalDmg += s.damage; kdSum += s.kd;
    if (m.active) activeCount++;
  });
  const avgKd = members.length > 0 ? (kdSum / members.length).toFixed(2) : 0;
  const avgDmg = members.length > 0 ? (totalDmg / members.length).toFixed(1) : 0;
  const winRate = totalRounds > 0 ? ((totalWins / totalRounds) * 100).toFixed(2) : 0;

  await pool.query(`
    INSERT INTO clans (tag, name, member_count, level, platform, registered_by,
                       total_kills, total_wins, avg_kd, avg_damage, total_rounds,
                       win_rate, active_members, pubg_clan_id, stats_updated_at, updated_at)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,NOW(),NOW())
    ON CONFLICT (tag) DO UPDATE SET
      name=EXCLUDED.name, member_count=EXCLUDED.member_count, level=EXCLUDED.level,
      platform=EXCLUDED.platform, total_kills=EXCLUDED.total_kills, total_wins=EXCLUDED.total_wins,
      avg_kd=EXCLUDED.avg_kd, avg_damage=EXCLUDED.avg_damage, total_rounds=EXCLUDED.total_rounds,
      win_rate=EXCLUDED.win_rate, active_members=EXCLUDED.active_members,
      pubg_clan_id=COALESCE(EXCLUDED.pubg_clan_id, clans.pubg_clan_id),
      stats_updated_at=NOW(), updated_at=NOW()
  `, [cleanTag, clanMeta.clanName, clanMeta.clanMemberCount, clanMeta.clanLevel, detectedPlatform,
      'pubgclans_import', totalKills, totalWins, avgKd, avgDmg, totalRounds, winRate, activeCount, clanId]);

  // Delete old members before re-importing
  await pool.query('DELETE FROM clan_members WHERE clan_tag = $1', [cleanTag]);
  for (const m of members) {
    const s = m.stats;
    await pool.query(`
      INSERT INTO clan_members (clan_tag, player_name, kills, wins, kd, damage, rounds, active, added_by)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
    `, [cleanTag, m.name, s.kills, s.wins, s.kd, s.damage, s.rounds, m.active, 'pubgclans_import']);
  }

  // Snapshot + Transfer Detection
  try {
    const existingSnap = await pool.query(
      "SELECT id FROM clan_snapshots WHERE clan_tag = $1 AND created_at > NOW() - INTERVAL '20 hours'", [cleanTag]
    );
    if (!existingSnap.rows.length) {
      await pool.query(
        `INSERT INTO clan_snapshots (clan_tag, total_kills, total_wins, avg_kd, avg_damage, win_rate, active_members, total_rounds)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
        [cleanTag, totalKills, totalWins, avgKd, avgDmg, winRate, activeCount, totalRounds]
      );
      console.log(`[snapshot] Saved evolution snapshot for [${cleanTag}]`);
    }
  } catch (snapErr) { console.error('[snapshot] Error:', snapErr.message); }

  try {
    const memberNames = members.map(m => m.name);
    for (const name of memberNames) {
      const prev = await pool.query(
        `SELECT clan_tag FROM clan_members WHERE player_name = $1 AND clan_tag != $2 AND active = true LIMIT 1`, [name, cleanTag]
      );
      if (prev.rows.length) {
        const fromClan = prev.rows[0].clan_tag;
        const alreadyDetected = await pool.query(
          `SELECT id FROM clan_transfers WHERE player_name = $1 AND from_clan = $2 AND to_clan = $3 AND detected_at > NOW() - INTERVAL '30 days'`, [name, fromClan, cleanTag]
        );
        if (!alreadyDetected.rows.length) {
          await pool.query(`INSERT INTO clan_transfers (player_name, from_clan, to_clan, platform) VALUES ($1,$2,$3,$4)`, [name, fromClan, cleanTag, detectedPlatform]);
          console.log(`[transfer] Detected: ${name} moved [${fromClan}] -> [${cleanTag}]`);
        }
      }
    }
  } catch (trErr) { console.error('[transfer] Error:', trErr.message); }

  console.log(`[import] Registered [${cleanTag}] ${clanMeta.clanName}: ${members.length} members, ${totalKills} kills`);
  return {
    ok: true, tag: cleanTag, name: clanMeta.clanName, platform: detectedPlatform,
    level: clanMeta.clanLevel, members: members.length, activeMembers: activeCount,
    totalKills, totalWins, avgKd, winRate, url: `/clan/${cleanTag}`
  };
}

// POST /clans/import-members — Import a clan using PUBG API metadata + member stats
app.post('/clans/import-members', rateLimit, async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'No database configured' });
  const { clanId } = req.body;
  if (!clanId) return res.status(400).json({ error: 'clanId required (e.g. clan.bc03cc7f04a347ef81e48070f004283c)' });
  try {
    const result = await importClanByPubgId(clanId);
    res.json(result);
  } catch (e) {
    console.error('[import] Error:', e.message);
    res.status(e.message.includes('not found') ? 404 : 500).json({ error: e.message || 'Error interno del servidor' });
  }
});

// POST /clans/refresh-stats/:tag — Manual refresh of clan stats (rate limited, any user)
app.post('/clans/refresh-stats/:tag', rateLimit, async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'No database configured' });
  try {
    const tag = req.params.tag.toUpperCase();
    // Try to get pubg_clan_id (column may not exist yet in older DBs)
    let pubgClanId = null, platform = 'psn';
    try {
      const clan = await pool.query('SELECT pubg_clan_id, platform FROM clans WHERE tag = $1', [tag]);
      if (!clan.rows.length) return res.status(404).json({ error: 'Clan not found' });
      pubgClanId = clan.rows[0].pubg_clan_id;
      platform = clan.rows[0].platform || 'psn';
    } catch (colErr) {
      // pubg_clan_id column may not exist yet — fallback to platform only
      const clan = await pool.query('SELECT platform FROM clans WHERE tag = $1', [tag]);
      if (!clan.rows.length) return res.status(404).json({ error: 'Clan not found' });
      platform = clan.rows[0].platform || 'psn';
    }
    if (!pubgClanId) {
      // Fallback: try to find clanId via PUBG API using first member or playerHint — try ALL shards
      const firstMember = await pool.query('SELECT player_name FROM clan_members WHERE clan_tag = $1 ORDER BY kills DESC LIMIT 1', [tag]);
      const playerHint = req.body?.playerHint;
      const lookupName = firstMember.rows.length ? firstMember.rows[0].player_name : playerHint;
      if (!lookupName) return res.status(400).json({ error: 'No se puede actualizar: sin miembros ni ID del clan. Busca un jugador del clan primero.' });
      const headers = { 'Authorization': 'Bearer ' + SERVER_API_KEY, 'Accept': 'application/vnd.api+json' };
      const shardsToTry = [platform, 'xbox', 'psn', 'steam'].filter((v, i, a) => a.indexOf(v) === i);
      let foundClanId = null;
      let foundShard = null;
      for (const shard of shardsToTry) {
        try {
          const playerResp = await fetchWithTimeout(fetch,
            `https://api.pubg.com/shards/${shard}/players?filter[playerNames]=${encodeURIComponent(lookupName)}`,
            { headers }, 8000);
          if (playerResp.ok) {
            const playerData = await playerResp.json();
            const cId = playerData.data?.[0]?.attributes?.clanId;
            if (cId) { foundClanId = cId; foundShard = shard; break; }
          }
        } catch (shardErr) {
          console.log(`[refresh] Shard ${shard} failed for ${lookupName}: ${shardErr.message}`);
        }
      }
      if (!foundClanId) return res.status(400).json({ error: 'No se encontró clan del jugador en ninguna plataforma' });
      // Save clanId + correct platform for future refreshes
      try { await pool.query('UPDATE clans SET pubg_clan_id = $1, platform = $2 WHERE tag = $3', [foundClanId, foundShard, tag]); } catch(e) {}
      const result = await importClanByPubgId(foundClanId);
      return res.json(result);
    }
    const result = await importClanByPubgId(pubgClanId);
    res.json(result);
  } catch (e) {
    console.error('[refresh] Error:', e.message);
    res.status(500).json({ error: e.message || 'Error al actualizar stats' });
  }
});

// ═══ AUTO-DISCOVER CLAN MEMBERS FROM MATCHES ═══
// POST /clans/discover-members — Given one gamertag, find frequent teammates
app.post('/clans/discover-members', requireAdmin, async (req, res) => {

  const { gamertag, platform } = req.body;
  if (!gamertag || !platform) return res.status(400).json({ error: 'gamertag and platform required' });
  if (!SERVER_API_KEY) return res.status(503).json({ error: 'No API key configured on server' });

  const shard = platform; // xbox, psn, steam, etc.
  const headers = { 'Authorization': 'Bearer ' + SERVER_API_KEY, 'Accept': 'application/vnd.api+json' };

  try {
    // Step 1: Look up the player to get their account ID and recent matches
    console.log(`[discover] Looking up player: ${gamertag} on ${shard}`);
    const playerResp = await fetchWithTimeout(fetch,
      `https://api.pubg.com/shards/${shard}/players?filter[playerNames]=${encodeURIComponent(gamertag)}`,
      { headers }, 8000
    );
    if (!playerResp.ok) {
      const errText = await playerResp.text();
      return res.status(playerResp.status).json({ error: `Player not found: ${gamertag}`, details: errText });
    }
    const playerData = await playerResp.json();
    const player = playerData.data[0];
    if (!player) return res.status(404).json({ error: 'Player not found' });

    const accountId = player.id;
    const matchIds = (player.relationships?.matches?.data || []).map(m => m.id).slice(0, 8); // max 8 matches

    if (!matchIds.length) return res.json({ members: [], message: 'No recent matches found' });

    // Step 2: Fetch each match and find teammates
    const teammateStats = {}; // { playerName: { kills, damage, wins, rounds, assists, appearances, clanConfirmed } }
    let matchesProcessed = 0;
    let seedClanId = null; // Will be detected from match data

    for (const matchId of matchIds) {
      try {
        // rpm100-throttling-relax-v1: con 100 RPM (10 req/s) podemos bajar a 300ms
        if (matchesProcessed > 0) await new Promise(r => setTimeout(r, 300));

        console.log(`[discover] Fetching match ${matchesProcessed + 1}/${matchIds.length}: ${matchId}`);
        const matchResp = await fetchWithTimeout(fetch, `https://api.pubg.com/shards/${shard}/matches/${matchId}`, { headers }, 10000);
        if (!matchResp.ok) continue;
        const matchData = await matchResp.json();

        const included = matchData.included || [];
        const participants = included.filter(i => i.type === 'participant');
        const rosters = included.filter(i => i.type === 'roster');

        // Find which roster our player is in
        const myParticipant = participants.find(p =>
          p.attributes?.stats?.playerId === accountId
        );
        if (!myParticipant) continue;

        // Detect seed player's clanId from match data (if available)
        const myClanId = myParticipant.attributes?.stats?.clanId;
        if (myClanId && !seedClanId) seedClanId = myClanId;

        const myRoster = rosters.find(r =>
          r.relationships?.participants?.data?.some(p => p.id === myParticipant.id)
        );
        if (!myRoster) continue;

        // Also check if roster won
        const rosterWon = myRoster.attributes?.won === 'true' || myRoster.attributes?.stats?.rank === 1;

        // Scan ALL participants in the match (not just our roster)
        // If they share our clanId, they're confirmed clan members
        // If they're on our roster but different/no clanId, they're possible randoms
        for (const p of participants) {
          const stats = p.attributes?.stats;
          if (!stats) continue;
          const name = stats.name;
          if (name === gamertag) continue;

          const pClanId = stats.clanId;
          const isOnMyRoster = myRoster.relationships.participants.data.some(rp => rp.id === p.id);
          const isSameClan = seedClanId && pClanId && pClanId === seedClanId;

          // Only track: same clan members (from any roster) OR our roster teammates
          if (!isSameClan && !isOnMyRoster) continue;

          if (!teammateStats[name]) {
            teammateStats[name] = { kills: 0, damage: 0, wins: 0, rounds: 0, assists: 0, appearances: 0, clanConfirmed: false };
          }
          teammateStats[name].kills += stats.kills || 0;
          teammateStats[name].damage += stats.damageDealt || 0;
          teammateStats[name].wins += (isOnMyRoster && rosterWon ? 1 : 0);
          teammateStats[name].rounds += 1;
          teammateStats[name].assists += stats.assists || 0;
          teammateStats[name].appearances += 1;
          if (isSameClan) teammateStats[name].clanConfirmed = true;
        }

        matchesProcessed++;
      } catch (matchErr) {
        console.error(`[discover] Error fetching match ${matchId}:`, matchErr.message);
      }
    }

    // Step 3: Build member list
    // If clanId was found, use it for definitive filtering
    // Otherwise fall back to frequency heuristic
    const allTeammates = Object.entries(teammateStats)
      .map(([name, s]) => {
        let confidence;
        if (s.clanConfirmed) confidence = 'confirmed'; // same clanId = 100% sure
        else if (s.appearances >= 3) confidence = 'high';
        else if (s.appearances >= 2) confidence = 'medium';
        else confidence = 'low';
        return {
          name, active: true,
          appearances: s.appearances,
          clanConfirmed: s.clanConfirmed,
          confidence,
          stats: {
            kills: s.kills, wins: s.wins,
            kd: s.rounds > 0 ? parseFloat((s.kills / s.rounds).toFixed(2)) : 0,
            damage: parseFloat(s.damage.toFixed(2)),
            rounds: s.rounds
          }
        };
      })
      .sort((a, b) => {
        // Sort: confirmed first, then by appearances
        if (a.clanConfirmed !== b.clanConfirmed) return b.clanConfirmed ? 1 : -1;
        return b.appearances - a.appearances;
      });

    // If we have clanId data: confirmed = members, unconfirmed = maybe randoms
    // If no clanId: fall back to 2+ appearances = members
    const hasClanData = seedClanId && allTeammates.some(m => m.clanConfirmed);
    const members = hasClanData
      ? allTeammates.filter(m => m.clanConfirmed)
      : allTeammates.filter(m => m.appearances >= 2);
    const maybeRandoms = hasClanData
      ? allTeammates.filter(m => !m.clanConfirmed)
      : allTeammates.filter(m => m.appearances < 2);

    console.log(`[discover] ClanId: ${seedClanId || 'not found'} | ${members.length} clan members + ${maybeRandoms.length} others across ${matchesProcessed} matches`);

    res.json({
      ok: true,
      seedPlayer: gamertag,
      platform: shard,
      matchesAnalyzed: matchesProcessed,
      clanIdDetected: !!seedClanId,  // true = we could verify by clanId
      members: members,
      maybeRandoms: maybeRandoms,
      total: members.length,
      totalIncludingRandoms: allTeammates.length
    });

  } catch (e) {
    console.error('[discover] Error:', e.message);
    console.error(e.message); res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// ═══ CLAN FEED — Recent activity of clan members ═══
app.get('/clans/:tag/feed', rateLimit, async (req, res) => {
  if (!pool || !SERVER_API_KEY) return res.status(503).json({ error: 'Servicio no disponible' });
  const tag = req.params.tag.toUpperCase().replace(/[^A-Z0-9_]/g, '');
  try {
    // Get top 5 active members by rounds played
    const membersResult = await pool.query(
      'SELECT player_name FROM clan_members WHERE clan_tag = $1 AND active = true ORDER BY rounds DESC NULLS LAST LIMIT 5',
      [tag]
    );
    if (!membersResult.rows.length) return res.json({ feed: [], message: 'No hay miembros activos' });

    // Check feed cache (10 min TTL)
    const feedCacheKey = `clan_feed_${tag}`;
    const cached = await pool.query("SELECT response_data FROM api_cache WHERE cache_key = $1 AND created_at > NOW() - INTERVAL '10 minutes'", [feedCacheKey]);
    if (cached.rows.length) { try { return res.json(JSON.parse(cached.rows[0].response_data)); } catch(e) {} }

    const headers = { 'Authorization': 'Bearer ' + SERVER_API_KEY, 'Accept': 'application/vnd.api+json' };
    const feed = [];
    const clanResult = await pool.query('SELECT platform FROM clans WHERE tag = $1', [tag]);
    const platform = clanResult.rows[0]?.platform || 'psn';

    // For each member, get recent matches (max 3 per member)
    for (const row of membersResult.rows) {
      const playerName = row.player_name;
      try {
        // Look up player on PUBG API
        const playerResp = await fetchWithTimeout(fetch,
          `https://api.pubg.com/shards/${platform}/players?filter[playerNames]=${encodeURIComponent(playerName)}`,
          { headers }, 8000);
        if (!playerResp.ok) continue;
        const playerData = await playerResp.json();
        const player = playerData.data?.[0];
        if (!player) continue;

        const matchIds = (player.relationships?.matches?.data || []).map(m => m.id).slice(0, 3);
        for (const matchId of matchIds) {
          try {
            // Check match cache first
            const matchCacheKey = `match_${matchId}`;
            let matchData;
            const mcached = await pool.query("SELECT response_data FROM api_cache WHERE cache_key = $1 AND created_at > NOW() - INTERVAL '30 minutes'", [matchCacheKey]);
            if (mcached.rows.length) {
              try { matchData = JSON.parse(mcached.rows[0].response_data); } catch(e) { matchData = null; }
            }
            if (!matchData) {
              await new Promise(r => setTimeout(r, 100)); // rpm100-throttling-relax-v2: 500→100ms
              const matchResp = await fetchWithTimeout(fetch,
                `https://api.pubg.com/shards/${platform}/matches/${matchId}`,
                { headers }, 10000);
              if (!matchResp.ok) continue;
              matchData = await matchResp.json();
              // Cache match data (30 min)
              await pool.query(
                'INSERT INTO api_cache (cache_key, response_data, status_code, created_at) VALUES ($1, $2, 200, NOW()) ON CONFLICT (cache_key) DO UPDATE SET response_data = $2, created_at = NOW()',
                [matchCacheKey, JSON.stringify(matchData)]
              );
            }

            // Extract this player's stats from the match
            const participants = (matchData.included || matchData.data?.included || []).filter(i => i.type === 'participant');
            const pp = participants.find(p => p.attributes?.stats?.name?.toLowerCase() === playerName.toLowerCase());
            if (!pp) continue;

            const ps = pp.attributes.stats;
            const attrs = matchData.data?.attributes || matchData.attributes || {};
            feed.push({
              player: playerName,
              matchId: matchId,
              map: attrs.mapName || '?',
              mode: attrs.gameMode || '?',
              place: ps.winPlace || 99,
              kills: ps.kills || 0,
              damage: Math.round(ps.damageDealt || 0),
              timeSurvived: ps.timeSurvived || 0,
              date: attrs.createdAt || new Date().toISOString()
            });
          } catch (me) { /* skip match */ }
        }
        await new Promise(r => setTimeout(r, 150)); // rpm100-throttling-relax-v2: 600→150ms entre players
      } catch (pe) { /* skip player */ }
    }

    // Sort by date descending, limit to 15 entries
    feed.sort((a, b) => new Date(b.date) - new Date(a.date));
    const result = { feed: feed.slice(0, 15) };

    // Cache the feed result (10 min)
    await pool.query(
      'INSERT INTO api_cache (cache_key, response_data, status_code, created_at) VALUES ($1, $2, 200, NOW()) ON CONFLICT (cache_key) DO UPDATE SET response_data = $2, created_at = NOW()',
      [feedCacheKey, JSON.stringify(result)]
    ).catch(() => {});

    res.json(result);
  } catch (e) {
    console.error('[clan-feed] Error:', e.message);
    res.status(500).json({ error: 'Error al cargar feed del clan' });
  }
});

// ═══ RIVALIDADES v1 — procesar telemetries cacheadas para extraer kill_events entre clanes registrados ═══
// POST /clans/:tag/process-kills — escanea api_cache, extrae kills, inserta en kill_events (idempotente por UNIQUE)
app.post('/clans/:tag/process-kills', rateLimit, async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'DB not configured' });
  const cleanTag = (req.params.tag || '').toUpperCase().replace(/[^A-Z0-9_]/g, '');
  if (!cleanTag) return res.status(400).json({ error: 'Tag inválido' });

  try {
    // 1. Miembros activos del clan objetivo
    const memRes = await pool.query(
      'SELECT player_name FROM clan_members WHERE clan_tag = $1 AND active = true',
      [cleanTag]
    );
    if (!memRes.rows.length) return res.status(404).json({ error: `Clan ${cleanTag} sin miembros activos` });
    const memberNamesLower = new Set(memRes.rows.map(r => r.player_name.toLowerCase()));

    // 2. Mapa global player → clan (incluye platform para distinguir jugadores homónimos)
    const allMembersRes = await pool.query(
      'SELECT cm.clan_tag, cm.player_name, c.platform FROM clan_members cm JOIN clans c ON c.tag = cm.clan_tag WHERE cm.active = true'
    );
    const playerToClan = new Map();
    for (const r of allMembersRes.rows) {
      playerToClan.set(r.player_name.toLowerCase(), { clan: r.clan_tag, platform: r.platform });
    }

    // 3. Telemetries cacheadas (limit alto pero acotado)
    const cacheRes = await pool.query(
      "SELECT cache_key, response_data FROM api_cache WHERE cache_key LIKE 'telemetry\\_%' ESCAPE '\\' ORDER BY created_at DESC LIMIT 1000"
    );

    let telemetriesScanned = cacheRes.rows.length;
    let matchesProcessed = 0;
    let killsInserted = 0;
    let killsSkippedNoClans = 0;
    let errors = 0;

    // Batch de inserts para reducir round-trips
    const pending = [];

    for (const row of cacheRes.rows) {
      const matchId = row.cache_key.replace(/^telemetry_/, '');
      let telemetry;
      try { telemetry = JSON.parse(row.response_data); } catch (e) { errors++; continue; }
      if (!Array.isArray(telemetry)) continue;

      // Pre-filtro: solo telemetries que contengan miembros de este clan
      const relevant = telemetry.some(ev => {
        const n1 = (ev.killer?.name || ev.finisher?.name || '').toLowerCase();
        const n2 = (ev.victim?.name || '').toLowerCase();
        return memberNamesLower.has(n1) || memberNamesLower.has(n2);
      });
      if (!relevant) continue;
      matchesProcessed++;

      // Extraer kills
      for (const ev of telemetry) {
        if (ev._T !== 'LogPlayerKillV2' && ev._T !== 'LogPlayerKill') continue;
        const killer = ev.killer?.name || ev.finisher?.name;
        const victim = ev.victim?.name;
        if (!killer || !victim || killer === victim) continue;

        const kInfo = playerToClan.get(killer.toLowerCase());
        const vInfo = playerToClan.get(victim.toLowerCase());
        if (!kInfo && !vInfo) { killsSkippedNoClans++; continue; }

        pending.push({
          match_id: matchId,
          killer, victim,
          kClan: kInfo?.clan || null,
          vClan: vInfo?.clan || null,
          platform: kInfo?.platform || vInfo?.platform || 'xbox',
          occurred_at: ev._D || null
        });
      }
    }

    // Batch insert con UNIQUE constraint (match_id, killer, victim) → ON CONFLICT DO NOTHING
    for (const k of pending) {
      try {
        const r = await pool.query(
          `INSERT INTO kill_events (match_id, killer_name, victim_name, killer_clan, victim_clan, platform, occurred_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7)
           ON CONFLICT (match_id, killer_name, victim_name) DO NOTHING`,
          [k.match_id, k.killer, k.victim, k.kClan, k.vClan, k.platform, k.occurred_at]
        );
        if (r.rowCount > 0) killsInserted++;
      } catch (e) { errors++; }
    }

    res.json({
      clan: cleanTag,
      telemetriesScanned,
      matchesProcessed,
      killsQueued: pending.length,
      killsInserted,
      killsSkippedNoClans,
      errors
    });
  } catch (e) {
    console.error('[process-kills] Error:', e.message);
    res.status(500).json({ error: 'Error procesando kills: ' + e.message });
  }
});

// ═══ USAGE METRICS (in-memory) ═══
const metrics = {
  startedAt: Date.now(),
  totalRequests: 0,
  apiRequests: 0,
  cacheHits: 0,
  cacheMisses: 0,
  rateLimited: 0,
  pubgRateLimited: 0,
  uniqueIPs: new Set(),
  searchesTotal: 0,
  // Per-hour breakdown (last 24h)
  hourly: {},
  // Per-IP request counts (for current window)
  topIPs: new Map(),
  // Endpoint counts
  endpoints: {},
};
function trackMetric(req, type) {
  metrics.totalRequests++;
  const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip;
  metrics.uniqueIPs.add(ip);
  // Hourly tracking
  const hourKey = new Date().toISOString().slice(0, 13); // "2026-04-01T14"
  if (!metrics.hourly[hourKey]) metrics.hourly[hourKey] = { requests: 0, uniqueIPs: new Set(), searches: 0, rateLimited: 0, cacheHits: 0 };
  metrics.hourly[hourKey].requests++;
  metrics.hourly[hourKey].uniqueIPs.add(ip);
  // Top IPs
  metrics.topIPs.set(ip, (metrics.topIPs.get(ip) || 0) + 1);
  // Endpoint tracking
  const ep = (req.method + ' ' + req.path).replace(/\/[a-zA-Z0-9_.-]{3,}$/, '/:param');
  metrics.endpoints[ep] = (metrics.endpoints[ep] || 0) + 1;
  if (type) {
    if (type === 'api') metrics.apiRequests++;
    if (type === 'search') { metrics.searchesTotal++; metrics.hourly[hourKey].searches++; }
    if (type === 'cache-hit') { metrics.cacheHits++; metrics.hourly[hourKey].cacheHits++; }
    if (type === 'cache-miss') metrics.cacheMisses++;
    if (type === 'rate-limited') { metrics.rateLimited++; metrics.hourly[hourKey].rateLimited++; }
    if (type === 'pubg-rate-limited') metrics.pubgRateLimited++;
  }
}
// Cleanup hourly data older than 48h
setInterval(() => {
  const cutoff = new Date(Date.now() - 48 * 3600000).toISOString().slice(0, 13);
  for (const key of Object.keys(metrics.hourly)) {
    if (key < cutoff) delete metrics.hourly[key];
  }
}, 3600000);

// ═══ RATE LIMITER (in-memory, no deps) ═══
const rateLimitMap = new Map();
const RATE_LIMIT_WINDOW = 60000; // 1 minute
const RATE_LIMIT_MAX = 30; // max 30 requests per minute per IP
function rateLimit(req, res, next) {
  const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip;
  const now = Date.now();
  let entry = rateLimitMap.get(ip);
  if (!entry || now - entry.start > RATE_LIMIT_WINDOW) {
    entry = { start: now, count: 1 };
    rateLimitMap.set(ip, entry);
  } else {
    entry.count++;
  }
  if (entry.count > RATE_LIMIT_MAX) {
    trackMetric(req, 'rate-limited');
    return res.status(429).json({ error: 'Demasiadas peticiones. Espera un momento.' });
  }
  next();
}
// Cleanup old entries every 5 minutes
setInterval(() => {
  const now = Date.now();
  for (const [ip, entry] of rateLimitMap) {
    if (now - entry.start > RATE_LIMIT_WINDOW * 2) rateLimitMap.delete(ip);
  }
}, 300000);

// ═══ AUTH SYSTEM ═══

// JWT middleware — extracts user from token (optional, doesn't block)
function authMiddleware(req, res, next) {
  const token = getTokenFromRequest(req);
  if (token) {
    try { req.user = jwt.verify(token, JWT_SECRET); }
    catch (e) { req.user = null; }
  }
  next();
}

// Require auth — blocks if no valid token
function getTokenFromRequest(req) {
  // 1. HttpOnly cookie (preferred, secure)
  const cookies = parseCookies(req);
  if (cookies.v4nz_token) return cookies.v4nz_token;
  // 2. Authorization header (backwards compatibility + mobile)
  const auth = req.headers.authorization;
  if (auth && auth.startsWith('Bearer ')) return auth.slice(7);
  return null;
}

function requireAuth(req, res, next) {
  const token = getTokenFromRequest(req);
  if (!token) return res.status(401).json({ error: 'No autorizado' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch (e) { return res.status(401).json({ error: 'Token invalido' }); }
}

// Require admin — blocks if no valid admin token
function requireAdmin(req, res, next) {
  const token = getTokenFromRequest(req);
  if (!token) return res.status(401).json({ error: 'No autorizado' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    if (decoded.role !== 'admin') return res.status(403).json({ error: 'Acceso denegado' });
    req.user = decoded;
    next();
  } catch (e) { return res.status(401).json({ error: 'Token invalido' }); }
}

function generateToken(user) {
  return jwt.sign({ id: user.id, display_name: user.display_name }, JWT_SECRET, { expiresIn: '7d' });
}

// POST /auth/register — Email + password registration
app.post('/auth/register', rateLimit, async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'Base de datos no disponible' });
  const { email, password, displayName, gamertag, platform, newsOptIn } = req.body;
  if (!email || !password || !displayName) return res.status(400).json({ error: 'Email, contrasena y nombre son obligatorios' });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: 'Email no valido' });
  if (password.length < 8) return res.status(400).json({ error: 'La contrasena debe tener al menos 8 caracteres' });
  try {
    const exists = await pool.query('SELECT id FROM users WHERE email = $1', [email.toLowerCase()]);
    if (exists.rows.length) return res.status(409).json({ error: 'Este email ya esta registrado' });
    const hash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (email, password_hash, display_name, gamertag, platform, news_opt_in) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, display_name, gamertag, platform',
      [email.toLowerCase(), hash, displayName.slice(0, 50), (gamertag || '').slice(0, 50), platform || 'psn', !!newsOptIn]
    );
    const user = result.rows[0];
    const token = generateToken(user);
    setAuthCookie(res, token);
    res.json({ token, user: { id: user.id, display_name: user.display_name, gamertag: user.gamertag, platform: user.platform } });
  } catch (e) { console.error(e.message); res.status(500).json({ error: 'Error interno del servidor' }); }
});

// POST /auth/login — Email + password login
app.post('/auth/login', rateLimit, async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'Base de datos no disponible' });
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email y contrasena son obligatorios' });
  try {
    const result = await pool.query('SELECT id, display_name, password_hash, gamertag, platform FROM users WHERE email = $1', [email.toLowerCase()]);
    if (!result.rows.length) return res.status(401).json({ error: 'Email o contrasena incorrectos' });
    const user = result.rows[0];
    if (!user.password_hash) return res.status(401).json({ error: 'Esta cuenta usa Discord para entrar' });
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(401).json({ error: 'Email o contrasena incorrectos' });
    await pool.query('UPDATE users SET last_login = NOW() WHERE id = $1', [user.id]);
    const token = generateToken(user);
    setAuthCookie(res, token);
    res.json({ token, user: { id: user.id, display_name: user.display_name, gamertag: user.gamertag, platform: user.platform } });
  } catch (e) { console.error(e.message); res.status(500).json({ error: 'Error interno del servidor' }); }
});

// POST /auth/logout — Clear cookie
app.post('/auth/logout', (req, res) => {
  clearAuthCookie(res);
  res.json({ ok: true });
});

// GET /auth/discord — Redirect to Discord OAuth (with state for CSRF protection)
app.get('/auth/discord', (req, res) => {
  if (!DISCORD_CLIENT_ID) return res.status(503).json({ error: 'Discord OAuth no configurado' });
  const state = crypto.randomBytes(16).toString('hex');
  const isProduction = process.env.NODE_ENV === 'production' || process.env.RAILWAY_ENVIRONMENT;
  res.setHeader('Set-Cookie', `oauth_state=${state}; HttpOnly; ${isProduction ? 'Secure; ' : ''}SameSite=Lax; Path=/; Max-Age=600`);
  const params = new URLSearchParams({
    client_id: DISCORD_CLIENT_ID,
    redirect_uri: DISCORD_REDIRECT_URI,
    response_type: 'code',
    scope: 'identify email',
    state
  });
  res.redirect('https://discord.com/api/oauth2/authorize?' + params.toString());
});

// GET /auth/discord/callback — Discord OAuth callback (with state verification)
app.get('/auth/discord/callback', async (req, res) => {
  if (!pool) return res.redirect('/#auth_error=db_unavailable');

  const { code, state } = req.query;
  if (!code) return res.redirect('/#auth_error=no_code');
  // Verify OAuth state to prevent CSRF
  const cookies = parseCookies(req);
  if (!state || !cookies.oauth_state || state !== cookies.oauth_state) {
    console.warn('Discord OAuth state mismatch — possible CSRF attempt');
    return res.redirect('/#auth_error=invalid_state');
  }
  // Clear the state cookie
  const isProduction = process.env.NODE_ENV === 'production' || process.env.RAILWAY_ENVIRONMENT;
  res.append('Set-Cookie', `oauth_state=; HttpOnly; ${isProduction ? 'Secure; ' : ''}SameSite=Lax; Path=/; Max-Age=0`);
  try {
    // Exchange code for token
    const tokenRes = await fetchWithTimeout(fetch, 'https://discord.com/api/oauth2/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: DISCORD_CLIENT_ID, client_secret: DISCORD_CLIENT_SECRET,
        grant_type: 'authorization_code', code, redirect_uri: DISCORD_REDIRECT_URI
      })
    }, 8000);
    const tokenData = await tokenRes.json();
    if (!tokenData.access_token) return res.redirect('/?auth_error=token_failed');

    // Get Discord user info
    const userRes = await fetchWithTimeout(fetch, 'https://discord.com/api/users/@me', {
      headers: { 'Authorization': 'Bearer ' + tokenData.access_token }
    }, 8000);
    const discordUser = await userRes.json();
    if (!discordUser.id) return res.redirect('/?auth_error=user_failed');

    // Upsert user in DB
    let user;
    const existing = await pool.query('SELECT id, display_name, gamertag, platform FROM users WHERE discord_id = $1', [discordUser.id]);
    if (existing.rows.length) {
      user = existing.rows[0];
      await pool.query('UPDATE users SET discord_name = $1, avatar_url = $2, last_login = NOW() WHERE id = $3',
        [discordUser.username, discordUser.avatar ? `https://cdn.discordapp.com/avatars/${discordUser.id}/${discordUser.avatar}.png` : null, user.id]);
    } else {
      const result = await pool.query(
        'INSERT INTO users (discord_id, discord_name, display_name, avatar_url, email) VALUES ($1, $2, $3, $4, $5) RETURNING id, display_name, gamertag, platform',
        [discordUser.id, discordUser.username, discordUser.global_name || discordUser.username,
         discordUser.avatar ? `https://cdn.discordapp.com/avatars/${discordUser.id}/${discordUser.avatar}.png` : null,
         discordUser.email || null]
      );
      user = result.rows[0];
    }
    const jwtToken = generateToken(user);
    // Set HttpOnly cookie (primary) + URL token (for frontend state init)
    setAuthCookie(res, jwtToken);
    res.redirect('/#auth_token=' + jwtToken);
  } catch (e) {
    console.error('Discord OAuth error:', e.message);
    res.redirect('/#auth_error=server_error');
  }
});

// GET /auth/me — Get current user info
app.get('/auth/me', requireAuth, async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'Base de datos no disponible' });
  try {
    const result = await pool.query('SELECT id, display_name, gamertag, platform, email, discord_name, avatar_url, news_opt_in FROM users WHERE id = $1', [req.user.id]);
    if (!result.rows.length) return res.status(404).json({ error: 'Usuario no encontrado' });
    res.json({ user: result.rows[0] });
  } catch (e) { console.error(e.message); res.status(500).json({ error: 'Error interno del servidor' }); }
});

// PUT /auth/profile — Update gamertag + platform + news opt-in
app.put('/auth/profile', requireAuth, async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'Base de datos no disponible' });
  const { gamertag, platform, newsOptIn } = req.body;
  try {
    // If only updating news opt-in preference
    if (newsOptIn !== undefined && gamertag === undefined) {
      const result = await pool.query(
        'UPDATE users SET news_opt_in = $1 WHERE id = $2 RETURNING id, display_name, gamertag, platform, email, discord_name, avatar_url, news_opt_in',
        [!!newsOptIn, req.user.id]
      );
      if (!result.rows.length) return res.status(404).json({ error: 'Usuario no encontrado' });
      return res.json({ user: result.rows[0] });
    }
    const cleanGT = (gamertag || '').trim().slice(0, 50);
    const cleanPlat = ['psn', 'xbox'].includes(platform) ? platform : 'psn';
    const result = await pool.query(
      'UPDATE users SET gamertag = $1, platform = $2 WHERE id = $3 RETURNING id, display_name, gamertag, platform, email, discord_name, avatar_url, news_opt_in',
      [cleanGT || null, cleanPlat, req.user.id]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'Usuario no encontrado' });
    res.json({ user: result.rows[0] });
  } catch (e) { console.error(e.message); res.status(500).json({ error: 'Error interno del servidor' }); }
});

// ═══ FAVORITES SYNC ═══

// GET /favorites — Get user's favorites
app.get('/favorites', requireAuth, async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'Base de datos no disponible' });
  try {
    const { rows } = await pool.query('SELECT name, platform, fav_type, fav_group FROM user_favorites WHERE user_id = $1 ORDER BY added_at DESC', [req.user.id]);
    res.json({ favorites: rows });
  } catch (e) { console.error(e.message); res.status(500).json({ error: 'Error interno del servidor' }); }
});

// POST /favorites — Add a favorite
app.post('/favorites', requireAuth, async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'Base de datos no disponible' });
  const { name, platform, type, group } = req.body;
  if (!name) return res.status(400).json({ error: 'Nombre obligatorio' });
  try {
    await pool.query(
      'INSERT INTO user_favorites (user_id, name, platform, fav_type, fav_group) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (user_id, fav_type, name) DO UPDATE SET fav_group = $5, platform = $3',
      [req.user.id, name, platform || 'psn', type || 'player', group || '']
    );
    res.json({ ok: true });
  } catch (e) { console.error(e.message); res.status(500).json({ error: 'Error interno del servidor' }); }
});

// DELETE /favorites/:name — Remove a favorite
app.delete('/favorites/:name', requireAuth, async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'Base de datos no disponible' });
  try {
    const favType = req.query.type || 'player';
    await pool.query('DELETE FROM user_favorites WHERE user_id = $1 AND name = $2 AND fav_type = $3', [req.user.id, req.params.name, favType]);
    res.json({ ok: true });
  } catch (e) { console.error(e.message); res.status(500).json({ error: 'Error interno del servidor' }); }
});

// POST /favorites/sync — Full sync (replace all favorites)
app.post('/favorites/sync', requireAuth, async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'Base de datos no disponible' });
  const { favorites: favs } = req.body;
  if (!Array.isArray(favs)) return res.status(400).json({ error: 'Formato invalido' });
  try {
    await pool.query('DELETE FROM user_favorites WHERE user_id = $1', [req.user.id]);
    for (const f of favs) {
      await pool.query(
        'INSERT INTO user_favorites (user_id, name, platform, fav_type, fav_group) VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING',
        [req.user.id, f.name, f.platform || 'psn', f.type || 'player', f.group || '']
      );
    }
    res.json({ ok: true, count: favs.length });
  } catch (e) { console.error(e.message); res.status(500).json({ error: 'Error interno del servidor' }); }
});

// ═══ PUBG API PROXY WITH CACHE ═══
// Cache TTL in minutes per endpoint type
const CACHE_TTL = {
  seasons: 60,       // Seasons change rarely — cache 1 hour
  players: 10,       // Player search — cache 10 min
  'players/.*seasons': 10,  // Season stats — cache 10 min
  'players/.*matches': 5,   // Match list — cache 5 min
  leaderboards: 120, // Leaderboards — cache 2 hours (PUBG updates infrequently)
  default: 10        // Everything else — 10 min
};

function getCacheTTL(pubgPath) {
  if (/\/seasons$/.test(pubgPath)) return CACHE_TTL.seasons;
  if (/\/leaderboards\//.test(pubgPath)) return CACHE_TTL.leaderboards;
  if (/\/players\/.*\/seasons\//.test(pubgPath)) return CACHE_TTL['players/.*seasons'];
  if (/\/players\/.*\/matches/.test(pubgPath)) return CACHE_TTL['players/.*matches'];
  if (/\/players/.test(pubgPath)) return CACHE_TTL.players;
  return CACHE_TTL.default;
}

// ═══ LEADERBOARD SERVER-SIDE ENDPOINT ═══
// Dedicated endpoint that caches leaderboard data and returns cache age
// This avoids client-side API calls and enables pre-warming
app.get('/api/leaderboard', async (req, res) => {
  const { platform = 'console', region = 'eu', mode = 'squad-fpp' } = req.query;
  if (!SERVER_API_KEY) return res.status(503).json({ error: 'API key not configured' });

  const validPlatforms = ['console', 'psn', 'xbox'];
  const validRegions = ['eu', 'na', 'as'];
  const validModes = ['squad', 'squad-fpp', 'solo', 'solo-fpp', 'duo', 'duo-fpp'];
  if (!validPlatforms.includes(platform)) return res.status(400).json({ error: 'Invalid platform' });
  if (!validRegions.includes(region)) return res.status(400).json({ error: 'Invalid region' });
  if (!validModes.includes(mode)) return res.status(400).json({ error: 'Invalid mode' });

  const cacheKey = `lb_${platform}_${region}_${mode}`;
  const ttlMinutes = CACHE_TTL.leaderboards;

  // Check cache first
  if (pool) {
    try {
      const cached = await pool.query(
        "SELECT response_data, created_at FROM api_cache WHERE cache_key = $1 AND created_at > NOW() - INTERVAL '1 minute' * $2",
        [cacheKey, ttlMinutes]
      );
      if (cached.rows.length > 0) {
        const data = JSON.parse(cached.rows[0].response_data);
        const cachedAt = cached.rows[0].created_at;
        return res.json({ ...data, cachedAt, cacheHit: true });
      }
    } catch (e) { /* cache miss */ }
  }

  try {
    // Fetch current season
    const fetchPlat = platform === 'console' ? 'psn' : platform;
    const lbHeaders = { Authorization: 'Bearer ' + SERVER_API_KEY, Accept: 'application/vnd.api+json' };
    const seasonResp = await fetchWithTimeout(fetch, `https://api.pubg.com/shards/${fetchPlat}/seasons`, { headers: lbHeaders }, 10000);
    if (!seasonResp.ok) return res.status(503).json({ error: 'Failed to fetch seasons' });
    const seasonData = await seasonResp.json();
    const currentSeason = seasonData.data.find(s => s.attributes.isCurrentSeason);
    if (!currentSeason) return res.status(503).json({ error: 'No current season found' });
    const sid = currentSeason.id;

    let allPlayers = [];

    if (platform === 'console') {
      // Fetch PSN + Xbox and merge
      const [psnResp, xboxResp] = await Promise.all([
        fetchWithTimeout(fetch, `https://api.pubg.com/shards/psn-${region}/leaderboards/${sid}/${mode}`, { headers: lbHeaders }, 12000),
        fetchWithTimeout(fetch, `https://api.pubg.com/shards/xbox-${region}/leaderboards/${sid}/${mode}`, { headers: lbHeaders }, 12000)
      ]);
      const psnData = psnResp.ok ? await psnResp.json() : { data: { relationships: { players: { data: [] } } }, included: [] };
      const xboxData = xboxResp.ok ? await xboxResp.json() : { data: { relationships: { players: { data: [] } } }, included: [] };

      const playerMap = {};
      const processPlatform = (resp, plat) => {
        const players = resp.included || [];
        const pRelations = resp.data?.relationships?.players?.data || [];
        pRelations.forEach(pRef => {
          const p = players.find(pl => pl.id === pRef.id);
          if (!p || !p.attributes) return;
          const pa = p.attributes;
          const stats = pa.stats || {};
          const name = pa.name;
          if (!playerMap[name]) {
            playerMap[name] = { name, stats: { kills: 0, wins: 0, roundsPlayed: 0, averageDamage: 0 }, platforms: [] };
          }
          const entry = playerMap[name];
          // Use Math.max (not +=) because psn-eu and xbox-eu return the same cross-platform data.
          // Summing would double every player's stats.
          entry.stats.kills = Math.max(entry.stats.kills, stats.kills || 0);
          entry.stats.wins = Math.max(entry.stats.wins, stats.wins || 0);
          entry.stats.roundsPlayed = Math.max(entry.stats.roundsPlayed, stats.roundsPlayed || stats.games || 0);
          entry.stats.averageDamage = Math.max(entry.stats.averageDamage, stats.averageDamage || 0);
          entry.platforms.push(plat);
        });
      };
      processPlatform(psnData, 'PSN');
      processPlatform(xboxData, 'Xbox');
      allPlayers = Object.values(playerMap).sort((a, b) => (b.stats.kills || 0) - (a.stats.kills || 0)).slice(0, 500);
    } else {
      // Single platform
      const lbShard = `${platform}-${region}`;
      const lbResp = await fetchWithTimeout(fetch, `https://api.pubg.com/shards/${lbShard}/leaderboards/${sid}/${mode}`, { headers: lbHeaders }, 12000);
      if (!lbResp.ok) return res.status(503).json({ error: 'Failed to fetch leaderboard' });
      const lbData = await lbResp.json();
      const players = lbData.included || [];
      const pRelations = lbData.data?.relationships?.players?.data || [];
      pRelations.slice(0, 500).forEach(pRef => {
        const p = players.find(pl => pl.id === pRef.id);
        if (!p || !p.attributes) return;
        const pa = p.attributes;
        const stats = pa.stats || {};
        allPlayers.push({
          name: pa.name,
          stats: { kills: stats.kills || 0, wins: stats.wins || 0, roundsPlayed: stats.roundsPlayed || stats.games || 0, averageDamage: stats.averageDamage || 0 },
          platforms: [platform.toUpperCase()]
        });
      });
    }

    const result = { players: allPlayers, season: sid, platform, region, mode };
    const now = new Date().toISOString();

    // Save to cache
    if (pool) {
      try {
        await pool.query(
          "INSERT INTO api_cache (cache_key, response_data, status_code, created_at) VALUES ($1, $2, 200, NOW()) ON CONFLICT (cache_key) DO UPDATE SET response_data = $2, status_code = 200, created_at = NOW()",
          [cacheKey, JSON.stringify(result)]
        );
      } catch (e) { console.error('LB cache write error:', e.message); }
    }

    res.json({ ...result, cachedAt: now, cacheHit: false });
  } catch (e) {
    console.error('Leaderboard endpoint error:', e.message);
    res.status(500).json({ error: 'Error fetching leaderboard' });
  }
});

// ═══ BOT INDEX — Telemetry-based bot detection ═══
// MUST be before app.all('/api/*') to avoid being captured by the proxy
app.get('/api/bot-index/:platform/:playerName', async (req, res) => {
  const { platform, playerName } = req.params;
  const shard = ['psn','xbox','steam'].includes(platform) ? platform : 'psn';
  const cacheKey = `bot_index_${shard}_${playerName.toLowerCase()}`;

  // Check cache (6 hours) — skip stale entries with botKills=0 (old buggy data)
  if (pool) {
    try {
      const cached = await pool.query(
        "SELECT response_data FROM api_cache WHERE cache_key = $1 AND created_at > NOW() - INTERVAL '6 hours'",
        [cacheKey]
      );
      if (cached.rows.length) {
        try {
          const cData = JSON.parse(cached.rows[0].response_data);
          // Skip cache if it has the old bug (0 botKills but had kills — clearly wrong)
          if (cData.totalKills > 0 && cData.botKills === 0) { /* recalculate */ }
          else return res.json(cData);
        } catch(e) {}
      }
    } catch(e) {}
  }

  if (!SERVER_API_KEY) return res.status(503).json({ error: 'No API key' });
  const headers = { 'Authorization': 'Bearer ' + SERVER_API_KEY, 'Accept': 'application/vnd.api+json' };

  try {
    // 1. Get player + match IDs
    const pRes = await fetchWithTimeout(fetch, `https://api.pubg.com/shards/${shard}/players?filter[playerNames]=${encodeURIComponent(playerName)}`, { headers }, 12000);
    const pData = await pRes.json();
    if (!pData.data || !pData.data[0]) return res.json({ error: 'player_not_found' });

    const playerId = pData.data[0].id;
    // bot-index-pro-v1: subir de 5 a 25 partidas analizadas (con 100 RPM aprobado y batch
    // paralelo cabe holgadamente). N=25 da confianza estadística para detectar farmers
    // de bots con consistencia (5 partidas = ruido, 25 partidas = patrón claro).
    // Match JSON cuenta como RPM PUBG. Telemetría va al CDN (no cuenta).
    const matchIds = (pData.data[0].relationships?.matches?.data || []).slice(0, 25).map(m => m.id);
    if (!matchIds.length) return res.json({ error: 'no_matches', playerName, platform: shard, totalKills: 0, botKills: 0, humanKills: 0, botRatio: 0, matchesAnalyzed: 0 });

    let totalKills = 0, botKills = 0, analyzed = 0;

    // Procesar en batches paralelos de 5 (5 fetches simultáneos × 5 batches max).
    // Antes era secuencial (5 partidas tardaban ~10-15s sin caché). Ahora paralelo (~3-4s sin caché).
    const BATCH = 5;
    async function processOne(matchId) {
      try {
        let matchData;
        const mKey = `match_${shard}_${matchId}`;
        const mCached = await pool.query("SELECT response_data FROM api_cache WHERE cache_key = $1 AND created_at > NOW() - INTERVAL '30 days'", [mKey]);
        if (mCached.rows.length) {
          try { matchData = JSON.parse(mCached.rows[0].response_data); } catch(e) { matchData = null; }
        }
        if (!matchData) {
          const mRes = await fetchWithTimeout(fetch, `https://api.pubg.com/shards/${shard}/matches/${matchId}`, { headers }, 12000);
          matchData = await mRes.json();
          await pool.query(
            'INSERT INTO api_cache (cache_key, response_data, status_code, created_at) VALUES ($1, $2, 200, NOW()) ON CONFLICT (cache_key) DO UPDATE SET response_data = $2, created_at = NOW()',
            [mKey, JSON.stringify(matchData)]
          ).catch(() => {});
        }

        const asset = (matchData.included || []).find(i => i.type === 'asset');
        const telUrl = asset?.attributes?.URL;
        if (!telUrl) return null;

        let telemetry;
        const tKey = `telemetry_${matchId}`;
        const tCached = await pool.query("SELECT response_data FROM api_cache WHERE cache_key = $1 AND created_at > NOW() - INTERVAL '30 days'", [tKey]);
        if (tCached.rows.length) {
          try { telemetry = JSON.parse(tCached.rows[0].response_data); } catch(e) { telemetry = null; }
        }
        if (!telemetry) {
          const tRes = await fetchWithTimeout(fetch, telUrl, {}, 20000);
          telemetry = await tRes.json();
          await pool.query(
            'INSERT INTO api_cache (cache_key, response_data, status_code, created_at) VALUES ($1, $2, 200, NOW()) ON CONFLICT (cache_key) DO UPDATE SET response_data = $2, created_at = NOW()',
            [tKey, JSON.stringify(telemetry)]
          ).catch(() => {});
        }

        let mTotal = 0, mBots = 0;
        const killEvents = telemetry.filter(e => e._T === 'LogPlayerKillV2' || e._T === 'LogPlayerKill');
        for (const ev of killEvents) {
          const killer = ev.killer || ev.finisher;
          if (!killer || killer.accountId !== playerId) continue;
          mTotal++;
          const victimId = ev.victim?.accountId || '';
          if (!victimId || victimId === '' || victimId.startsWith('ai.')) mBots++;
        }
        return { mTotal, mBots };
      } catch(e) { return null; }
    }

    for (let i = 0; i < matchIds.length; i += BATCH) {
      const batch = matchIds.slice(i, i + BATCH);
      const results = await Promise.all(batch.map(processOne));
      for (const r of results) {
        if (!r) continue;
        totalKills += r.mTotal;
        botKills += r.mBots;
        analyzed++;
      }
    }

    const result = {
      playerName, platform: shard, totalKills, botKills,
      humanKills: totalKills - botKills,
      botRatio: totalKills > 0 ? Math.round((botKills / totalKills) * 100) : 0,
      matchesAnalyzed: analyzed,
      calculatedAt: new Date().toISOString()
    };

    // Cache result 6 hours
    if (pool) {
      await pool.query(
        'INSERT INTO api_cache (cache_key, response_data, status_code, created_at) VALUES ($1, $2, 200, NOW()) ON CONFLICT (cache_key) DO UPDATE SET response_data = $2, created_at = NOW()',
        [cacheKey, JSON.stringify(result)]
      ).catch(() => {});
    }

    res.json(result);
  } catch(err) {
    console.error('[bot-index]', err.message);
    res.status(500).json({ error: 'Error al analizar bots' });
  }
});

// ═══ PUBG Report Proxy (evita CORS) ═══
app.get('/api/pubg-report/:accountId', async (req, res) => {
  const accountId = req.params.accountId;
  try {
    const resp = await fetch('https://api.pubg.report/v1/players/' + encodeURIComponent(accountId));
    if (!resp.ok) return res.status(resp.status).json({ error: 'pubg.report returned ' + resp.status });
    const data = await resp.json();
    let encounters = [];
    if (Array.isArray(data)) encounters = data;
    else if (data.encounters) encounters = data.encounters;
    else if (data.data && Array.isArray(data.data)) encounters = data.data;
    else if (data.matches) encounters = data.matches;
    const clips = {};
    encounters.forEach(enc => {
      const mid = enc.match_id || enc.matchId || enc.MatchId || enc.id || (enc.match && enc.match.id) || '';
      if (!mid) return;
      let clipUrl = '', streamer = '';
      if (enc.clips && enc.clips.length) {
        clipUrl = enc.clips[0].url || enc.clips[0].clip_url || '';
        streamer = enc.clips[0].broadcaster_name || enc.clips[0].streamer || enc.clips[0].channel || '';
      } else if (enc.clip_url) { clipUrl = enc.clip_url; streamer = enc.streamer_name || ''; }
      else if (enc.url) { clipUrl = enc.url; streamer = enc.streamer || ''; }
      if (!clipUrl) clipUrl = 'https://pubg.report/players/' + encodeURIComponent(accountId);
      if (!streamer) streamer = 'Streamer';
      clips[mid] = { url: clipUrl, streamer };
    });
    res.set('Cache-Control', 'public, max-age=600');
    res.json({ clips, total: Object.keys(clips).length, raw_format: Array.isArray(data) ? 'array' : typeof data });
  } catch (e) {
    console.error('PUBG Report proxy error:', e.message);
    console.error('[pubg-report]', e.message); res.status(503).json({ error: 'Servicio no disponible' });
  }
});

// ═══ Player Snapshots (Mi Evolución) ═══
app.post('/api/snapshots', async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'No database' });
  const { player_name, platform, squad_mode, game_mode, kd, win_rate, avg_damage, hs_rate, kills, wins, rounds, top10_rate, longest_kill } = req.body;
  if (!player_name || !platform) return res.status(400).json({ error: 'player_name and platform required' });
  try {
    const existing = await pool.query(
      `SELECT id FROM player_snapshots
       WHERE player_name = $1 AND platform = $2 AND squad_mode = $3 AND game_mode = $4
       AND created_at > NOW() - INTERVAL '20 hours'
       ORDER BY created_at DESC LIMIT 1`,
      [player_name, platform, squad_mode || 'squad', game_mode || 'tpp']
    );
    if (existing.rows.length > 0) {
      const snap = existing.rows[0];
      await pool.query(
        `UPDATE player_snapshots SET kd=$1, win_rate=$2, avg_damage=$3, hs_rate=$4, kills=$5, wins=$6, rounds=$7, top10_rate=$8, longest_kill=$9
         WHERE id=$10`,
        [kd || 0, win_rate || 0, avg_damage || 0, hs_rate || 0, kills || 0, wins || 0, rounds || 0, top10_rate || 0, longest_kill || 0, snap.id]
      );
      return res.json({ ok: true, action: 'updated' });
    }
    await pool.query(
      `INSERT INTO player_snapshots (player_name, platform, squad_mode, game_mode, kd, win_rate, avg_damage, hs_rate, kills, wins, rounds, top10_rate, longest_kill)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
      [player_name, platform, squad_mode || 'squad', game_mode || 'tpp',
       kd || 0, win_rate || 0, avg_damage || 0, hs_rate || 0, kills || 0, wins || 0, rounds || 0, top10_rate || 0, longest_kill || 0]
    );
    res.json({ ok: true, action: 'created' });
  } catch (e) { console.error('Snapshot save error:', e.message); res.status(500).json({ error: 'Error saving snapshot' }); }
});

app.get('/api/snapshots/:platform/:player', async (req, res) => {
  if (!pool) return res.json({ snapshots: [] });
  const { platform, player } = req.params;
  const squad_mode = req.query.squad_mode || 'squad';
  const game_mode = req.query.game_mode || 'tpp';
  try {
    const { rows } = await pool.query(
      `SELECT kd, win_rate, avg_damage, hs_rate, kills, wins, rounds, top10_rate, longest_kill, created_at
       FROM player_snapshots
       WHERE player_name = $1 AND platform = $2 AND squad_mode = $3 AND game_mode = $4
       ORDER BY created_at ASC
       LIMIT 12`,
      [player, platform, squad_mode, game_mode]
    );
    res.json({ snapshots: rows });
  } catch (e) { console.error('Snapshot fetch error:', e.message); res.status(500).json({ error: 'Error fetching snapshots' }); }
});

// ============ V4NZ Leaderboard (top players from snapshots) ============
app.get('/api/v4nz-leaderboard', async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'No database' });
  const { platform = 'all', mode = 'squad', game_mode = 'tpp' } = req.query;

  const cacheKey = `v4nz-lb:${platform}:${mode}:${game_mode}`;
  // Check cache (1 hour TTL)
  try {
    const cached = await pool.query(
      "SELECT response_data, created_at FROM api_cache WHERE cache_key = $1 AND created_at > NOW() - INTERVAL '60 minutes'",
      [cacheKey]
    );
    if (cached.rows.length > 0) {
      return res.json({ ...JSON.parse(cached.rows[0].response_data), cachedAt: cached.rows[0].created_at, cacheHit: true });
    }
  } catch (e) { /* cache miss */ }

  try {
    const platformFilter = platform !== 'all' ? 'AND ps.platform = $4' : '';
    const params = [mode, game_mode, 50];
    if (platform !== 'all') params.push(platform);

    const { rows } = await pool.query(
      `SELECT DISTINCT ON (ps.player_name)
         ps.player_name, ps.platform, ps.kd, ps.avg_damage, ps.win_rate, ps.hs_rate, ps.kills, ps.wins, ps.rounds, ps.top10_rate, ps.created_at
       FROM player_snapshots ps
       WHERE ps.squad_mode = $1 AND ps.game_mode = $2
         AND ps.rounds >= $3
         ${platformFilter}
       ORDER BY ps.player_name, ps.created_at DESC`,
      params
    );

    // Sort by K/D descending, take top 100
    const sorted = rows.sort((a, b) => parseFloat(b.kd) - parseFloat(a.kd)).slice(0, 100);

    // Add rank
    const ranked = sorted.map((r, i) => ({ ...r, rank: i + 1 }));

    const result = { players: ranked, total: ranked.length, filters: { platform, mode, game_mode } };

    // Store in cache
    try {
      await pool.query(
        `INSERT INTO api_cache (cache_key, response_data, created_at) VALUES ($1, $2, NOW())
         ON CONFLICT (cache_key) DO UPDATE SET response_data = $2, created_at = NOW()`,
        [cacheKey, JSON.stringify(result)]
      );
    } catch (e) { /* cache write error, non-fatal */ }

    res.json(result);
  } catch (e) {
    console.error('V4NZ leaderboard error:', e.message);
    res.status(500).json({ error: 'Error fetching leaderboard' });
  }
});

// ============ Clear AI DNA cache for a player (admin use) ============
app.delete('/api/ai-dna-cache', async (req, res) => {
  const { playerName, platform } = req.query;
  if (!playerName || !pool) return res.status(400).json({ error: 'Missing playerName' });
  const cacheKey = `ai-dna:${playerName.toLowerCase()}:${platform || 'psn'}`;
  try {
    const result = await pool.query('DELETE FROM api_cache WHERE cache_key = $1', [cacheKey]);
    res.json({ ok: true, deleted: result.rowCount });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ============ AI DNA Analysis (MUST be before the PUBG API catch-all proxy) ============
app.get('/api/ai-dna', async (req, res) => {
  try {
    const { playerName, platform, stats: statsParam } = req.query;
    let stats;
    try { stats = JSON.parse(decodeURIComponent(statsParam || '{}')); } catch(e) { stats = null; }
    if (!playerName || !stats) return res.status(400).json({ error: 'Missing playerName or stats' });

    const cacheKey = `ai-dna:${playerName.toLowerCase()}:${platform || 'psn'}`;

    // Check cache
    try {
      const cached = await pool.query(
        `SELECT data FROM api_cache WHERE cache_key = $1 AND created_at + (ttl_seconds || ' seconds')::interval > NOW()`,
        [cacheKey]
      );
      if (cached.rows.length > 0) {
        return res.json(cached.rows[0].data);
      }
    } catch (e) { console.error('AI DNA cache check error:', e); }

    // Check if Anthropic API key is configured
    if (!process.env.ANTHROPIC_API_KEY) {
      return res.status(503).json({ error: 'AI analysis not available' });
    }

    // Dynamic import of Anthropic SDK
    let AnthropicSDK;
    try {
      AnthropicSDK = await import('@anthropic-ai/sdk');
    } catch (e) {
      console.error('Failed to import Anthropic SDK:', e);
      return res.status(503).json({ error: 'AI service unavailable' });
    }
    const Anthropic = AnthropicSDK.default || AnthropicSDK.Anthropic;
    const client = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });

    const systemPrompt = `Eres V4NZ AI, el analista experto de PUBG para consola (PlayStation/Xbox) de v4nz.com. Analizas estadísticas de jugadores y generas perfiles de personalidad ÚNICOS, detallados y técnicamente precisos.

═══ BENCHMARKS REALES PSN/XBOX CONSOLA (Temporada 40+) ═══
K/D: Top 1% = 5.0+ | Top 5% = 4.0-5.0 | Top 10% = 3.0-4.0 | Top 25% = 2.0-3.0 | Media = 1.0-1.5 | Bajo = <1.0
ADR: Top 1% = 350+ | Top 5% = 250-350 | Top 10% = 180-250 | Media = 100-150 | Bajo = <80
HS%: Top 1% = 25%+ | Bueno = 18-25% | Normal consola = 12-18% | Bajo = <12%
Win Rate: Top 1% = 20%+ | Bueno = 10-20% | Normal = 3-8% | Bajo = <3%
Top10 Rate: Bueno = >40% | Normal = 25-40% | Bajo = <20%

═══ PATRONES DE DIAGNÓSTICO (CRUCES DE STATS) ═══
SIEMPRE cruza al menos 3 stats. Una stat aislada puede engañar.

• K/D alto + ADR alto = Jugador REALMENTE bueno, hace daño y remata
• K/D alto + ADR bajo (<150) = Probable bot farmer o muy pasivo, espera kills fáciles
• K/D alto + HS% alto = Jugador técnico, excelente control del arma
• K/D alto + HS% bajo = Posible problema de mando o solo farmea bots de cerca
• K/D alto + Win Rate bajo = Bueno en combate pero no sabe cerrar partidas/gestionar círculo
• ADR alto + K/D bajo = Support del squad — hace el daño, el equipo remata (NO es malo)
• Revives altos = Pilar del equipo, NUNCA decirle que suba K/D
• Assists/Kill ratio >0.5 = Jugador de equipo, comparte daño
• Longest Kill >300m = Usa snipers regularmente con confianza
• Longest Kill <200m = Raramente usa larga distancia, jugador CQC/mid range
• Walk dist alta + Ride dist baja = Jugador táctico, evita ruido de vehículo
• Walk dist baja + Ride dist alta = "Road warrior", mucho vehículo
• Survival Time >28min = Muy pasivo/rat | 20-28min = Equilibrado | <15min = Muy agresivo

═══ BOT RATIO — CLAVE PARA HONESTIDAD ═══
• Bot ratio <15%: K/D es fiable, stats reales
• Bot ratio 15-30%: K/D algo inflado, el "real" contra humanos es ~10-15% menor
• Bot ratio 30-50%: K/D significativamente inflado, mencionar con tacto
• Bot ratio >50%: Stats apenas analizables, ser honesto pero constructivo
Fórmula: Si K/D > 3.5 Y ADR < 200 Y Longest Kill < 200m → MUY probable bot farming

═══ ARQUETIPOS DE JUGADOR ═══
• DEPREDADOR: K/D >3, ADR >250, agresivo, busca pelea, survival time bajo
• RATA/SUPERVIVIENTE: K/D >1.5, ADR <150, survival time >25min, Win Rate alto, pocos kills
• FRANCOTIRADOR: HS% >20%, Longest Kill >400m, ADR moderado, kills a distancia
• SUPPORT: Revives altos, assists altos, ADR puede ser alto pero K/D moderado
• TÉCNICO: HS% >22%, ADR >200, balance entre agresividad y supervivencia
• BOT FARMER: K/D >3 con ADR <200 y bot ratio >40%, stats infladas

═══ REGLAS ESTRICTAS ═══
- El rol SIEMPRE debe ser 2 palabras creativas en español, NUNCA una sola palabra
- Los insights deben ser MUY ESPECÍFICOS a los números del jugador, NUNCA genéricos
- SIEMPRE menciona el percentil real basado en los benchmarks de arriba
- Si bot ratio >30%, DEBES mencionarlo en la descripción con tacto constructivo
- Habla directamente al jugador usando "tú"
- El ADR es más honesto que el K/D — dale más peso en tu análisis
- Responde SOLO con JSON válido, sin markdown ni explicaciones
- Los scores pueden diferir de los heurísticos si tu análisis lo justifica`;

    const userPrompt = `Analiza este jugador de PUBG consola:

Nombre: ${playerName} (${platform || 'psn'})

STATS PRINCIPALES:
• K/D: ${stats.kd} | ADR (Daño medio/partida): ${stats.avgDamage}
• Headshot%: ${stats.hsRate}% | Win Rate: ${stats.winRate}% | Top 10: ${stats.top10Rate}%
• Kills/partida: ${stats.killsPerRound} | Longest Kill: ${stats.longestKill}m

MOVIMIENTO Y ESTILO:
• Distancia a pie/partida: ${stats.walkDistPerRound}m | En vehículo/partida: ${stats.rideDistPerRound}m

EQUIPO (squad):
• Revives/partida: ${stats.revivesPerRound} | Asistencias/partida: ${stats.assistsPerRound}
• Curas/partida: ${stats.healsPerRound}

CONTEXTO:
• Total partidas: ${stats.roundsPlayed}
${stats.botRatio != null ? `• Bot ratio estimado: ${stats.botRatio}%` : '• Bot ratio: no disponible'}
• Rol heurístico actual: ${stats.role}
• Scores heurísticos: AGR ${stats.dnaScores?.agresividad || '?'}, PRE ${stats.dnaScores?.precision || '?'}, SUP ${stats.dnaScores?.supervivencia || '?'}, MOV ${stats.dnaScores?.movilidad || '?'}, SOP ${stats.dnaScores?.soporte || '?'}

INSTRUCCIONES:
1. Cruza las stats usando los patrones de diagnóstico del system prompt
2. Identifica el arquetipo real del jugador
3. Si bot ratio >30%, ajusta tu evaluación siendo honesto pero constructivo
4. Usa los benchmarks reales para dar percentiles PRECISOS

Genera el análisis JSON:
{
  "role": "DOS PALABRAS CREATIVAS EN MAYÚSCULAS",
  "roleColor": "#hexcolor (#ff3355=agresivo, #a855f7=técnico, #ffd700=élite, #00ff88=superviviente, #ff6b00=caótico, #00f0ff=táctico)",
  "description": "2-3 frases personalizadas con diagnóstico cruzado real. Menciona percentiles. Si bot ratio alto, menciónalo con tacto.",
  "insights": ["1 FORTALEZA principal del jugador con datos", "1 DEBILIDAD o área de mejora con datos", "1 dato SORPRENDENTE o curioso del cruce de stats"],
  "tip": "1 consejo accionable y específico basado en la debilidad detectada",
  "scores": {"agresividad": 0-100, "precision": 0-100, "supervivencia": 0-100, "movilidad": 0-100, "soporte": 0-100}
}`;

    // Retry up to 2 times on transient errors
    let response, lastErr;
    for (let attempt = 0; attempt < 2; attempt++) {
      try {
        response = await client.messages.create({
          model: 'claude-sonnet-4-6',
          max_tokens: 1200,
          system: systemPrompt,
          messages: [{ role: 'user', content: userPrompt }]
        });
        break;
      } catch (apiErr) {
        lastErr = apiErr;
        console.error(`AI DNA API attempt ${attempt + 1} failed:`, apiErr.status || apiErr.message);
        if (attempt === 0 && (apiErr.status === 529 || apiErr.status === 500 || apiErr.status === 502 || apiErr.status === 503)) {
          await new Promise(r => setTimeout(r, 500));  // rpm100-throttling-relax-v2: 2000→500ms (export workflows)
          continue;
        }
        throw apiErr;
      }
    }
    if (!response) throw lastErr || new Error('AI API failed after retries');

    const text = response.content[0]?.text || '';
    let aiResult;
    try {
      // Try to parse JSON, handle potential markdown wrapping
      const jsonMatch = text.match(/\{[\s\S]*\}/);
      aiResult = JSON.parse(jsonMatch ? jsonMatch[0] : text);
    } catch (e) {
      console.error('AI DNA parse error, raw text:', text.substring(0, 500));
      return res.status(500).json({ error: 'Failed to parse AI response' });
    }

    // Validate required fields
    if (!aiResult.role || !aiResult.description || !aiResult.scores) {
      console.error('AI DNA incomplete response, keys:', Object.keys(aiResult));
      return res.status(500).json({ error: 'Incomplete AI response' });
    }

    aiResult.generatedAt = new Date().toISOString();

    // Cache result (7 days)
    try {
      await pool.query(
        `INSERT INTO api_cache (cache_key, data, ttl_seconds) VALUES ($1, $2, $3) ON CONFLICT (cache_key) DO UPDATE SET data = $2, created_at = NOW(), ttl_seconds = $3`,
        [cacheKey, JSON.stringify(aiResult), 604800]
      );
    } catch (e) { console.error('AI DNA cache save error:', e); }

    res.json(aiResult);

  } catch (e) {
    console.error('AI DNA error:', e.status || e.code || '', e.message || e);
    res.status(500).json({ error: 'AI analysis failed', detail: e.message || 'Unknown error' });
  }
});

// ============ AI Compare Players (MUST be before the PUBG API catch-all proxy) ============
app.get('/api/ai-compare-players', async (req, res) => {
  try {
    const { p1, p2, platform, mode, stats: statsParam } = req.query;
    let payload;
    try { payload = JSON.parse(decodeURIComponent(statsParam || '{}')); } catch(e) { payload = null; }
    if (!p1 || !p2 || !payload || !payload.s1 || !payload.s2) return res.status(400).json({ error: 'Missing players or stats' });

    // Normalise cache key: order players alphabetically so A-vs-B and B-vs-A share cache
    const [a, b] = [p1.toLowerCase(), p2.toLowerCase()].sort();
    const cacheKey = `ai-compare:${a}:${b}:${platform || 'psn'}:${mode || 'squad'}`;

    // Check cache
    if (pool) {
      try {
        const cached = await pool.query(
          `SELECT data FROM api_cache WHERE cache_key = $1 AND created_at + (ttl_seconds || ' seconds')::interval > NOW()`,
          [cacheKey]
        );
        if (cached.rows.length > 0) {
          return res.json(cached.rows[0].data);
        }
      } catch (e) { console.error('AI compare cache check error:', e); }
    }

    if (!process.env.ANTHROPIC_API_KEY) {
      return res.status(503).json({ error: 'AI analysis not available' });
    }

    let AnthropicSDK;
    try {
      AnthropicSDK = await import('@anthropic-ai/sdk');
    } catch (e) {
      console.error('Failed to import Anthropic SDK:', e);
      return res.status(503).json({ error: 'AI service unavailable' });
    }
    const Anthropic = AnthropicSDK.default || AnthropicSDK.Anthropic;
    const client = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });

    const systemPrompt = `Eres V4NZ AI, el analista experto de PUBG consola (PSN/Xbox) de v4nz.com. Comparas DOS jugadores de forma justa, técnica y con tacto competitivo.

═══ BENCHMARKS PSN/XBOX CONSOLA (Temporada 40+) ═══
K/D: Top 1% 5.0+ | Top 5% 4-5 | Top 10% 3-4 | Top 25% 2-3 | Media 1-1.5 | Bajo <1
ADR: Top 1% 350+ | Top 5% 250-350 | Top 10% 180-250 | Media 100-150 | Bajo <80
HS%: Top 1% 25%+ | Bueno 18-25% | Normal 12-18% | Bajo <12%
Win Rate: Top 1% 20%+ | Bueno 10-20% | Normal 3-8% | Bajo <3%

═══ REGLAS DE COMPARACIÓN ═══
- Cruza stats. El ADR es más honesto que el K/D.
- Si un jugador tiene muchas menos partidas (<30% del otro) menciónalo: su stat puede ser menos fiable.
- Identifica CATEGORÍAS donde cada uno domina: Combate (K/D+ADR), Precisión (HS%+Longest), Supervivencia (WinRate+Top10+TimeSurvived), Soporte (revives+assists).
- El veredicto NO es solo "quién tiene más K/D". Valora el conjunto, el rol, y la fiabilidad muestral.
- Sé justo: si hay empate técnico dilo. Evita sesgos.
- Habla en español, tono directo pero respetuoso, nada de insultos.
- Responde SOLO con JSON válido, sin markdown.`;

    const s1 = payload.s1, s2 = payload.s2;
    const userPrompt = `Compara estos dos jugadores de PUBG consola (${platform || 'psn'}, modo ${mode || 'squad'}):

═══ JUGADOR 1: ${p1} ═══
• K/D: ${s1.kd} | ADR: ${s1.avgDamage} | HS%: ${s1.hsRate}%
• Win Rate: ${s1.winRate}% | Top10%: ${s1.top10Rate}%
• Kills: ${s1.kills} | Wins: ${s1.wins} | Partidas: ${s1.rounds}
• Longest Kill: ${s1.longestKill}m | Revives: ${s1.revives} | Assists: ${s1.assists}

═══ JUGADOR 2: ${p2} ═══
• K/D: ${s2.kd} | ADR: ${s2.avgDamage} | HS%: ${s2.hsRate}%
• Win Rate: ${s2.winRate}% | Top10%: ${s2.top10Rate}%
• Kills: ${s2.kills} | Wins: ${s2.wins} | Partidas: ${s2.rounds}
• Longest Kill: ${s2.longestKill}m | Revives: ${s2.revives} | Assists: ${s2.assists}

Genera el análisis JSON:
{
  "winner": "${p1}" | "${p2}" | "EMPATE",
  "winnerReason": "1 frase explicando por qué gana (o por qué es empate técnico)",
  "categories": {
    "combate": {"winner":"${p1}"|"${p2}"|"EMPATE","note":"breve nota cruzando K/D y ADR"},
    "precision": {"winner":"${p1}"|"${p2}"|"EMPATE","note":"breve nota con HS% y longest kill"},
    "supervivencia": {"winner":"${p1}"|"${p2}"|"EMPATE","note":"breve nota con WR y Top10"},
    "soporte": {"winner":"${p1}"|"${p2}"|"EMPATE","note":"breve nota con revives y assists"}
  },
  "sampleWarning": "si uno tiene muchas menos partidas menciónalo aquí, si no null",
  "styleP1": "2-4 palabras que describan el estilo del jugador 1",
  "styleP2": "2-4 palabras que describan el estilo del jugador 2",
  "verdict": "2-3 frases de análisis final comparando a ambos jugadores",
  "tipLoser": "1 consejo accionable para el jugador que pierde (o el más flojo en caso de empate)"
}`;

    let response, lastErr;
    for (let attempt = 0; attempt < 2; attempt++) {
      try {
        response = await client.messages.create({
          model: 'claude-sonnet-4-6',
          max_tokens: 1400,
          system: systemPrompt,
          messages: [{ role: 'user', content: userPrompt }]
        });
        break;
      } catch (apiErr) {
        lastErr = apiErr;
        console.error(`AI compare API attempt ${attempt + 1} failed:`, apiErr.status || apiErr.message);
        if (attempt === 0 && (apiErr.status === 529 || apiErr.status === 500 || apiErr.status === 502 || apiErr.status === 503)) {
          await new Promise(r => setTimeout(r, 500));  // rpm100-throttling-relax-v2: 2000→500ms (export workflows)
          continue;
        }
        throw apiErr;
      }
    }
    if (!response) throw lastErr || new Error('AI API failed after retries');

    const text = response.content[0]?.text || '';
    let aiResult;
    try {
      const jsonMatch = text.match(/\{[\s\S]*\}/);
      aiResult = JSON.parse(jsonMatch ? jsonMatch[0] : text);
    } catch (e) {
      console.error('AI compare parse error, raw text:', text.substring(0, 500));
      return res.status(500).json({ error: 'Failed to parse AI response' });
    }

    if (!aiResult.winner || !aiResult.verdict || !aiResult.categories) {
      console.error('AI compare incomplete response, keys:', Object.keys(aiResult));
      return res.status(500).json({ error: 'Incomplete AI response' });
    }

    aiResult.generatedAt = new Date().toISOString();
    aiResult.p1 = p1;
    aiResult.p2 = p2;

    if (pool) {
      try {
        await pool.query(
          `INSERT INTO api_cache (cache_key, data, ttl_seconds) VALUES ($1, $2, $3) ON CONFLICT (cache_key) DO UPDATE SET data = $2, created_at = NOW(), ttl_seconds = $3`,
          [cacheKey, JSON.stringify(aiResult), 604800]
        );
      } catch (e) { console.error('AI compare cache save error:', e); }
    }

    res.json(aiResult);

  } catch (e) {
    console.error('AI compare error:', e.status || e.code || '', e.message || e);
    res.status(500).json({ error: 'AI compare failed', detail: e.message || 'Unknown error' });
  }
});

// ============ AI Deep Analysis (Pro) — usuario logueado con historial (v154) ============
app.get('/api/ai-deep-analysis', requireAuth, async (req, res) => {
  try {
    if (!pool) return res.status(503).json({ error: 'DB not available' });
    const userId = req.user.id;
    const { stats: statsParam } = req.query;
    let currentStats;
    try { currentStats = JSON.parse(decodeURIComponent(statsParam || '{}')); } catch(e) { currentStats = null; }
    if (!currentStats || !currentStats.kd) return res.status(400).json({ error: 'Missing current stats' });

    // Get user's linked gamertag
    const u = await pool.query('SELECT gamertag, platform, display_name FROM users WHERE id = $1', [userId]);
    if (!u.rows.length || !u.rows[0].gamertag) return res.status(400).json({ error: 'No gamertag vinculado' });
    const gamertag = u.rows[0].gamertag;
    const platform = u.rows[0].platform || 'psn';

    const cacheKey = `ai-deep:${userId}:${gamertag.toLowerCase()}:${platform}`;

    // Check cache
    try {
      const cached = await pool.query(
        `SELECT data FROM api_cache WHERE cache_key = $1 AND created_at + (ttl_seconds || ' seconds')::interval > NOW()`,
        [cacheKey]
      );
      if (cached.rows.length > 0) return res.json(cached.rows[0].data);
    } catch (e) { console.error('Deep analysis cache check error:', e); }

    if (!process.env.ANTHROPIC_API_KEY) {
      return res.status(503).json({ error: 'AI analysis not available' });
    }

    // Fetch historical snapshots (last 90 days) for the linked gamertag across modes
    const snapsQ = await pool.query(
      `SELECT squad_mode, game_mode, kd, win_rate, avg_damage, hs_rate, kills, wins, rounds, top10_rate, longest_kill, created_at
       FROM player_snapshots
       WHERE player_name = $1 AND platform = $2 AND created_at > NOW() - INTERVAL '90 days'
       ORDER BY created_at ASC`,
      [gamertag, platform]
    );
    const allSnaps = snapsQ.rows;

    // Pick main mode (squad tpp if available, else most frequent)
    const modeCount = {};
    allSnaps.forEach(s => { const k = `${s.squad_mode}:${s.game_mode}`; modeCount[k] = (modeCount[k]||0)+1; });
    let mainMode = 'squad:tpp';
    if (!modeCount[mainMode]) {
      const sorted = Object.entries(modeCount).sort((a,b)=>b[1]-a[1]);
      if (sorted.length) mainMode = sorted[0][0];
    }
    const [msq, mgm] = mainMode.split(':');
    const modeSnaps = allSnaps.filter(s => s.squad_mode === msq && s.game_mode === mgm);

    // Compute trends: last vs ~7d, ~30d, ~90d ago
    function findSnapNDaysAgo(snaps, days) {
      if (!snaps.length) return null;
      const target = Date.now() - days * 86400000;
      let best = snaps[0], bestDiff = Math.abs(new Date(snaps[0].created_at).getTime() - target);
      for (const s of snaps) {
        const d = Math.abs(new Date(s.created_at).getTime() - target);
        if (d < bestDiff) { bestDiff = d; best = s; }
      }
      return best;
    }
    function delta(curr, prev, key) {
      if (!curr || !prev) return null;
      const a = parseFloat(curr[key]) || 0, b = parseFloat(prev[key]) || 0;
      if (b === 0) return null;
      return ((a - b) / b * 100).toFixed(1);
    }
    const latest = modeSnaps.length ? modeSnaps[modeSnaps.length-1] : null;
    const s7 = findSnapNDaysAgo(modeSnaps, 7);
    const s30 = findSnapNDaysAgo(modeSnaps, 30);
    const s90 = findSnapNDaysAgo(modeSnaps, 90);
    const trends = {
      kd_7d: delta(latest, s7, 'kd'), kd_30d: delta(latest, s30, 'kd'), kd_90d: delta(latest, s90, 'kd'),
      adr_7d: delta(latest, s7, 'avg_damage'), adr_30d: delta(latest, s30, 'avg_damage'), adr_90d: delta(latest, s90, 'avg_damage'),
      wr_30d: delta(latest, s30, 'win_rate'), wr_90d: delta(latest, s90, 'win_rate'),
      hs_30d: delta(latest, s30, 'hs_rate'), hs_90d: delta(latest, s90, 'hs_rate')
    };
    // Days active (snapshots with rounds delta > 0 vs previous)
    let daysActive = 0;
    for (let i = 1; i < modeSnaps.length; i++) {
      if ((modeSnaps[i].rounds || 0) > (modeSnaps[i-1].rounds || 0)) daysActive++;
    }

    let AnthropicSDK;
    try { AnthropicSDK = await import('@anthropic-ai/sdk'); }
    catch (e) { return res.status(503).json({ error: 'AI service unavailable' }); }
    const Anthropic = AnthropicSDK.default || AnthropicSDK.Anthropic;
    const client = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });

    const systemPrompt = `Eres V4NZ AI Pro, el analista DEFINITIVO de jugadores PUBG consola (PSN/Xbox) de v4nz.com. Este es un análisis PROFUNDO y PRIVADO para un usuario registrado que ha vinculado su gamertag y tiene datos históricos.

═══ BENCHMARKS PSN/XBOX CONSOLA (Temporada 40+) ═══
K/D: Top 1% 5.0+ | Top 5% 4-5 | Top 10% 3-4 | Top 25% 2-3 | Media 1-1.5 | Bajo <1
ADR: Top 1% 350+ | Top 5% 250-350 | Top 10% 180-250 | Media 100-150 | Bajo <80
HS%: Top 1% 25%+ | Bueno 18-25% | Normal 12-18% | Bajo <12%
Win Rate: Top 1% 20%+ | Bueno 10-20% | Normal 3-8% | Bajo <3%

═══ META DE CONSOLA — LOADOUTS RECOMENDADOS ═══
• Agresivo CQC: Beryl M762 + sight red dot + angled grip + compensador (meta actual)
• Equilibrado mid-range: Beryl/M416 + 2x/3x + angled grip + flash hider
• Precisión larga distancia: SLR o Mini14 + 4x/6x + cheekpad + compensador
• Support defensivo: SLR + 4x o QBU + scope + shotgun secundaria

═══ TENDENCIAS — CÓMO INTERPRETARLAS ═══
• Delta K/D 30d +10%+ = progresión real, el jugador está en racha
• Delta K/D 30d -10%- = estancamiento o regresión, investigar causa
• Delta ADR subiendo mientras K/D baja = jugador más agresivo pero muriendo antes
• Delta WR subiendo con K/D estable = mejor gestión de círculo y posicionamiento
• Días activos <10 en 90d = jugador esporádico, las stats son menos fiables

═══ REGLAS ESTRICTAS ═══
- Este es un análisis PRIVADO PRO, puede ser más directo y técnico que el AI DNA público
- USA las tendencias históricas para detectar progresión, estancamiento o regresión
- Da un plan de entrenamiento CONCRETO con 4-5 pasos accionables
- Recomienda un loadout específico basado en el estilo detectado
- Propón un objetivo SMART realista para los próximos 30 días
- Habla al jugador usando "tú" y su nombre
- Responde SOLO con JSON válido, sin markdown`;

    const userPrompt = `Análisis PRO privado para ${u.rows[0].display_name} (gamertag: ${gamertag}, ${platform}, modo principal: ${msq}/${mgm}).

═══ STATS ACTUALES (temporada) ═══
• K/D: ${currentStats.kd} | ADR: ${currentStats.avgDamage} | HS%: ${currentStats.hsRate}%
• Win Rate: ${currentStats.winRate}% | Top 10%: ${currentStats.top10Rate}%
• Kills: ${currentStats.kills} | Wins: ${currentStats.wins} | Partidas: ${currentStats.rounds}
• Longest Kill: ${currentStats.longestKill}m | Revives/ronda: ${currentStats.revivesPerRound || 0}

═══ HISTORIAL (últimos 90 días) ═══
• Snapshots disponibles: ${modeSnaps.length}
• Días activos (partidas jugadas): ${daysActive}
• Delta K/D 7d: ${trends.kd_7d || 'N/A'}% | 30d: ${trends.kd_30d || 'N/A'}% | 90d: ${trends.kd_90d || 'N/A'}%
• Delta ADR 7d: ${trends.adr_7d || 'N/A'}% | 30d: ${trends.adr_30d || 'N/A'}% | 90d: ${trends.adr_90d || 'N/A'}%
• Delta WR 30d: ${trends.wr_30d || 'N/A'}% | 90d: ${trends.wr_90d || 'N/A'}%
• Delta HS% 30d: ${trends.hs_30d || 'N/A'}% | 90d: ${trends.hs_90d || 'N/A'}%

Genera el análisis JSON:
{
  "profile": "2-3 frases describiendo el perfil técnico del jugador con percentiles reales",
  "trendSummary": "1-2 frases interpretando la dirección global (progresando/estancado/regresando) con datos",
  "trends": {
    "kd": {"direction":"subiendo"|"estancado"|"bajando","note":"breve nota con delta %"},
    "adr": {"direction":"subiendo"|"estancado"|"bajando","note":"breve nota con delta %"},
    "winRate": {"direction":"subiendo"|"estancado"|"bajando","note":"breve nota"},
    "headshots": {"direction":"subiendo"|"estancado"|"bajando","note":"breve nota"}
  },
  "strengths": ["3 fortalezas concretas con datos"],
  "weaknesses": ["3 debilidades concretas con datos"],
  "loadout": {
    "style": "etiqueta del estilo detectado",
    "primary": "arma primaria + 2-3 accesorios",
    "secondary": "arma secundaria recomendada",
    "rationale": "1 frase explicando por qué este loadout encaja con su estilo"
  },
  "trainingPlan": ["4-5 pasos concretos y accionables para los próximos 30 días"],
  "next30DaysGoal": "1 objetivo SMART específico y medible (ej: subir ADR de 145 a 170)"
}`;

    let response, lastErr;
    for (let attempt = 0; attempt < 2; attempt++) {
      try {
        response = await client.messages.create({
          model: 'claude-sonnet-4-6',
          max_tokens: 2000,
          system: systemPrompt,
          messages: [{ role: 'user', content: userPrompt }]
        });
        break;
      } catch (apiErr) {
        lastErr = apiErr;
        console.error(`AI deep analysis attempt ${attempt + 1} failed:`, apiErr.status || apiErr.message);
        if (attempt === 0 && (apiErr.status === 529 || apiErr.status === 500 || apiErr.status === 502 || apiErr.status === 503)) {
          await new Promise(r => setTimeout(r, 500));  // rpm100-throttling-relax-v2: 2000→500ms (export workflows)
          continue;
        }
        throw apiErr;
      }
    }
    if (!response) throw lastErr || new Error('AI API failed after retries');

    const text = response.content[0]?.text || '';
    let aiResult;
    try {
      const jsonMatch = text.match(/\{[\s\S]*\}/);
      aiResult = JSON.parse(jsonMatch ? jsonMatch[0] : text);
    } catch (e) {
      console.error('AI deep analysis parse error, raw:', text.substring(0, 500));
      return res.status(500).json({ error: 'Failed to parse AI response' });
    }
    if (!aiResult.profile || !aiResult.trainingPlan || !aiResult.loadout) {
      return res.status(500).json({ error: 'Incomplete AI response' });
    }

    aiResult.generatedAt = new Date().toISOString();
    aiResult.gamertag = gamertag;
    aiResult.platform = platform;
    aiResult.snapshotsAnalyzed = modeSnaps.length;
    aiResult.daysActive = daysActive;

    try {
      await pool.query(
        `INSERT INTO api_cache (cache_key, data, ttl_seconds) VALUES ($1, $2, $3) ON CONFLICT (cache_key) DO UPDATE SET data = $2, created_at = NOW(), ttl_seconds = $3`,
        [cacheKey, JSON.stringify(aiResult), 604800]
      );
    } catch (e) { console.error('AI deep analysis cache save error:', e); }

    res.json(aiResult);
  } catch (e) {
    console.error('AI deep analysis error:', e.status || '', e.message || e);
    res.status(500).json({ error: 'AI deep analysis failed', detail: e.message || 'Unknown error' });
  }
});

// ============ AI Compare Clans (MUST be before the PUBG API catch-all proxy) ============
app.get('/api/ai-compare-clans', async (req, res) => {
  try {
    const { tag1, tag2, stats: statsParam } = req.query;
    let payload;
    try { payload = JSON.parse(decodeURIComponent(statsParam || '{}')); } catch(e) { payload = null; }
    if (!tag1 || !tag2 || !payload || !payload.c1 || !payload.c2) return res.status(400).json({ error: 'Missing clans or stats' });

    const [a, b] = [tag1.toUpperCase(), tag2.toUpperCase()].sort();
    const cacheKey = `ai-compare-clans:${a}:${b}`;

    if (pool) {
      try {
        const cached = await pool.query(
          `SELECT data FROM api_cache WHERE cache_key = $1 AND created_at + (ttl_seconds || ' seconds')::interval > NOW()`,
          [cacheKey]
        );
        if (cached.rows.length > 0) {
          return res.json(cached.rows[0].data);
        }
      } catch (e) { console.error('AI compare clans cache check error:', e); }
    }

    if (!process.env.ANTHROPIC_API_KEY) {
      return res.status(503).json({ error: 'AI analysis not available' });
    }

    let AnthropicSDK;
    try {
      AnthropicSDK = await import('@anthropic-ai/sdk');
    } catch (e) {
      console.error('Failed to import Anthropic SDK:', e);
      return res.status(503).json({ error: 'AI service unavailable' });
    }
    const Anthropic = AnthropicSDK.default || AnthropicSDK.Anthropic;
    const client = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });

    const systemPrompt = `Eres V4NZ AI, el analista experto de clanes PUBG consola (PSN/Xbox) de v4nz.com. Comparas DOS clanes de forma técnica, justa y con criterio competitivo.

═══ BENCHMARKS CLANES CONSOLA (Temporada 40+) ═══
K/D medio clan: Elite 2.0+ | Bueno 1.5-2.0 | Normal 1.0-1.5 | Bajo <1.0
Win Rate clan: Elite 10%+ | Bueno 6-10% | Normal 3-6% | Bajo <3%
ADR medio clan: Elite 200+ | Bueno 150-200 | Normal 100-150 | Bajo <100
Actividad (% miembros con rounds>0): Sano 70%+ | Medio 40-70% | Fantasma <40%

═══ DIMENSIONES DE ANÁLISIS DE CLAN ═══
1. POTENCIA — kills totales, wins totales (volumen bruto del clan).
2. CALIDAD — K/D medio + ADR + Win Rate (nivel de skill individual medio).
3. PROFUNDIDAD — kills/miembro + wins/miembro (qué pasa si normalizas por tamaño).
4. ACTIVIDAD — % activos sobre total (salud del clan, fantasmas vs activos).
5. TAMAÑO — miembros totales y nivel del clan.

═══ REGLAS ESTRICTAS ═══
- Un clan grande con K/D bajo NO es mejor que uno pequeño con K/D alto — explícalo.
- Si un clan tiene muchísimos más miembros (>2x) pero menos kills/miembro, menciónalo: es un clan inflado.
- Si un clan tiene <40% de activos, es un clan fantasma aunque tenga buenos números medios.
- El veredicto debe considerar CALIDAD sobre VOLUMEN cuando los tamaños son muy distintos.
- Sé justo y técnico, sin insultos. Tono de analista pro.
- Responde SOLO con JSON válido, sin markdown.`;

    const c1 = payload.c1, c2 = payload.c2;
    const userPrompt = `Compara estos dos clanes de PUBG consola:

═══ CLAN 1: [${tag1}] ${payload.name1 || tag1} ═══
• Miembros totales: ${c1.members} | Activos: ${c1.active} (${c1.members ? Math.round(c1.active/c1.members*100) : 0}%)
• Nivel clan: ${c1.level}
• Total Kills: ${c1.totalKills} | Total Wins: ${c1.totalWins}
• K/D medio: ${c1.avgKD} | ADR medio: ${c1.avgDamage}
• Win Rate: ${c1.winRate}% | Partidas totales: ${c1.totalRounds}
• Kills/miembro activo: ${c1.killsPerMember} | Wins/miembro activo: ${c1.winsPerMember}

═══ CLAN 2: [${tag2}] ${payload.name2 || tag2} ═══
• Miembros totales: ${c2.members} | Activos: ${c2.active} (${c2.members ? Math.round(c2.active/c2.members*100) : 0}%)
• Nivel clan: ${c2.level}
• Total Kills: ${c2.totalKills} | Total Wins: ${c2.totalWins}
• K/D medio: ${c2.avgKD} | ADR medio: ${c2.avgDamage}
• Win Rate: ${c2.winRate}% | Partidas totales: ${c2.totalRounds}
• Kills/miembro activo: ${c2.killsPerMember} | Wins/miembro activo: ${c2.winsPerMember}

Genera el análisis JSON:
{
  "winner": "${tag1}" | "${tag2}" | "EMPATE",
  "winnerReason": "1 frase explicando por qué gana considerando calidad vs volumen",
  "dimensions": {
    "potencia": {"winner":"${tag1}"|"${tag2}"|"EMPATE","note":"breve nota sobre kills+wins totales"},
    "calidad": {"winner":"${tag1}"|"${tag2}"|"EMPATE","note":"breve nota sobre K/D+ADR+WR medios"},
    "profundidad": {"winner":"${tag1}"|"${tag2}"|"EMPATE","note":"breve nota sobre kills/miembro"},
    "actividad": {"winner":"${tag1}"|"${tag2}"|"EMPATE","note":"breve nota sobre % activos"}
  },
  "identityC1": "2-4 palabras que describan la identidad del clan 1 (ej: Elite compacto, Mastodonte activo, Fantasma inflado, Cantera en alza)",
  "identityC2": "2-4 palabras que describan la identidad del clan 2",
  "sizeWarning": "si un clan tiene >2x miembros que el otro, comentarlo aquí. Si no, null",
  "verdict": "3-4 frases de análisis comparativo final de los dos clanes",
  "tipLoser": "1 consejo estratégico para el clan perdedor (o el más flojo si empate)"
}`;

    let response, lastErr;
    for (let attempt = 0; attempt < 2; attempt++) {
      try {
        response = await client.messages.create({
          model: 'claude-sonnet-4-6',
          max_tokens: 1500,
          system: systemPrompt,
          messages: [{ role: 'user', content: userPrompt }]
        });
        break;
      } catch (apiErr) {
        lastErr = apiErr;
        console.error(`AI compare clans API attempt ${attempt + 1} failed:`, apiErr.status || apiErr.message);
        if (attempt === 0 && (apiErr.status === 529 || apiErr.status === 500 || apiErr.status === 502 || apiErr.status === 503)) {
          await new Promise(r => setTimeout(r, 500));  // rpm100-throttling-relax-v2: 2000→500ms (export workflows)
          continue;
        }
        throw apiErr;
      }
    }
    if (!response) throw lastErr || new Error('AI API failed after retries');

    const text = response.content[0]?.text || '';
    let aiResult;
    try {
      const jsonMatch = text.match(/\{[\s\S]*\}/);
      aiResult = JSON.parse(jsonMatch ? jsonMatch[0] : text);
    } catch (e) {
      console.error('AI compare clans parse error, raw text:', text.substring(0, 500));
      return res.status(500).json({ error: 'Failed to parse AI response' });
    }

    if (!aiResult.winner || !aiResult.verdict || !aiResult.dimensions) {
      console.error('AI compare clans incomplete response, keys:', Object.keys(aiResult));
      return res.status(500).json({ error: 'Incomplete AI response' });
    }

    aiResult.generatedAt = new Date().toISOString();
    aiResult.tag1 = tag1;
    aiResult.tag2 = tag2;

    if (pool) {
      try {
        await pool.query(
          `INSERT INTO api_cache (cache_key, data, ttl_seconds) VALUES ($1, $2, $3) ON CONFLICT (cache_key) DO UPDATE SET data = $2, created_at = NOW(), ttl_seconds = $3`,
          [cacheKey, JSON.stringify(aiResult), 604800]
        );
      } catch (e) { console.error('AI compare clans cache save error:', e); }
    }

    res.json(aiResult);

  } catch (e) {
    console.error('AI compare clans error:', e.status || e.code || '', e.message || e);
    res.status(500).json({ error: 'AI compare clans failed', detail: e.message || 'Unknown error' });
  }
});

// ============ Player clan lookup ============
// player-clan-lookup-v1 — devuelve el clan_tag y name del jugador buscando en clan_members.
// Usado por el panel homeV2Logged "Mi Clan" para mostrar el clan REAL del user logueado
// (antes leía pubg_clan_favorites[0] que era solo el primer clan favorito, no el del jugador).
app.get('/api/player-clan', async (req, res) => {
  try {
    const name = (req.query.name || '').toString().trim();
    if (!name) return res.status(400).json({ error: 'Missing name' });
    if (!pool) return res.status(503).json({ error: 'DB no disponible' });
    const result = await pool.query(
      `SELECT cm.clan_tag, c.name AS clan_name
       FROM clan_members cm
       LEFT JOIN clans c ON c.tag = cm.clan_tag
       WHERE LOWER(cm.player_name) = LOWER($1) AND cm.active = true
       ORDER BY cm.kills DESC NULLS LAST
       LIMIT 1`,
      [name]
    );
    if (!result.rows.length) return res.json({ tag: null });
    res.json({ tag: result.rows[0].clan_tag, name: result.rows[0].clan_name || result.rows[0].clan_tag });
  } catch (e) {
    console.error('player-clan error:', e.message || e);
    res.status(500).json({ error: 'query failed' });
  }
});

// ============ AI Clan DNA (análisis IA de un clan individual) ============
// ai-clan-dna-v1 — sustituye el 404 del botón "ANALIZAR CLAN CON IA".
// Patrón identico a /api/ai-compare-clans: cache api_cache 7d + Claude API con
// retry en 5xx transitorios. Se alimenta de clans + clan_members (stats agregadas).
app.get('/api/ai-clan-dna', async (req, res) => {
  try {
    const rawTag = (req.query.tag || '').toString().trim();
    if (!rawTag) return res.status(400).json({ error: 'Falta tag del clan' });
    const tag = rawTag.toUpperCase();
    const cacheKey = `ai-clan-dna:${tag}`;

    if (pool) {
      try {
        const cached = await pool.query(
          `SELECT data FROM api_cache WHERE cache_key = $1 AND created_at + (ttl_seconds || ' seconds')::interval > NOW()`,
          [cacheKey]
        );
        if (cached.rows.length > 0) return res.json(cached.rows[0].data);
      } catch (e) { console.error('AI clan DNA cache check error:', e); }
    }

    if (!pool) return res.status(503).json({ error: 'DB no disponible' });

    // 1. Datos del clan
    const clanRow = await pool.query(
      'SELECT tag, name, level, platform, active_members, total_kills, total_wins, avg_kd FROM clans WHERE tag = $1',
      [tag]
    );
    if (!clanRow.rows.length) return res.status(404).json({ error: 'Clan no registrado en V4NZ. Búscalo primero desde la pestaña Clanes.' });
    const clan = clanRow.rows[0];

    // 2. Miembros + agregados
    const membersRow = await pool.query(
      'SELECT player_name, kills, wins, kd, damage, rounds, active FROM clan_members WHERE clan_tag = $1 ORDER BY kills DESC NULLS LAST',
      [tag]
    );
    const members = membersRow.rows || [];
    const total = members.length;
    const activos = members.filter(m => m.active).length;
    const activePct = total ? Math.round(activos / total * 100) : 0;
    const withRounds = members.filter(m => (m.rounds || 0) > 0);
    const avgKD = withRounds.length ? (withRounds.reduce((s, m) => s + (parseFloat(m.kd) || 0), 0) / withRounds.length) : 0;
    const avgADR = withRounds.length ? (withRounds.reduce((s, m) => s + (parseFloat(m.damage) || 0), 0) / withRounds.length) : 0;
    const totalKills = members.reduce((s, m) => s + (m.kills || 0), 0);
    const totalWins = members.reduce((s, m) => s + (m.wins || 0), 0);
    const totalRounds = members.reduce((s, m) => s + (m.rounds || 0), 0);
    const winRate = totalRounds ? (totalWins / totalRounds * 100) : 0;
    const kdVariance = withRounds.length > 1
      ? (withRounds.reduce((s, m) => s + Math.pow((parseFloat(m.kd) || 0) - avgKD, 2), 0) / withRounds.length)
      : 0;
    const kdStdDev = Math.sqrt(kdVariance);
    const topMembers = members.slice(0, 5).map(m => `${m.player_name} (K/D ${Number(m.kd || 0).toFixed(2)}, ${m.kills} kills, ${m.wins} wins)`);
    const mvp = members[0]?.player_name || null;

    if (!process.env.ANTHROPIC_API_KEY) return res.status(503).json({ error: 'AI no disponible' });

    let AnthropicSDK;
    try { AnthropicSDK = await import('@anthropic-ai/sdk'); }
    catch (e) { console.error('Anthropic SDK import failed:', e); return res.status(503).json({ error: 'AI SDK no disponible' }); }
    const Anthropic = AnthropicSDK.default || AnthropicSDK.Anthropic;
    const client = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });

    const systemPrompt = `Eres V4NZ AI, el analista experto de clanes PUBG consola (PSN/Xbox) de v4nz.com. Analizas el ADN colectivo de un clan: su arquetipo, sus fortalezas, sus debilidades y qué le distingue. Tono técnico, justo, sin insultos.

═══ BENCHMARKS CLANES CONSOLA (Temporada 40+) ═══
K/D medio clan: Elite 2.0+ | Bueno 1.5-2.0 | Normal 1.0-1.5 | Bajo <1.0
Win Rate clan: Elite 10%+ | Bueno 6-10% | Normal 3-6% | Bajo <3%
ADR medio clan: Elite 200+ | Bueno 150-200 | Normal 100-150 | Bajo <100
Actividad (% miembros con rounds>0): Sano 70%+ | Medio 40-70% | Fantasma <40%
Desviación K/D alta (>0.6) = clan dispar, baja (<0.3) = clan homogéneo

═══ 5 DIMENSIONES A PUNTUAR (0-100) ═══
1. COMPETITIVIDAD — skill medio: K/D + ADR + Win Rate combinados.
2. COHESIÓN — homogeneidad: desviación K/D baja + balance activos/fantasmas.
3. AGRESIVIDAD — kills/miembro alto + ADR alto (más ruido, más tiros).
4. CONSISTENCIA — Win Rate + rounds jugados (partidas consistentes, no solo carries puntuales).
5. ACTIVIDAD — % activos sobre total. Fantasmas bajan esta puntuación.

═══ ARQUETIPOS SUGERIDOS ═══
- ELITE QUIRÚRGICO · rojo #ff3355 (pocos miembros, todos top)
- MASTODONTE ACTIVO · naranja #ff6b00 (muchos miembros, volumen bruto alto)
- AGRESIVO HIPER · magenta #ff2d92 (kills bestiales, win rate normal)
- CANTERA EN ALZA · verde #00ff88 (nivel medio, muchos activos con rounds)
- FANTASMA INFLADO · gris #6b7280 (>60% inactivos)
- METÓDICO FRÍO · cyan #00f0ff (win rate alto, consistente, no explosivo)
- CLAN DISPAR · amarillo #f5c842 (3 cracks + 50 pasivos, desviación K/D alta)

═══ REGLAS ESTRICTAS ═══
- Si <40% activos, debe aparecer como debilidad aunque las medias sean buenas.
- Strengths y weaknesses: 3-4 bullets cada uno, concretos, con números.
- MVP: el jugador que mejor define el arquetipo (no siempre el de más kills).
- Tip: 1 frase accionable para mejorar la debilidad más urgente del clan.
- Responde SOLO con JSON válido, sin markdown ni explicaciones fuera del JSON.`;

    const userPrompt = `Analiza este clan PUBG consola:

═══ CLAN [${tag}] ${clan.name || tag} ═══
• Nivel del clan: ${clan.level || '?'}
• Plataforma: ${clan.platform || 'console'}
• Miembros totales: ${total} | Activos (rounds>0): ${activos} (${activePct}%)
• Kills totales: ${totalKills} | Wins totales: ${totalWins} | Rounds totales: ${totalRounds}
• K/D medio (solo activos): ${avgKD.toFixed(2)}
• ADR medio (solo activos): ${Math.round(avgADR)}
• Win Rate: ${winRate.toFixed(2)}%
• Kills/miembro activo: ${activos ? (totalKills / activos).toFixed(1) : 0}
• Desviación K/D entre activos: ${kdStdDev.toFixed(2)} (${kdStdDev > 0.6 ? 'DISPAR' : kdStdDev < 0.3 ? 'HOMOGÉNEO' : 'normal'})

═══ TOP 5 POR KILLS ═══
${topMembers.map((l, i) => `${i + 1}. ${l}`).join('\n') || '(sin datos)'}

Devuelve JSON exactamente así (nada fuera del objeto):
{
  "archetype": "NOMBRE DEL ARQUETIPO EN MAYÚSCULAS",
  "archetypeColor": "#hex",
  "description": "2-3 frases explicando qué tipo de clan es y qué lo define",
  "scores": {
    "competitividad": 0-100,
    "cohesion": 0-100,
    "agresividad": 0-100,
    "consistencia": 0-100,
    "actividad": ${activePct}
  },
  "strengths": ["3-4 fortalezas concretas con números"],
  "weaknesses": ["3-4 debilidades concretas con números"],
  "mvp": "nombre del jugador MVP",
  "tip": "1 frase accionable para mejorar la debilidad principal",
  "tag": "${tag}"
}`;

    let response, lastErr;
    for (let attempt = 0; attempt < 2; attempt++) {
      try {
        response = await client.messages.create({
          model: 'claude-sonnet-4-6',
          max_tokens: 1500,
          system: systemPrompt,
          messages: [{ role: 'user', content: userPrompt }]
        });
        break;
      } catch (apiErr) {
        lastErr = apiErr;
        console.error(`AI clan DNA API attempt ${attempt + 1} failed:`, apiErr.status || apiErr.message);
        if (attempt === 0 && (apiErr.status === 529 || apiErr.status === 500 || apiErr.status === 502 || apiErr.status === 503)) {
          await new Promise(r => setTimeout(r, 500));  // rpm100-throttling-relax-v2: 2000→500ms (export workflows)
          continue;
        }
        throw apiErr;
      }
    }
    if (!response) throw lastErr || new Error('AI API failed after retries');

    const text = response.content[0]?.text || '';
    let aiResult;
    try {
      const jsonMatch = text.match(/\{[\s\S]*\}/);
      aiResult = JSON.parse(jsonMatch ? jsonMatch[0] : text);
    } catch (e) {
      console.error('AI clan DNA parse error, raw text:', text.substring(0, 500));
      return res.status(500).json({ error: 'Failed to parse AI response' });
    }

    if (!aiResult.archetype || !aiResult.scores || !aiResult.description) {
      console.error('AI clan DNA incomplete response, keys:', Object.keys(aiResult));
      return res.status(500).json({ error: 'Incomplete AI response' });
    }

    aiResult.tag = tag;
    aiResult.generatedAt = new Date().toISOString();
    if (mvp && !aiResult.mvp) aiResult.mvp = mvp;

    if (pool) {
      try {
        await pool.query(
          `INSERT INTO api_cache (cache_key, data, ttl_seconds) VALUES ($1, $2, $3) ON CONFLICT (cache_key) DO UPDATE SET data = $2, created_at = NOW(), ttl_seconds = $3`,
          [cacheKey, JSON.stringify(aiResult), 604800]
        );
      } catch (e) { console.error('AI clan DNA cache save error:', e); }
    }

    res.json(aiResult);

  } catch (e) {
    console.error('AI clan DNA error:', e.status || e.code || '', e.message || e);
    res.status(500).json({ error: 'AI clan DNA failed', detail: e.message || 'Unknown error' });
  }
});

// ============ Telemetry Audit (MUST be before the PUBG API catch-all proxy) ============

// Specific rate limit for telemetry: 3 requests per minute per IP
const telemetryRateLimitMap = new Map();
function telemetryRateLimit(req, res, next) {
  const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip;
  const now = Date.now();
  let entry = telemetryRateLimitMap.get(ip);
  if (!entry || now - entry.start > 60000) {
    entry = { start: now, count: 1 };
    telemetryRateLimitMap.set(ip, entry);
  } else {
    entry.count++;
  }
  if (entry.count > 3) {
    return res.status(429).json({ error: 'Máximo 3 auditorías por minuto. Espera un momento.' });
  }
  next();
}
setInterval(() => {
  const now = Date.now();
  for (const [ip, entry] of telemetryRateLimitMap) {
    if (now - entry.start > 120000) telemetryRateLimitMap.delete(ip);
  }
}, 300000);

app.get('/api/telemetry-audit', telemetryRateLimit, async (req, res) => {
  try {
    const { matchId, playerName, platform } = req.query;
    if (!matchId || !playerName) {
      return res.status(400).json({ error: 'Missing matchId or playerName' });
    }
    const shard = platform || 'psn';

    // 1. Check cache first (telemetry audits cached 24h)
    const cacheKey = `telemetry-audit:${matchId}:${playerName.toLowerCase()}:${shard}`;
    if (pool) {
      try {
        const cached = await pool.query(
          `SELECT data FROM api_cache WHERE cache_key = $1 AND created_at + (ttl_seconds || ' seconds')::interval > NOW()`,
          [cacheKey]
        );
        if (cached.rows.length > 0) {
          return res.json(cached.rows[0].data);
        }
      } catch (e) { console.error('Telemetry cache check error:', e); }
    }

    // 2. Fetch match data from PUBG API
    if (!SERVER_API_KEY) {
      return res.status(503).json({ error: 'PUBG API key not configured' });
    }

    const matchUrl = `https://api.pubg.com/shards/${shard}/matches/${matchId}`;
    const matchRes = await fetchWithTimeout(fetch, matchUrl, {
      headers: { 'Authorization': 'Bearer ' + SERVER_API_KEY, 'Accept': 'application/vnd.api+json' }
    }, 15000);

    if (!matchRes.ok) {
      return res.status(matchRes.status).json({ error: `Match not found (${matchRes.status})` });
    }

    const matchData = await matchRes.json();

    // Extract match info
    const matchAttrs = matchData.data?.attributes || {};
    const mapName = matchAttrs.mapName || 'Unknown';
    const gameMode = matchAttrs.gameMode || 'Unknown';
    const duration = matchAttrs.duration || 0;
    const isCustomMatch = matchAttrs.isCustomMatch || false;

    // Find player's placement from rosters
    let playerPlacement = null;
    let playerStats = null;
    const included = matchData.included || [];
    for (const item of included) {
      if (item.type === 'participant' && item.attributes?.stats?.name?.toLowerCase() === playerName.toLowerCase()) {
        playerStats = item.attributes.stats;
        playerPlacement = playerStats.winPlace;
        break;
      }
    }

    // 3. Find telemetry URL
    let telemetryUrl = null;
    for (const item of included) {
      if (item.type === 'asset' && item.attributes?.name === 'telemetry') {
        telemetryUrl = item.attributes.URL;
        break;
      }
    }

    if (!telemetryUrl) {
      return res.status(404).json({ error: 'Telemetry data not found for this match' });
    }

    // 4. Download telemetry (CDN, no API key needed)
    const telRes = await fetchWithTimeout(fetch, telemetryUrl, {}, 30000);
    if (!telRes.ok) {
      return res.status(502).json({ error: `Failed to download telemetry (${telRes.status})` });
    }
    const telemetryData = await telRes.json();

    // 5. Filter events for this player
    const pName = playerName.toLowerCase();
    const relevantTypes = new Set([
      'LogWeaponFireCount', 'LogPlayerAttack', 'LogPlayerTakeDamage',
      'LogPlayerKillV2', 'LogItemPickup', 'LogItemEquip', 'LogItemUse',
      'LogPlayerUseThrowable', 'LogPlayerPosition', 'LogPhaseChange',
      'LogVehicleRide', 'LogVehicleLeave', 'LogPlayerRevive',
      'LogGameStatePeriodic'
    ]);

    let positionCount = 0;
    let periodicCount = 0;
    const filteredEvents = [];

    for (const event of telemetryData) {
      const type = event._T;
      if (!relevantTypes.has(type)) continue;

      // LogPhaseChange: keep all (few events)
      if (type === 'LogPhaseChange') {
        filteredEvents.push(event);
        continue;
      }

      // LogGameStatePeriodic: keep every 3rd
      if (type === 'LogGameStatePeriodic') {
        periodicCount++;
        if (periodicCount % 3 === 0) {
          // Slim down: only keep numAlivePlayers and gameState
          filteredEvents.push({
            _T: type, _D: event._D,
            gameState: event.gameState ? {
              numAlivePlayers: event.gameState.numAlivePlayers,
              safetyZonePosition: event.gameState.safetyZonePosition,
              safetyZoneRadius: event.gameState.safetyZoneRadius,
              poisonGasWarningPosition: event.gameState.poisonGasWarningPosition,
              poisonGasWarningRadius: event.gameState.poisonGasWarningRadius
            } : undefined
          });
        }
        continue;
      }

      // LogPlayerPosition: only for target player, every 5th
      if (type === 'LogPlayerPosition') {
        if (event.character?.name?.toLowerCase() === pName) {
          positionCount++;
          if (positionCount % 5 === 0) {
            filteredEvents.push({
              _T: type, _D: event._D,
              character: { name: event.character.name, location: event.character.location },
              elapsedTime: event.elapsedTime
            });
          }
        }
        continue;
      }

      // All other events: check if player is involved
      const charName = (event.character?.name || '').toLowerCase();
      const attackerName = (event.attacker?.name || '').toLowerCase();
      const victimName = (event.victim?.name || '').toLowerCase();
      const killerName = (event.killer?.name || '').toLowerCase();
      const reviverName = (event.reviver?.name || '').toLowerCase();

      if (charName === pName || attackerName === pName || victimName === pName ||
          killerName === pName || reviverName === pName) {
        filteredEvents.push(event);
      }
    }

    // 6. Size check: if filtered events JSON > 50KB, reduce position/periodic further
    let eventsJson = JSON.stringify(filteredEvents);
    if (eventsJson.length > 50000) {
      // Re-filter with sparser sampling
      positionCount = 0;
      periodicCount = 0;
      const sparseEvents = [];
      for (const event of filteredEvents) {
        if (event._T === 'LogPlayerPosition') {
          positionCount++;
          if (positionCount % 2 === 0) sparseEvents.push(event); // keep every 2nd of already filtered (= every 10th original)
        } else if (event._T === 'LogGameStatePeriodic') {
          periodicCount++;
          if (periodicCount % 2 === 0) sparseEvents.push(event); // keep every 2nd (= every 6th original)
        } else {
          sparseEvents.push(event);
        }
      }
      eventsJson = JSON.stringify(sparseEvents);
    }

    // 7. Send to Claude for analysis
    if (!process.env.ANTHROPIC_API_KEY) {
      return res.status(503).json({ error: 'AI analysis not available' });
    }

    let AnthropicSDK;
    try {
      AnthropicSDK = await import('@anthropic-ai/sdk');
    } catch (e) {
      console.error('Failed to import Anthropic SDK:', e);
      return res.status(503).json({ error: 'AI service unavailable' });
    }
    const Anthropic = AnthropicSDK.default || AnthropicSDK.Anthropic;
    const client = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });

    const systemPrompt = `Eres V4NZ Auditor, un analista experto de partidas de PUBG para consola.
Evalúas la telemetría de UNA partida individual y das un informe detallado y constructivo.

SISTEMA DE SCORING (0-10):
- Combate (25%): Trade ratio, kills por fase, calidad de kills (humanos vs bots)
- Supervivencia (20%): Gestión del círculo, tiempo vivo, muertes evitables
- Rotación (15%): Posición vs círculo, timing de movimientos, daño de zona recibido
- Decisiones (15%): Selección de arma por distancia, cuándo pelear vs escapar
- Precisión (15%): Hit rate por arma, headshot rate
- Inventario (10%): Uso de consumibles, granadas, boost en end game

ESCALA:
S (9-10) = Élite | A (7.5-8.9) = Excelente | B (6-7.4) = Bueno
C (4.5-5.9) = Normal | D (3-4.4) = Mejorable | F (0-2.9) = Crítico

REGLAS:
- Tono constructivo, habla al jugador con "tú"
- Sé específico: menciona armas concretas, momentos concretos, distancias
- Si hay muchos bots en las kills, menciónalo
- Responde SOLO con JSON válido, sin markdown ni explicaciones`;

    const userPrompt = `Audita esta partida de PUBG:

MATCH INFO:
- Mapa: ${mapName}
- Modo: ${gameMode}
- Duración: ${Math.round(duration / 60)} min
- Jugador: ${playerName} (${shard})
- Posición final: #${playerPlacement || '?'}
${playerStats ? `- Kills: ${playerStats.kills} | Damage: ${Math.round(playerStats.damageDealt)} | Headshots: ${playerStats.headshotKills}` : ''}
${playerStats ? `- Walk distance: ${Math.round(playerStats.walkDistance)}m | Ride distance: ${Math.round(playerStats.rideDistance)}m` : ''}
${playerStats ? `- Heals: ${playerStats.heals} | Boosts: ${playerStats.boosts} | Revives: ${playerStats.revives}` : ''}
${isCustomMatch ? '- ⚠️ Partida personalizada' : ''}

TELEMETRY EVENTS (${filteredEvents.length} eventos filtrados del jugador):
${eventsJson}

Genera el análisis JSON con este formato exacto:
{
  "score_total": 7.2,
  "grade": "B",
  "grade_label": "Bueno",
  "scores": {
    "combate": { "score": 7.5, "detalle": "breve explicación" },
    "supervivencia": { "score": 8.0, "detalle": "breve explicación" },
    "rotacion": { "score": 6.5, "detalle": "breve explicación" },
    "decisiones": { "score": 7.0, "detalle": "breve explicación" },
    "precision": { "score": 6.8, "detalle": "breve explicación" },
    "inventario": { "score": 7.0, "detalle": "breve explicación" }
  },
  "lo_que_hiciste_bien": ["punto 1 específico", "punto 2 específico"],
  "lo_que_puedes_mejorar": ["punto 1 específico", "punto 2 específico"],
  "momento_clave": "descripción del momento más importante de la partida",
  "consejo": "1 consejo accionable basado en el error más frecuente",
  "resumen": "2-3 frases resumen de la partida"
}`;

    const response = await client.messages.create({
      model: 'claude-sonnet-4-6',
      max_tokens: 1500,
      system: systemPrompt,
      messages: [{ role: 'user', content: userPrompt }]
    });

    const text = response.content[0]?.text || '';
    let auditResult;
    try {
      const jsonMatch = text.match(/\{[\s\S]*\}/);
      auditResult = JSON.parse(jsonMatch ? jsonMatch[0] : text);
    } catch (e) {
      console.error('Telemetry audit parse error:', text.substring(0, 500));
      return res.status(500).json({ error: 'Failed to parse AI audit response' });
    }

    // Validate required fields
    if (!auditResult.score_total || !auditResult.grade || !auditResult.scores) {
      return res.status(500).json({ error: 'Incomplete AI audit response' });
    }

    auditResult.matchId = matchId;
    auditResult.playerName = playerName;
    auditResult.platform = shard;
    auditResult.mapName = mapName;
    auditResult.gameMode = gameMode;
    auditResult.placement = playerPlacement;
    auditResult.generatedAt = new Date().toISOString();
    auditResult.eventsProcessed = filteredEvents.length;

    // 8. Cache result (24 hours)
    if (pool) {
      try {
        await pool.query(
          `INSERT INTO api_cache (cache_key, data, ttl_seconds) VALUES ($1, $2, $3) ON CONFLICT (cache_key) DO UPDATE SET data = $2, created_at = NOW(), ttl_seconds = $3`,
          [cacheKey, JSON.stringify(auditResult), 86400]
        );
      } catch (e) { console.error('Telemetry audit cache save error:', e); }
    }

    res.json(auditResult);

  } catch (e) {
    console.error('Telemetry audit error:', e);
    if (e.name === 'AbortError') {
      return res.status(504).json({ error: 'Timeout downloading telemetry. Try again.' });
    }
    res.status(500).json({ error: 'Telemetry audit failed' });
  }
});

// ═══ MATCH INSIGHTS (match-insights-v2) — Radiografia del match ═══
// I-0a: infraestructura. Tabla + endpoint placeholder de los 14 slots.
// I-1 (INSIGHTS_V=2): TTFK + HS by distance reales (primeras 2 tarjetas vivas).
//   Resto de tarjetas siguen marcadas como _pending en el JSON para que el
//   frontend las muestre con skeleton "Próximamente" hasta sesiones I-2..I-6.
const INSIGHTS_VERSION = 2;
const INSIGHTS_PLANNED_KEYS = [
  'ttfk','hs_by_distance','engagement_winrate','blue_zone_damage',
  'healing_efficiency','grenade_effectiveness','reload_interruptions',
  'knocked_survival','vehicle_time','blue_chip_ops','redeploy_impact',
  'landing_spot','final_circle_timing','audit_summary'
];

// ─── Helpers compartidos ────────────────────────────────────────────────
// Bot PUBG: accountId vacío o con prefijo "ai." (robusto — visto en ambos formatos).
function _isBotEntity(e) {
  if (!e) return false;
  const id = e.accountId;
  if (id === '' || id == null) return true;
  if (typeof id === 'string' && id.startsWith('ai.')) return true;
  return false;
}

// Distancia 3D en metros. PUBG guarda locations en cm — dividir /100.
// Fallback al campo ev.distance directo si está presente (también en cm).
function _killDistanceMeters(ev) {
  try {
    const a = ev?.killer?.location || ev?.finisher?.location;
    const b = ev?.victim?.location;
    if (a && b && typeof a.x === 'number' && typeof b.x === 'number') {
      const dx = a.x - b.x, dy = a.y - b.y, dz = (a.z || 0) - (b.z || 0);
      return Math.sqrt(dx*dx + dy*dy + dz*dz) / 100;
    }
  } catch(_) {}
  if (typeof ev?.distance === 'number' && ev.distance > 0) return ev.distance / 100;
  return null;
}

// Fetch match JSON con cache 24h (match JSON + telemetry URL). Reutiliza
// la misma cache_key que bot-index para no duplicar: `match_${shard}_${id}`.
async function _getMatchJsonCached(shard, matchId) {
  if (!pool) return null;
  const mKey = `match_${shard}_${matchId}`;
  try {
    const cached = await pool.query(
      "SELECT response_data FROM api_cache WHERE cache_key = $1 AND created_at > NOW() - INTERVAL '24 hours'",
      [mKey]
    );
    if (cached.rows.length) {
      try { return JSON.parse(cached.rows[0].response_data); } catch(_) {}
    }
  } catch(_) {}
  if (!SERVER_API_KEY) return null;
  try {
    const mRes = await fetchWithTimeout(fetch, `https://api.pubg.com/shards/${shard}/matches/${matchId}`, {
      headers: { 'Authorization': 'Bearer ' + SERVER_API_KEY, 'Accept': 'application/vnd.api+json' }
    }, 12000);
    if (!mRes.ok) return null;
    const data = await mRes.json();
    pool.query(
      'INSERT INTO api_cache (cache_key, response_data, status_code, created_at) VALUES ($1, $2, 200, NOW()) ON CONFLICT (cache_key) DO UPDATE SET response_data = $2, created_at = NOW()',
      [mKey, JSON.stringify(data)]
    ).catch(() => {});
    return data;
  } catch(_) { return null; }
}

// Fetch telemetría con cache 30 días (key: `telemetry_${matchId}`).
async function _getTelemetryCached(matchId, telemetryUrl) {
  if (!pool) {
    if (!telemetryUrl) return null;
    try {
      const tRes = await fetchWithTimeout(fetch, telemetryUrl, {}, 30000);
      return tRes.ok ? await tRes.json() : null;
    } catch(_) { return null; }
  }
  const tKey = `telemetry_${matchId}`;
  try {
    const cached = await pool.query(
      "SELECT response_data FROM api_cache WHERE cache_key = $1 AND created_at > NOW() - INTERVAL '30 days'",
      [tKey]
    );
    if (cached.rows.length) {
      try { return JSON.parse(cached.rows[0].response_data); } catch(_) {}
    }
  } catch(_) {}
  if (!telemetryUrl) return null;
  try {
    const tRes = await fetchWithTimeout(fetch, telemetryUrl, {}, 30000);
    if (!tRes.ok) return null;
    const data = await tRes.json();
    pool.query(
      'INSERT INTO api_cache (cache_key, response_data, status_code, created_at) VALUES ($1, $2, 200, NOW()) ON CONFLICT (cache_key) DO UPDATE SET response_data = $2, created_at = NOW()',
      [tKey, JSON.stringify(data)]
    ).catch(() => {});
    return data;
  } catch(_) { return null; }
}

// ─── Worker — calcula insights reales para (matchId, player, platform) ──
// No-throw: cualquier fallo deja status='error' en la tabla con error_msg.
// I-1 produce TTFK + hs_by_distance. Resto de keys se entregan con
// `_pending: true` para que el frontend renderice "Próximamente".
async function computeMatchInsights(matchId, player, platform) {
  if (!pool) return;
  const setErr = async (msg) => {
    try {
      await pool.query(
        `UPDATE match_insights SET status='error', error_msg=$4, computed_at=NOW()
         WHERE match_id=$1 AND player_name=$2 AND platform=$3`,
        [matchId, player, platform, String(msg).slice(0, 500)]
      );
    } catch(_) {}
  };
  try {
    // Marcar como "computing" (en marcha). El endpoint ya dejó 'pending'.
    await pool.query(
      `UPDATE match_insights SET status='computing' WHERE match_id=$1 AND player_name=$2 AND platform=$3 AND status IN ('pending','error')`,
      [matchId, player, platform]
    );

    // 1. Match JSON (cache 24h) — saca telemetry URL + stats del participante.
    const shard = platform === 'xbox' ? 'xbox' : 'psn';
    const matchData = await _getMatchJsonCached(shard, matchId);
    if (!matchData) return setErr('match_fetch_failed');

    const included = matchData.included || [];
    const attrs = matchData.data?.attributes || {};
    const matchDuration = attrs.duration || 0;

    // Buscar participante por nombre (case-insensitive) para accountId + stats
    let participantAccountId = null;
    let participantStats = null;
    const pLower = player.toLowerCase();
    for (const it of included) {
      if (it.type === 'participant' && it.attributes?.stats?.name?.toLowerCase() === pLower) {
        participantStats = it.attributes.stats;
        participantAccountId = participantStats.playerId || null;
        break;
      }
    }
    if (!participantStats) return setErr('participant_not_found');

    // 2. Telemetry URL desde los assets
    let telemetryUrl = null;
    for (const it of included) {
      if (it.type === 'asset' && it.attributes?.name === 'telemetry') {
        telemetryUrl = it.attributes.URL; break;
      }
    }
    if (!telemetryUrl) return setErr('telemetry_url_missing');

    // 3. Telemetría (cache 30d) — puede fallar con partidas >14 días (CDN purga)
    const telemetry = await _getTelemetryCached(matchId, telemetryUrl);
    if (!telemetry || !Array.isArray(telemetry)) return setErr('telemetry_fetch_failed');

    // 4. Calcular insights reales
    // matchStartedAt: desde LogMatchStart._D o fallback al createdAt del match
    let matchStartISO = null;
    for (const ev of telemetry) {
      if (ev._T === 'LogMatchStart') { matchStartISO = ev._D; break; }
    }
    const matchStartMs = matchStartISO ? new Date(matchStartISO).getTime() : (attrs.createdAt ? new Date(attrs.createdAt).getTime() : null);

    // Filtrar kills del jugador (LogPlayerKillV2 prioritario, fallback LogPlayerKill).
    // Match por accountId primero (más robusto frente a cambios de nombre),
    // fallback por nombre (case-insensitive).
    const myKills = [];
    for (const ev of telemetry) {
      if (ev._T !== 'LogPlayerKillV2' && ev._T !== 'LogPlayerKill') continue;
      const killer = ev.killer || ev.finisher;
      if (!killer) continue;
      const isMe = (participantAccountId && killer.accountId === participantAccountId) ||
                   (killer.name && killer.name.toLowerCase() === pLower);
      if (!isMe) continue;
      myKills.push(ev);
    }

    // ─── TTFK (Time To First Kill) ─────────────────────────────────────
    // Regla acordada: excluir kills de bots. Si todos son bots → n/d.
    const humanKills = myKills.filter(ev => !_isBotEntity(ev.victim));
    humanKills.sort((a,b) => new Date(a._D).getTime() - new Date(b._D).getTime());
    let ttfk = null;
    if (humanKills.length && matchStartMs) {
      const firstMs = new Date(humanKills[0]._D).getTime();
      const seconds = Math.max(0, Math.round((firstMs - matchStartMs) / 1000));
      // Benchmark: <90s excelente · 90-240s normal · >240s tardío
      let rating = 'tardio';
      if (seconds <= 90) rating = 'excelente';
      else if (seconds <= 240) rating = 'normal';
      ttfk = {
        value_seconds: seconds,
        first_victim: humanKills[0].victim?.name || null,
        first_weapon: humanKills[0].damageCauserName || null,
        rating,
        bots_excluded: myKills.length - humanKills.length,
        total_kills: myKills.length
      };
    } else if (myKills.length && humanKills.length === 0) {
      ttfk = { value_seconds: null, rating: 'solo_bots', total_kills: myKills.length, bots_excluded: myKills.length };
    } else {
      ttfk = { value_seconds: null, rating: 'sin_kills', total_kills: 0, bots_excluded: 0 };
    }

    // ─── HS by distance (3 buckets: 0-50, 50-150, 150+) ────────────────
    // Solo kills a jugadores reales. Headshot: damageReason === 'HeadShot'.
    const buckets = [
      { key: '0-50',    min: 0,   max: 50,    hits: 0, hs: 0 },
      { key: '50-150',  min: 50,  max: 150,   hits: 0, hs: 0 },
      { key: '150+',    min: 150, max: Infinity, hits: 0, hs: 0 }
    ];
    let outOfRange = 0;
    for (const ev of humanKills) {
      const d = _killDistanceMeters(ev);
      if (d == null) { outOfRange++; continue; }
      const isHS = ev.damageReason === 'HeadShot' || ev.isHeadShot === true;
      const b = buckets.find(bk => d >= bk.min && d < bk.max);
      if (!b) continue;
      b.hits++;
      if (isHS) b.hs++;
    }
    const hsByDistance = {
      buckets: buckets.map(b => ({
        range: b.key,
        min_m: b.min,
        max_m: b.max === Infinity ? null : b.max,
        sample_size: b.hits,
        hs_count: b.hs,
        hs_pct: b.hits > 0 ? Math.round((b.hs / b.hits) * 1000) / 10 : null
      })),
      total_hits: humanKills.length,
      out_of_range: outOfRange,
      bots_excluded: myKills.length - humanKills.length
    };

    // ─── Resto de tarjetas: _pending (I-2..I-6 las rellenarán) ─────────
    const pending = { _pending: true };
    const insights = {
      _version: INSIGHTS_VERSION,
      _meta: {
        match_id: matchId,
        player_name: player,
        platform,
        match_duration_s: matchDuration,
        map: attrs.mapName || null,
        game_mode: attrs.gameMode || null,
        computed_at: new Date().toISOString()
      },
      ttfk,
      hs_by_distance: hsByDistance,
      engagement_winrate: pending,
      blue_zone_damage: pending,
      healing_efficiency: pending,
      grenade_effectiveness: pending,
      reload_interruptions: pending,
      knocked_survival: pending,
      vehicle_time: pending,
      blue_chip_ops: pending,
      redeploy_impact: pending,
      landing_spot: pending,
      final_circle_timing: pending,
      audit_summary: pending
    };

    // 5. Persistir ready
    await pool.query(
      `UPDATE match_insights
         SET status='ready', insights=$4::jsonb, version=$5, computed_at=NOW(), error_msg=NULL
       WHERE match_id=$1 AND player_name=$2 AND platform=$3`,
      [matchId, player, platform, JSON.stringify(insights), INSIGHTS_VERSION]
    );
  } catch (e) {
    console.error('[match-insights] compute error:', e);
    await setErr(e.message || 'compute_failed');
  }
}

app.get('/api/match-insights/:matchId', async (req, res) => {
  try {
    const { matchId } = req.params;
    const player = String(req.query.player || '').trim();
    const platform = String(req.query.platform || 'psn').trim().toLowerCase();
    if (!matchId || !player) {
      return res.status(400).json({ error: 'Missing matchId or player' });
    }
    // Sin pool: devolver placeholder (dev local sin DB)
    if (!pool) {
      return res.json({
        status: 'ready', version: INSIGHTS_VERSION,
        insights: { _placeholder: true, message: 'DB no disponible en este entorno', planned: INSIGHTS_PLANNED_KEYS }
      });
    }
    // 1. Cache hit
    const found = await pool.query(
      `SELECT status, insights, error_msg, version, computed_at
       FROM match_insights WHERE match_id=$1 AND player_name=$2 AND platform=$3`,
      [matchId, player, platform]
    );
    if (found.rows.length > 0) {
      const row = found.rows[0];
      // Ready + versión actual → devolver tal cual
      if (row.version >= INSIGHTS_VERSION && row.status === 'ready') {
        return res.json({
          status: 'ready', version: row.version, computed_at: row.computed_at,
          insights: row.insights
        });
      }
      // In-flight → decir que siga haciendo polling
      if (row.status === 'pending' || row.status === 'computing') {
        return res.json({
          status: row.status, version: INSIGHTS_VERSION,
          message: 'Analizando telemetria...'
        });
      }
      // Versión vieja o error → re-computar
      if (row.version < INSIGHTS_VERSION || row.status === 'error') {
        await pool.query(
          `UPDATE match_insights SET status='pending', version=$4, error_msg=NULL
           WHERE match_id=$1 AND player_name=$2 AND platform=$3`,
          [matchId, player, platform, INSIGHTS_VERSION]
        ).catch(() => {});
        setImmediate(() => { computeMatchInsights(matchId, player, platform).catch(err => console.error('[match-insights] bg err:', err)); });
        return res.json({ status: 'pending', version: INSIGHTS_VERSION, message: 'Recomputando...' });
      }
    }
    // 2. Primera vez: insertar pending + disparar worker asíncrono
    await pool.query(
      `INSERT INTO match_insights (match_id, player_name, platform, status, insights, version)
       VALUES ($1, $2, $3, 'pending', NULL, $4)
       ON CONFLICT (match_id, player_name, platform) DO UPDATE
         SET status='pending', version=EXCLUDED.version, error_msg=NULL`,
      [matchId, player, platform, INSIGHTS_VERSION]
    ).catch(e => console.error('match-insights insert error:', e));
    setImmediate(() => { computeMatchInsights(matchId, player, platform).catch(err => console.error('[match-insights] bg err:', err)); });
    return res.json({
      status: 'pending', version: INSIGHTS_VERSION,
      message: 'Analizando telemetria...'
    });
  } catch (e) {
    console.error('match-insights error:', e);
    return res.status(500).json({ error: 'internal', message: e.message });
  }
});

// ═══ WHO IS PLAYING (v186) — Check last match of favorite players ═══
const _wipRateMap = new Map();
app.post('/api/who-is-playing', async (req, res) => {
  // Rate limit: 1 req/min per IP
  const ip = req.ip || req.connection.remoteAddress;
  const now = Date.now();
  if (_wipRateMap.get(ip) && now - _wipRateMap.get(ip) < 60000) {
    return res.status(429).json({ error: 'Rate limited — 1 req/min' });
  }
  _wipRateMap.set(ip, now);

  const { players } = req.body;
  if (!Array.isArray(players) || !players.length) return res.json({ players: [] });
  if (!SERVER_API_KEY) return res.status(503).json({ error: 'No API key' });

  const headers = { 'Authorization': 'Bearer ' + SERVER_API_KEY, 'Accept': 'application/vnd.api+json' };
  const results = [];
  const maxPlayers = Math.min(players.length, 20);

  // Group players by platform, batch up to 10 names per PUBG API call
  const byPlatform = {};
  for (let i = 0; i < maxPlayers; i++) {
    const p = players[i];
    const plat = (p.platform || 'psn').toLowerCase() === 'xbox' ? 'xbox' : 'psn';
    if (!byPlatform[plat]) byPlatform[plat] = [];
    byPlatform[plat].push(p.name);
  }

  for (const [platform, names] of Object.entries(byPlatform)) {
    // PUBG API accepts up to 10 playerNames per request
    for (let i = 0; i < names.length; i += 10) {
      const batch = names.slice(i, i + 10);
      const shard = platform === 'xbox' ? 'xbox-na' : 'psn';
      try {
        // Check cache first (5 min TTL)
        const cacheKey = `wip:${shard}:${batch.sort().join(',')}`;
        if (pool) {
          const cached = await pool.query(
            "SELECT data FROM api_cache WHERE cache_key = $1 AND created_at > NOW() - INTERVAL '5 minutes'",
            [cacheKey]
          ).catch(() => ({ rows: [] }));
          if (cached.rows.length > 0) {
            const cachedData = cached.rows[0].data;
            if (cachedData && cachedData.players) { results.push(...cachedData.players); continue; }
          }
        }

        const url = `https://api.pubg.com/shards/${shard}/players?filter[playerNames]=${batch.map(encodeURIComponent).join(',')}`;
        const r = await fetch(url, { headers, timeout: 8000 });
        if (!r.ok) continue;
        const data = await r.json();
        const batchResults = [];

        for (const player of (data.data || [])) {
          const name = player.attributes?.name;
          const matches = player.relationships?.matches?.data || [];
          if (!name || !matches.length) continue;

          // Get the most recent match to find lastPlayedAt
          const matchId = matches[0].id;
          try {
            // Check match cache
            const matchCacheKey = `match:${shard}:${matchId}`;
            let matchData = null;
            if (pool) {
              const mc = await pool.query(
                "SELECT data FROM api_cache WHERE cache_key = $1 AND created_at > NOW() - INTERVAL '30 minutes'",
                [matchCacheKey]
              ).catch(() => ({ rows: [] }));
              if (mc.rows.length > 0) matchData = mc.rows[0].data;
            }
            if (!matchData) {
              const mr = await fetch(`https://api.pubg.com/shards/${shard}/matches/${matchId}`, { headers: { 'Accept': 'application/vnd.api+json' } });
              if (mr.ok) {
                matchData = await mr.json();
                // Cache match data
                if (pool) {
                  pool.query(
                    "INSERT INTO api_cache(cache_key, data, created_at, ttl_seconds) VALUES($1,$2,NOW(),1800) ON CONFLICT(cache_key) DO UPDATE SET data=$2, created_at=NOW()",
                    [matchCacheKey, matchData]
                  ).catch(() => {});
                }
              }
            }
            if (matchData) {
              const attrs = matchData.data?.attributes || {};
              batchResults.push({
                name,
                platform,
                lastPlayedAt: attrs.createdAt || null,
                mapName: attrs.mapName || null,
                gameMode: attrs.gameMode || null
              });
            }
          } catch (e) { /* skip this match */ }
        }

        // Cache batch results
        if (pool && batchResults.length) {
          pool.query(
            "INSERT INTO api_cache(cache_key, data, created_at, ttl_seconds) VALUES($1,$2,NOW(),300) ON CONFLICT(cache_key) DO UPDATE SET data=$2, created_at=NOW()",
            [cacheKey, { players: batchResults }]
          ).catch(() => {});
        }
        results.push(...batchResults);
      } catch (e) { /* skip batch */ }
    }
  }

  res.json({ players: results });
});

// ═══ PUBG API PROXY (generic catch-all — MUST be after ALL /api/* specific routes) ═══
app.all('/api/*', rateLimit, async (req, res) => {
  trackMetric(req, 'api');
  const originalQuery = req.originalUrl.split('?')[1] || '';
  const pubgPath = req.params[0];
  const pubgUrl = `https://api.pubg.com/${pubgPath}${originalQuery ? '?' + originalQuery : ''}`;

  const apiKey = SERVER_API_KEY ? 'Bearer ' + SERVER_API_KEY : req.headers.authorization;
  if (!apiKey) return res.status(401).json({ error: 'Missing API Key' });

  // Only cache GET requests
  const cacheKey = req.method === 'GET' ? pubgUrl : null;
  const ttlMinutes = getCacheTTL(pubgPath);

  // Try to serve from cache
  if (cacheKey && pool) {
    try {
      const cached = await pool.query(
        "SELECT response_data, status_code FROM api_cache WHERE cache_key = $1 AND created_at > NOW() - INTERVAL '1 minute' * $2",
        [cacheKey, ttlMinutes]
      );
      if (cached.rows.length > 0) {
        trackMetric(req, 'cache-hit');
        res.status(cached.rows[0].status_code);
        res.set('Content-Type', 'application/vnd.api+json');
        res.set('X-Cache', 'HIT');
        res.send(cached.rows[0].response_data);
        return;
      }
    } catch (e) { /* cache miss, continue to API */ }
  }

  try {
    const response = await fetchWithTimeout(fetch, pubgUrl, {
      method: req.method,
      headers: { 'Authorization': apiKey, 'Accept': 'application/vnd.api+json' },
    }, 15000);
    const data = await response.text();

    // Save to cache if GET and successful (2xx)
    if (cacheKey && pool && response.status >= 200 && response.status < 300) {
      pool.query(
        "INSERT INTO api_cache (cache_key, response_data, status_code, created_at) VALUES ($1, $2, $3, NOW()) ON CONFLICT (cache_key) DO UPDATE SET response_data = $2, status_code = $3, created_at = NOW()",
        [cacheKey, data, response.status]
      ).catch(() => {}); // Fire and forget — don't block response
    }

    trackMetric(req, 'cache-miss');
    if (response.status === 429) trackMetric(req, 'pubg-rate-limited');
    res.status(response.status);
    res.set('Content-Type', 'application/vnd.api+json');
    res.set('X-Cache', 'MISS');
    res.send(data);
  } catch (err) {
    // On API error, try to serve stale cache (better than nothing)
    if (cacheKey && pool) {
      try {
        const stale = await pool.query(
          "SELECT response_data, status_code FROM api_cache WHERE cache_key = $1",
          [cacheKey]
        );
        if (stale.rows.length > 0) {
          res.status(stale.rows[0].status_code);
          res.set('Content-Type', 'application/vnd.api+json');
          res.set('X-Cache', 'STALE');
          res.send(stale.rows[0].response_data);
          return;
        }
      } catch (e) { /* no stale cache either */ }
    }
    console.error('Proxy error:', err.message);
    console.error('Proxy error:', err.message); res.status(500).json({ error: 'Error al consultar datos' });
  }
});

// Cleanup old cache entries every 30 minutes — EXCLUYE telemetry_* (rivalidades-v1)
setInterval(async () => {
  if (!pool) return;
  try { await pool.query("DELETE FROM api_cache WHERE created_at < NOW() - INTERVAL '2 hours' AND cache_key NOT LIKE 'telemetry\\_%' ESCAPE '\\'"); }
  catch (e) { /* silent */ }
}, 1800000);

// Admin verification endpoint — password never exposed in frontend
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
app.post('/auth/admin', rateLimit, (req, res) => {
  if (!ADMIN_PASSWORD) return res.status(503).json({ error: 'Admin no configurado' });
  const { password } = req.body;
  if (!password || typeof password !== 'string') return res.status(401).json({ error: 'Contraseña incorrecta' });
  // Timing-safe comparison to prevent timing attacks
  const a = Buffer.from(password.padEnd(64, '\0'));
  const b = Buffer.from(ADMIN_PASSWORD.padEnd(64, '\0'));
  if (a.length === b.length && crypto.timingSafeEqual(a, b)) {
    const token = jwt.sign({ role: 'admin' }, JWT_SECRET, { expiresIn: '4h' });
    console.log('[admin] Login exitoso desde', req.ip);
    res.json({ ok: true, token });
  } else {
    console.warn('[admin] Intento fallido desde', req.ip);
    res.status(401).json({ error: 'Contraseña incorrecta' });
  }
});

// ═══ METRICS ENDPOINT (admin only) ═══
app.get('/admin/metrics', (req, res) => {
  // Verify admin token
  const token = req.headers.authorization?.replace('Bearer ', '') || '';
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    if (decoded.role !== 'admin') throw new Error('Not admin');
  } catch (e) {
    return res.status(401).json({ error: 'Admin token requerido' });
  }
  const uptimeMs = Date.now() - metrics.startedAt;
  const uptimeH = Math.round(uptimeMs / 3600000 * 10) / 10;
  // Build hourly data (serializable — convert Sets to counts)
  const hourly = {};
  const sortedHours = Object.keys(metrics.hourly).sort().slice(-48);
  for (const h of sortedHours) {
    const d = metrics.hourly[h];
    hourly[h] = { requests: d.requests, uniqueIPs: d.uniqueIPs.size, searches: d.searches, rateLimited: d.rateLimited, cacheHits: d.cacheHits };
  }
  // Top 10 IPs by request count
  const topIPs = [...metrics.topIPs.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 15)
    .map(([ip, count]) => ({ ip, count }));
  // Top endpoints
  const topEndpoints = Object.entries(metrics.endpoints)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 20)
    .map(([ep, count]) => ({ endpoint: ep, count }));
  // Active users right now (IPs with requests in last 5 min)
  const fiveMinAgo = Date.now() - 300000;
  let activeNow = 0;
  for (const [, entry] of rateLimitMap) {
    if (entry.start > fiveMinAgo) activeNow++;
  }
  // Cache efficiency
  const cacheTotal = metrics.cacheHits + metrics.cacheMisses;
  const cacheRate = cacheTotal > 0 ? Math.round(metrics.cacheHits / cacheTotal * 100) : 0;
  res.json({
    uptime: uptimeH + 'h',
    uptimeMs,
    totalRequests: metrics.totalRequests,
    apiRequests: metrics.apiRequests,
    searchesTotal: metrics.searchesTotal,
    uniqueIPsTotal: metrics.uniqueIPs.size,
    activeNow,
    rateLimited: metrics.rateLimited,
    pubgRateLimited: metrics.pubgRateLimited,
    cache: { hits: metrics.cacheHits, misses: metrics.cacheMisses, rate: cacheRate + '%' },
    hourly,
    topIPs,
    topEndpoints
  });
});

// Sitemap for SEO — dynamic with clan URLs + popular players
app.get('/sitemap.xml', async (req, res) => {
  res.set('Content-Type', 'application/xml');
  const today = new Date().toISOString().split('T')[0];
  let clanUrls = '';
  let playerUrls = '';
  if (pool) {
    try {
      const { rows } = await pool.query('SELECT tag FROM clans WHERE active_members > 0 ORDER BY total_kills DESC LIMIT 500');
      rows.forEach(r => {
        clanUrls += `  <url><loc>https://v4nz.com/clan/${encodeURIComponent(r.tag)}</loc><changefreq>weekly</changefreq><priority>0.6</priority><lastmod>${today}</lastmod></url>\n`;
      });
    } catch(e) { console.error('Sitemap clan error:', e.message); }
    try {
      const { rows } = await pool.query(`
        SELECT DISTINCT player_name, platform
        FROM player_snapshots
        WHERE created_at > NOW() - INTERVAL '90 days'
        ORDER BY player_name
        LIMIT 1000
      `);
      rows.forEach(r => {
        playerUrls += `  <url><loc>https://v4nz.com/stats/${r.platform}/${encodeURIComponent(r.player_name)}</loc><changefreq>weekly</changefreq><priority>0.5</priority><lastmod>${today}</lastmod></url>\n`;
      });
    } catch(e) { console.error('Sitemap player error:', e.message); }
  }
  res.send(`<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://v4nz.com</loc><changefreq>daily</changefreq><priority>1.0</priority><lastmod>${today}</lastmod></url>
  <url><loc>https://v4nz.com/clanes</loc><changefreq>daily</changefreq><priority>0.8</priority><lastmod>${today}</lastmod></url>
  <url><loc>https://v4nz.com/ranking</loc><changefreq>daily</changefreq><priority>0.8</priority><lastmod>${today}</lastmod></url>
  <url><loc>https://v4nz.com/top500</loc><changefreq>weekly</changefreq><priority>0.7</priority><lastmod>${today}</lastmod></url>
  <url><loc>https://v4nz.com/comparar</loc><changefreq>weekly</changefreq><priority>0.6</priority><lastmod>${today}</lastmod></url>
${clanUrls}${playerUrls}</urlset>`);
});

// Google Search Console verification
app.get('/googlef2390246b37ad8b0.html', (req, res) => {
  res.set('Content-Type', 'text/html');
  res.send('google-site-verification: googlef2390246b37ad8b0.html');
});

// Robots.txt
app.get('/robots.txt', (req, res) => {
  res.set('Content-Type', 'text/plain');
  res.send('User-agent: *\nAllow: /\nSitemap: https://v4nz.com/sitemap.xml');
});

// ═══ Dynamic OG Image (SVG → PNG via sharp) ═══
function escXml(s) { return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&apos;'); }

function buildPlayerSvg(player, platform, stats) {
  const platIcon = platform === 'PSN' ? 'PlayStation' : 'Xbox';
  const hasStats = stats && stats.roundsPlayed;
  // Calculate stats if available
  const kills = hasStats ? (stats.kills || 0) : 0;
  const wins = hasStats ? (stats.wins || 0) : 0;
  const rounds = hasStats ? (stats.roundsPlayed || 0) : 0;
  const deaths = rounds - wins;
  const kd = hasStats && deaths > 0 ? (kills / deaths).toFixed(2) : '0';
  const wr = hasStats && rounds > 0 ? ((wins / rounds) * 100).toFixed(1) : '0';
  const avgDmg = hasStats && rounds > 0 ? Math.round((stats.damageDealt || 0) / rounds) : 0;
  const hsRate = hasStats && kills > 0 ? (((stats.headshotKills || 0) / kills) * 100).toFixed(0) : '0';

  const statsSection = hasStats ? `
    <!-- Stats boxes -->
    <rect x="80" y="310" width="230" height="100" rx="12" fill="#ffffff" fill-opacity="0.04" stroke="#00f0ff" stroke-opacity="0.15"/>
    <text x="195" y="355" font-family="Arial,Helvetica,sans-serif" font-size="40" font-weight="900" fill="#00f0ff" text-anchor="middle">${escXml(kd)}</text>
    <text x="195" y="390" font-family="Arial,Helvetica,sans-serif" font-size="14" fill="#888" text-anchor="middle" letter-spacing="2">K/D RATIO</text>

    <rect x="330" y="310" width="230" height="100" rx="12" fill="#ffffff" fill-opacity="0.04" stroke="#ffd700" stroke-opacity="0.15"/>
    <text x="445" y="355" font-family="Arial,Helvetica,sans-serif" font-size="40" font-weight="900" fill="#ffd700" text-anchor="middle">${escXml(String(wins))}</text>
    <text x="445" y="390" font-family="Arial,Helvetica,sans-serif" font-size="14" fill="#888" text-anchor="middle" letter-spacing="2">WINS (${escXml(wr)}%)</text>

    <rect x="580" y="310" width="230" height="100" rx="12" fill="#ffffff" fill-opacity="0.04" stroke="#ff6b00" stroke-opacity="0.15"/>
    <text x="695" y="355" font-family="Arial,Helvetica,sans-serif" font-size="40" font-weight="900" fill="#ff6b00" text-anchor="middle">${escXml(String(avgDmg))}</text>
    <text x="695" y="390" font-family="Arial,Helvetica,sans-serif" font-size="14" fill="#888" text-anchor="middle" letter-spacing="2">AVG DAMAGE</text>

    <rect x="830" y="310" width="230" height="100" rx="12" fill="#ffffff" fill-opacity="0.04" stroke="#a855f7" stroke-opacity="0.15"/>
    <text x="945" y="355" font-family="Arial,Helvetica,sans-serif" font-size="40" font-weight="900" fill="#a855f7" text-anchor="middle">${escXml(hsRate)}%</text>
    <text x="945" y="390" font-family="Arial,Helvetica,sans-serif" font-size="14" fill="#888" text-anchor="middle" letter-spacing="2">HEADSHOT</text>

    <text x="80" y="470" font-family="Arial,Helvetica,sans-serif" font-size="18" fill="#555" letter-spacing="1">${escXml(String(kills))} kills · ${escXml(String(rounds))} partidas · ${platIcon}</text>
  ` : `
    <text x="80" y="380" font-family="Arial,Helvetica,sans-serif" font-size="20" fill="#555" letter-spacing="2">STATS EN TIEMPO REAL · K/D · WIN RATE · ADN PUBG</text>
    <text x="80" y="420" font-family="Arial,Helvetica,sans-serif" font-size="24" fill="#888" letter-spacing="3">${platIcon}</text>
  `;

  return `<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="630" viewBox="0 0 1200 630">
    <defs>
      <linearGradient id="bg" x1="0" y1="0" x2="1" y2="1"><stop offset="0%" stop-color="#0b0b12"/><stop offset="100%" stop-color="#12081f"/></linearGradient>
      <linearGradient id="accent" x1="0" y1="0" x2="1" y2="0"><stop offset="0%" stop-color="#00f0ff"/><stop offset="100%" stop-color="#ff6b00"/></linearGradient>
    </defs>
    <rect width="1200" height="630" fill="url(#bg)"/>
    <rect y="0" width="1200" height="4" fill="url(#accent)"/>
    <text x="80" y="80" font-family="Arial,Helvetica,sans-serif" font-size="28" font-weight="900" fill="#00f0ff" letter-spacing="6">V4NZ</text>
    <text x="190" y="80" font-family="Arial,Helvetica,sans-serif" font-size="16" fill="#555" letter-spacing="3">PUBG CONSOLE STATS</text>
    <text x="80" y="200" font-family="Arial,Helvetica,sans-serif" font-size="72" font-weight="900" fill="#ffffff" letter-spacing="2">${escXml(player)}</text>
    <text x="80" y="260" font-family="Arial,Helvetica,sans-serif" font-size="20" fill="#888" letter-spacing="3">${platIcon} · Squad TPP</text>
    ${statsSection}
    <text x="80" y="560" font-family="Arial,Helvetica,sans-serif" font-size="16" fill="#00f0ff" letter-spacing="1">v4nz.com/stats/${escXml(platform.toLowerCase())}/${escXml(player)}</text>
    <rect x="80" y="580" width="1040" height="2" fill="url(#accent)" opacity="0.3"/>
    <text x="1120" y="610" font-family="Arial,Helvetica,sans-serif" font-size="12" fill="#444" text-anchor="end">Datos en tiempo real via PUBG API</text>
  </svg>`;
}

function buildClanSvg(tag, clan) {
  const hasClan = clan && clan.tag;
  const name = hasClan ? (clan.name || tag) : tag;
  const statsSection = hasClan ? `
    <text x="80" y="280" font-family="Arial,Helvetica,sans-serif" font-size="22" fill="#888" letter-spacing="2">${escXml(name)} · ${escXml((clan.platform || 'PSN').toUpperCase())} · Nivel ${clan.level || '?'}</text>
    <rect x="80" y="320" width="230" height="90" rx="12" fill="#ffffff" fill-opacity="0.04" stroke="#00f0ff" stroke-opacity="0.15"/>
    <text x="195" y="360" font-family="Arial,Helvetica,sans-serif" font-size="36" font-weight="900" fill="#00f0ff" text-anchor="middle">${clan.total_kills || 0}</text>
    <text x="195" y="390" font-family="Arial,Helvetica,sans-serif" font-size="13" fill="#888" text-anchor="middle" letter-spacing="2">TOTAL KILLS</text>
    <rect x="330" y="320" width="230" height="90" rx="12" fill="#ffffff" fill-opacity="0.04" stroke="#00ff88" stroke-opacity="0.15"/>
    <text x="445" y="360" font-family="Arial,Helvetica,sans-serif" font-size="36" font-weight="900" fill="#00ff88" text-anchor="middle">${(parseFloat(clan.avg_kd) || 0).toFixed(2)}</text>
    <text x="445" y="390" font-family="Arial,Helvetica,sans-serif" font-size="13" fill="#888" text-anchor="middle" letter-spacing="2">K/D MEDIO</text>
    <rect x="580" y="320" width="230" height="90" rx="12" fill="#ffffff" fill-opacity="0.04" stroke="#ffd700" stroke-opacity="0.15"/>
    <text x="695" y="360" font-family="Arial,Helvetica,sans-serif" font-size="36" font-weight="900" fill="#ffd700" text-anchor="middle">${clan.total_wins || 0}</text>
    <text x="695" y="390" font-family="Arial,Helvetica,sans-serif" font-size="13" fill="#888" text-anchor="middle" letter-spacing="2">VICTORIAS</text>
    <rect x="830" y="320" width="230" height="90" rx="12" fill="#ffffff" fill-opacity="0.04" stroke="#ff6b00" stroke-opacity="0.15"/>
    <text x="945" y="360" font-family="Arial,Helvetica,sans-serif" font-size="36" font-weight="900" fill="#ff6b00" text-anchor="middle">${clan.active_members || 0}</text>
    <text x="945" y="390" font-family="Arial,Helvetica,sans-serif" font-size="13" fill="#888" text-anchor="middle" letter-spacing="2">ACTIVOS</text>
    <text x="80" y="470" font-family="Arial,Helvetica,sans-serif" font-size="16" fill="#555">${clan.member_count || 0} miembros · Win Rate ${(parseFloat(clan.win_rate) || 0).toFixed(1)}% · Dano medio ${(parseFloat(clan.avg_damage) || 0).toFixed(0)}</text>
  ` : `
    <text x="80" y="400" font-family="Arial,Helvetica,sans-serif" font-size="20" fill="#555" letter-spacing="2">MIEMBROS · KILLS · K/D · RANKING</text>
  `;
  return `<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="630" viewBox="0 0 1200 630">
    <defs>
      <linearGradient id="bg" x1="0" y1="0" x2="1" y2="1"><stop offset="0%" stop-color="#0b0b12"/><stop offset="100%" stop-color="#12081f"/></linearGradient>
      <linearGradient id="accent" x1="0" y1="0" x2="1" y2="0"><stop offset="0%" stop-color="#00f0ff"/><stop offset="100%" stop-color="#ff6b00"/></linearGradient>
    </defs>
    <rect width="1200" height="630" fill="url(#bg)"/>
    <rect y="0" width="1200" height="4" fill="url(#accent)"/>
    <text x="80" y="80" font-family="Arial,Helvetica,sans-serif" font-size="28" font-weight="900" fill="#00f0ff" letter-spacing="6">V4NZ</text>
    <text x="190" y="80" font-family="Arial,Helvetica,sans-serif" font-size="16" fill="#555" letter-spacing="3">PUBG CONSOLE STATS</text>
    <text x="80" y="145" font-family="Arial,Helvetica,sans-serif" font-size="20" fill="#ff6b00" letter-spacing="3">CLAN</text>
    <text x="80" y="220" font-family="Arial,Helvetica,sans-serif" font-size="80" font-weight="900" fill="#ffffff" letter-spacing="4">[${escXml(tag)}]</text>
    ${statsSection}
    <text x="80" y="560" font-family="Arial,Helvetica,sans-serif" font-size="16" fill="#ff6b00" letter-spacing="1">v4nz.com/clan/${escXml(tag)}</text>
    <rect x="80" y="580" width="1040" height="2" fill="url(#accent)" opacity="0.3"/>
    <text x="1120" y="610" font-family="Arial,Helvetica,sans-serif" font-size="12" fill="#444" text-anchor="end">Datos en tiempo real via PUBG API</text>
  </svg>`;
}

async function svgToPng(svgStr) {
  if (!sharp) return null;
  return sharp(Buffer.from(svgStr)).png().toBuffer();
}

// Player OG image — with real stats from PUBG API
app.get('/og-image/stats/:platform/:player.png', async (req, res) => {
  try {
    const platform = req.params.platform.toUpperCase();
    const player = decodeURIComponent(req.params.player);
    let stats = null;

    // Try to fetch real stats (cached via api_cache)
    if (SERVER_API_KEY && pool) {
      try {
        const headers = { 'Authorization': 'Bearer ' + SERVER_API_KEY, 'Accept': 'application/vnd.api+json' };
        const shard = platform.toLowerCase();
        // Check OG cache first (1 hour)
        const ogCacheKey = `og_stats_${shard}_${player.toLowerCase()}`;
        const cached = await pool.query("SELECT response_data FROM api_cache WHERE cache_key = $1 AND created_at > NOW() - INTERVAL '60 minutes'", [ogCacheKey]);
        if (cached.rows.length) {
          try { stats = JSON.parse(cached.rows[0].response_data); } catch(e) {}
        }
        if (!stats) {
          const pResp = await fetchWithTimeout(fetch, `https://api.pubg.com/shards/${shard}/players?filter[playerNames]=${encodeURIComponent(player)}`, { headers }, 8000);
          if (pResp.ok) {
            const pData = await pResp.json();
            const pId = pData.data?.[0]?.id;
            if (pId) {
              const seasonsResp = await fetchWithTimeout(fetch, `https://api.pubg.com/shards/${shard}/seasons`, { headers }, 8000);
              if (seasonsResp.ok) {
                const seasonsData = await seasonsResp.json();
                const currentSeason = (seasonsData.data || []).find(s => s.attributes?.isCurrentSeason);
                if (currentSeason) {
                  const statsResp = await fetchWithTimeout(fetch, `https://api.pubg.com/shards/${shard}/players/${pId}/seasons/${currentSeason.id}`, { headers }, 8000);
                  if (statsResp.ok) {
                    const sData = await statsResp.json();
                    stats = sData.data?.attributes?.gameModeStats?.['squad-fpp'] || sData.data?.attributes?.gameModeStats?.squad || null;
                    // Cache for 1 hour
                    if (stats) {
                      await pool.query('INSERT INTO api_cache (cache_key, response_data, status_code, created_at) VALUES ($1, $2, 200, NOW()) ON CONFLICT (cache_key) DO UPDATE SET response_data = $2, created_at = NOW()', [ogCacheKey, JSON.stringify(stats)]).catch(() => {});
                    }
                  }
                }
              }
            }
          }
        }
      } catch (e) { /* continue without stats */ }
    }

    const svg = buildPlayerSvg(player, platform, stats);
    const png = await svgToPng(svg);
    if (png) {
      res.set('Content-Type', 'image/png');
      res.set('Cache-Control', 'public, max-age=3600');
      return res.send(png);
    }
    res.set('Content-Type', 'image/svg+xml');
    res.set('Cache-Control', 'public, max-age=3600');
    res.send(svg);
  } catch (e) {
    console.error('OG image error:', e.message);
    res.status(500).send('Error generating image');
  }
});

// Clan OG image — with real stats from DB
app.get('/og-image/clan/:tag.png', async (req, res) => {
  try {
    const tag = decodeURIComponent(req.params.tag).toUpperCase().replace(/[^A-Z0-9_]/g, '');
    let clan = null;
    if (pool) {
      try {
        const result = await pool.query('SELECT * FROM clans WHERE tag = $1', [tag]);
        if (result.rows.length) clan = result.rows[0];
      } catch (e) { /* continue without stats */ }
    }
    const svg = buildClanSvg(tag, clan);
    const png = await svgToPng(svg);
    if (png) {
      res.set('Content-Type', 'image/png');
      res.set('Cache-Control', 'public, max-age=3600');
      return res.send(png);
    }
    res.set('Content-Type', 'image/svg+xml');
    res.set('Cache-Control', 'public, max-age=3600');
    res.send(svg);
  } catch (e) {
    console.error('OG image error:', e.message);
    res.status(500).send('Error generating image');
  }
});

// PWA files
app.get('/manifest.json', (req, res) => res.sendFile(path.join(__dirname, 'manifest.json')));
app.get('/sw.js', (req, res) => {
  res.set('Content-Type', 'application/javascript');
  res.set('Service-Worker-Allowed', '/');
  res.sendFile(path.join(__dirname, 'sw.js'));
});

// PWA Icons (generated SVG — no external files needed)
const V4NZ_ICON_SVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512">
  <rect width="512" height="512" rx="96" fill="#0b0b12"/>
  <rect x="24" y="24" width="464" height="464" rx="80" fill="none" stroke="#00f0ff" stroke-width="4" opacity=".3"/>
  <text x="256" y="300" text-anchor="middle" font-family="sans-serif" font-weight="900" font-size="220" fill="#00f0ff">V4</text>
  <text x="256" y="420" text-anchor="middle" font-family="sans-serif" font-weight="700" font-size="100" fill="#ff6b00">NZ</text>
</svg>`;
app.get('/icon-192.svg', (req, res) => { res.set('Content-Type', 'image/svg+xml'); res.send(V4NZ_ICON_SVG); });
app.get('/icon-512.svg', (req, res) => { res.set('Content-Type', 'image/svg+xml'); res.send(V4NZ_ICON_SVG); });
app.get('/icon-maskable.svg', (req, res) => {
  res.set('Content-Type', 'image/svg+xml');
  res.send(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512">
    <rect width="512" height="512" fill="#0b0b12"/>
    <text x="256" y="280" text-anchor="middle" font-family="sans-serif" font-weight="900" font-size="180" fill="#00f0ff">V4</text>
    <text x="256" y="390" text-anchor="middle" font-family="sans-serif" font-weight="700" font-size="90" fill="#ff6b00">NZ</text>
  </svg>`);
});

// OG Image (static SVG served as image for social sharing previews)
app.get('/og-image.png', (req, res) => {
  // Serve an SVG with .png extension — most crawlers accept this
  // For pixel-perfect PNG, install 'canvas' or 'sharp' npm packages
  res.set('Content-Type', 'image/svg+xml');
  res.send(`<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="630" viewBox="0 0 1200 630">
    <defs><linearGradient id="bg" x1="0" y1="0" x2="1" y2="1"><stop offset="0%" stop-color="#0b0b12"/><stop offset="100%" stop-color="#131320"/></linearGradient></defs>
    <rect width="1200" height="630" fill="url(#bg)"/>
    <rect x="16" y="16" width="1168" height="598" rx="24" fill="none" stroke="#00f0ff" stroke-width="2" opacity=".2"/>
    <text x="600" y="260" text-anchor="middle" font-family="sans-serif" font-weight="900" font-size="140" fill="#00f0ff">V4NZ</text>
    <text x="600" y="360" text-anchor="middle" font-family="sans-serif" font-weight="600" font-size="42" fill="#eaeaf2">PUBG Console Stats Tracker</text>
    <text x="600" y="430" text-anchor="middle" font-family="sans-serif" font-weight="400" font-size="28" fill="#9e9eb8">PlayStation &amp; Xbox — Estadisticas en Tiempo Real</text>
    <text x="600" y="560" text-anchor="middle" font-family="sans-serif" font-weight="700" font-size="24" fill="#ff6b00">v4nz.com</text>
  </svg>`);
});

// ═══ PLAYER NAME HISTORY ═══

// POST /players/track-name — Track accountId ↔ gamertag, detect name changes
app.post('/players/track-name', async (req, res) => {
  if (!pool) return res.json({ ok: true });
  try {
    const { accountId, playerName, platform } = req.body;
    if (!accountId || !playerName) return res.status(400).json({ error: 'accountId and playerName required' });
    // Check if we already know this account
    const existing = await pool.query('SELECT player_name, platform FROM player_accounts WHERE account_id = $1', [accountId]);
    if (existing.rows.length) {
      const oldName = existing.rows[0].player_name;
      if (oldName.toLowerCase() !== playerName.toLowerCase()) {
        // Name changed! Record it
        await pool.query(
          'INSERT INTO player_name_history (account_id, old_name, new_name, platform) VALUES ($1, $2, $3, $4)',
          [accountId, oldName, playerName, platform || 'psn']
        );
        console.log(`[name-change] Detected: "${oldName}" → "${playerName}" (${accountId})`);
        // Update clan_members if this player is in any clan
        await pool.query('UPDATE clan_members SET player_name = $1 WHERE player_name = $2', [playerName, oldName]).catch(() => {});
      }
      // Update the stored name
      await pool.query('UPDATE player_accounts SET player_name = $1, platform = $2, updated_at = NOW() WHERE account_id = $3',
        [playerName, platform || existing.rows[0].platform, accountId]);
    } else {
      // First time seeing this account
      await pool.query('INSERT INTO player_accounts (account_id, player_name, platform) VALUES ($1, $2, $3) ON CONFLICT (account_id) DO UPDATE SET player_name = EXCLUDED.player_name, updated_at = NOW()',
        [accountId, playerName, platform || 'psn']);
    }
    res.json({ ok: true });
  } catch (e) {
    console.error('[track-name] Error:', e.message);
    res.json({ ok: true }); // Don't fail the main flow
  }
});

// GET /players/:name/aliases — Get all known names for a player
app.get('/players/:name/aliases', async (req, res) => {
  if (!pool) return res.json({ aliases: [] });
  try {
    const name = req.params.name;
    // Find account ID for this player
    const account = await pool.query('SELECT account_id FROM player_accounts WHERE LOWER(player_name) = LOWER($1)', [name]);
    if (!account.rows.length) return res.json({ aliases: [] });
    const accountId = account.rows[0].account_id;
    // Get all name changes for this account
    const history = await pool.query(
      'SELECT old_name, new_name, detected_at FROM player_name_history WHERE account_id = $1 ORDER BY detected_at DESC',
      [accountId]
    );
    // Collect all unique previous names (not the current one)
    const currentName = name.toLowerCase();
    const aliasSet = new Set();
    history.rows.forEach(r => {
      if (r.old_name.toLowerCase() !== currentName) aliasSet.add(r.old_name);
      if (r.new_name.toLowerCase() !== currentName) aliasSet.add(r.new_name);
    });
    res.json({ aliases: [...aliasSet], history: history.rows });
  } catch (e) {
    console.error('[aliases] Error:', e.message);
    res.json({ aliases: [] });
  }
});

// GET /clans/:tag/aliases — Get name changes for all members of a clan
app.get('/clans/:tag/member-aliases', async (req, res) => {
  if (!pool) return res.json({ aliases: {} });
  try {
    const tag = req.params.tag.toUpperCase();
    const members = await pool.query('SELECT player_name FROM clan_members WHERE clan_tag = $1', [tag]);
    if (!members.rows.length) return res.json({ aliases: {} });
    const memberNames = members.rows.map(r => r.player_name.toLowerCase());
    // Find accounts for these members
    const accounts = await pool.query(
      'SELECT account_id, player_name FROM player_accounts WHERE LOWER(player_name) = ANY($1)',
      [memberNames]
    );
    if (!accounts.rows.length) return res.json({ aliases: {} });
    const accountIds = accounts.rows.map(r => r.account_id);
    // Get all name history for these accounts
    const history = await pool.query(
      'SELECT account_id, old_name, new_name, detected_at FROM player_name_history WHERE account_id = ANY($1) ORDER BY detected_at DESC',
      [accountIds]
    );
    // Build map: currentName -> [previous names]
    const accountToCurrentName = {};
    accounts.rows.forEach(r => { accountToCurrentName[r.account_id] = r.player_name; });
    const result = {};
    history.rows.forEach(r => {
      const current = accountToCurrentName[r.account_id];
      if (!current) return;
      if (!result[current]) result[current] = [];
      const prev = r.old_name.toLowerCase() !== current.toLowerCase() ? r.old_name : null;
      if (prev && !result[current].includes(prev)) result[current].push(prev);
    });
    res.json({ aliases: result });
  } catch (e) {
    console.error('[member-aliases] Error:', e.message);
    res.json({ aliases: {} });
  }
});

// HTML attribute escaping for dynamic meta tags
function escHtml(s) { return String(s || '').replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;'); }

// ═══ MAP IMAGE PROXY (GitHub LFS workaround) ═══
const MAP_IMG_CACHE = {};  // In-memory cache: { mapKey: { buffer, contentType, fetchedAt } }
const MAP_IMG_TTL = 7 * 24 * 60 * 60 * 1000; // 7 days cache
const MAP_IMG_NAMES = {
  'erangel': 'Erangel_Main_Low_Res.png',
  'miramar': 'Miramar_Main_Low_Res.png',
  'vikendi': 'Vikendi_Main_Low_Res.png',
  'sanhok': 'Sanhok_Main_Low_Res.png',
  'taego': 'Taego_Main_Low_Res.png',
  'deston': 'Deston_Main_Low_Res.png',
  'rondo': 'Rondo_Main_Low_Res.png',
  'haven': 'Haven_Main_Low_Res.png',
  'karakin': 'Karakin_Main_Low_Res.png',
  'paramo': 'Paramo_Main_Low_Res.png',
  'camp_jackal': 'Camp_Jackal_Main_Low_Res.png'
};

app.get('/maps/:name.png', async (req, res) => {
  const mapKey = (req.params.name || '').toLowerCase().replace(/[^a-z0-9_]/g, '');
  const fileName = MAP_IMG_NAMES[mapKey];
  if (!fileName) return res.status(404).send('Map not found');

  // Check cache
  const cached = MAP_IMG_CACHE[mapKey];
  if (cached && (Date.now() - cached.fetchedAt) < MAP_IMG_TTL) {
    res.set('Content-Type', cached.contentType || 'image/png');
    res.set('Cache-Control', 'public, max-age=604800'); // 7 days
    return res.send(cached.buffer);
  }

  // Try multiple GitHub URL patterns for LFS files
  const urls = [
    `https://media.githubusercontent.com/media/pubg/api-assets/master/Assets/Maps/${fileName}`,
    `https://raw.githubusercontent.com/pubg/api-assets/master/Assets/Maps/${fileName}`,
    `https://cdn.jsdelivr.net/gh/pubg/api-assets@master/Assets/Maps/${fileName}`
  ];

  for (const url of urls) {
    try {
      const resp = await fetchWithTimeout(fetch, url, {}, 12000);
      if (resp.ok) {
        const buffer = Buffer.from(await resp.arrayBuffer());
        // Verify it's actually an image (LFS pointer files are small text)
        if (buffer.length > 1000) {
          const contentType = resp.headers.get('content-type') || 'image/png';
          MAP_IMG_CACHE[mapKey] = { buffer, contentType, fetchedAt: Date.now() };
          res.set('Content-Type', contentType);
          res.set('Cache-Control', 'public, max-age=604800');
          return res.send(buffer);
        }
      }
    } catch (e) { /* try next URL */ }
  }

  res.status(502).send('Map image unavailable');
});

// Fallback: serve index.html for SPA routes with dynamic meta tags — marker: v184-server
app.get('*', (req, res) => {
  const statsMatch = req.path.match(/^\/stats\/(psn|xbox)\/([^\/]+)(?:\/match\/[a-f0-9-]+)?$/i);
  const clanMatch = req.path.match(/^\/clan\/([^\/]+)(?:\/[^\/]+)?$/i);
  const isMatchDetail = /\/match\/[a-f0-9-]+$/i.test(req.path);

  // Map SPA paths to SEO titles/descriptions for crawlers
  const spaPages = {
    '/clanes': { title: 'Clanes PUBG Consola — Busca y Compara | V4NZ', desc: 'Busca clanes de PUBG en PlayStation y Xbox. Compara estadísticas, miembros, kills y ranking entre clanes.' },
    '/clans': { title: 'Clanes PUBG Consola — Busca y Compara | V4NZ', desc: 'Busca clanes de PUBG en PlayStation y Xbox. Compara estadísticas, miembros, kills y ranking entre clanes.' },
    '/ranking': { title: 'Ranking de Clanes PUBG — Top Clanes Consola | V4NZ', desc: 'Ranking de los mejores clanes de PUBG en consola. Clasificación por kills, K/D, victorias y más.' },
    '/top500': { title: 'Top 500 PUBG Consola — Leaderboard Oficial | V4NZ', desc: 'Top 500 jugadores de PUBG en PlayStation y Xbox. Leaderboard oficial con stats en tiempo real.' },
    '/comparar': { title: 'Comparar Jugadores PUBG — Stats vs Stats | V4NZ', desc: 'Compara estadísticas de dos jugadores de PUBG en consola. K/D, victorias, daño, headshots y más cara a cara.' },
    '/compare': { title: 'Comparar Jugadores PUBG — Stats vs Stats | V4NZ', desc: 'Compara estadísticas de dos jugadores de PUBG en consola. K/D, victorias, daño, headshots y más cara a cara.' }
  };

  try {
    let html = _cachedHtml;
    let title, desc, canonicalUrl, ogImage;

    if (statsMatch) {
      const platform = statsMatch[1].toUpperCase();
      const playerName = decodeURIComponent(statsMatch[2]);
      if (isMatchDetail) {
        title = `Partida de ${playerName} — PUBG ${platform} | V4NZ`;
        desc = `Detalle de partida de ${playerName} en PUBG ${platform}. Kill log, daño, mapa y auditoría IA.`;
      } else {
        title = `${playerName} — Stats PUBG ${platform} | V4NZ`;
        desc = `Estadísticas de ${playerName} en PUBG ${platform}. K/D, victorias, partidas, daño y más. Datos en tiempo real via PUBG API.`;
      }
      canonicalUrl = `https://v4nz.com/stats/${statsMatch[1].toLowerCase()}/${encodeURIComponent(playerName)}`;
      ogImage = `https://v4nz.com/og-image/stats/${statsMatch[1].toLowerCase()}/${encodeURIComponent(playerName)}.png`;
    } else if (clanMatch) {
      const clanTag = decodeURIComponent(clanMatch[1]).toUpperCase();
      title = `Clan [${clanTag}] — PUBG Stats Consola | V4NZ`;
      desc = `Estadísticas del clan ${clanTag} en PUBG consola. Miembros, kills, K/D medio, victorias y ranking.`;
      canonicalUrl = `https://v4nz.com/clan/${encodeURIComponent(clanTag)}`;
      ogImage = `https://v4nz.com/og-image/clan/${encodeURIComponent(clanTag)}.png`;
    } else if (spaPages[req.path]) {
      title = spaPages[req.path].title;
      desc = spaPages[req.path].desc;
      canonicalUrl = `https://v4nz.com${req.path}`;
    }

    if (title) {
      const safeTitle = escHtml(title);
      const safeDesc = escHtml(desc);
      html = html
        .replace(/<title>[^<]*<\/title>/, `<title>${safeTitle}</title>`)
        .replace(/<meta property="og:title"[^>]*>/, `<meta property="og:title" content="${safeTitle}">`)
        .replace(/<meta property="og:description"[^>]*>/, `<meta property="og:description" content="${safeDesc}">`)
        .replace(/<meta name="twitter:title"[^>]*>/, `<meta name="twitter:title" content="${safeTitle}">`)
        .replace(/<meta name="twitter:description"[^>]*>/, `<meta name="twitter:description" content="${safeDesc}">`)
        .replace(/<meta name="description"[^>]*>/, `<meta name="description" content="${safeDesc}">`);
      if (canonicalUrl) {
        html = html
          .replace(/<meta property="og:url"[^>]*>/, `<meta property="og:url" content="${escHtml(canonicalUrl)}">`)
          .replace(/<link rel="canonical"[^>]*>/, `<link rel="canonical" href="${escHtml(canonicalUrl)}">`);
      }
      if (ogImage) {
        html = html
          .replace(/<meta property="og:image" content="[^"]*">/, `<meta property="og:image" content="${escHtml(ogImage)}">`)
          .replace(/<meta name="twitter:image" content="[^"]*">/, `<meta name="twitter:image" content="${escHtml(ogImage)}">`);
      }
    }
    res.set('Content-Type', 'text/html');
    res.send(html);
  } catch (e) {
    res.sendFile(path.join(__dirname, 'index.html'));
  }
});

// ═══ LEADERBOARD PRE-WARM ═══
// Pre-warm the most popular leaderboard combos on startup + every 2 hours
async function prewarmLeaderboards() {
  if (!SERVER_API_KEY || !pool) return;
  const combos = [
    { platform: 'console', region: 'eu', mode: 'squad-fpp' },
    { platform: 'console', region: 'eu', mode: 'squad' }
  ];
  for (const c of combos) {
    try {
      const url = `http://localhost:${PORT}/api/leaderboard?platform=${c.platform}&region=${c.region}&mode=${c.mode}`;
      await fetch(url);
      console.log(`[Pre-warm] LB ${c.platform}/${c.region}/${c.mode} OK`);
    } catch (e) { console.error(`[Pre-warm] LB ${c.platform}/${c.region}/${c.mode} FAIL:`, e.message); }
  }
}

// ═══ HEALTH CHECK ═══
app.get('/health', async (req, res) => {
  const health = { status: 'ok', uptime: process.uptime(), timestamp: new Date().toISOString() };
  if (pool) {
    try { await pool.query('SELECT 1'); health.database = 'connected'; }
    catch (e) { health.database = 'error'; health.status = 'degraded'; }
  } else { health.database = 'not configured'; }
  health.apiKey = SERVER_API_KEY ? 'configured' : 'missing';
  res.status(health.status === 'ok' ? 200 : 503).json(health);
});

// ═══ GRACEFUL SHUTDOWN ═══
function gracefulShutdown(signal) {
  console.log(`\n[${signal}] Shutting down gracefully...`);
  if (_server) {
    _server.close(() => {
      console.log('[shutdown] HTTP server closed');
      if (pool) pool.end().then(() => { console.log('[shutdown] DB pool closed'); process.exit(0); }).catch(() => process.exit(0));
      else process.exit(0);
    });
    setTimeout(() => { console.error('[shutdown] Forced exit after 10s timeout'); process.exit(1); }, 10000);
  } else { process.exit(0); }
}
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));
process.on('uncaughtException', (err) => { console.error('[FATAL] Uncaught exception:', err); gracefulShutdown('uncaughtException'); });
process.on('unhandledRejection', (reason) => { console.error('[FATAL] Unhandled rejection:', reason); });

// ═══ START ═══
let _server;
initDB().then(() => {
  _server = app.listen(PORT, () => {
    console.log(`
╔═══════════════════════════════════════════════╗
║  V4NZ PUBG Stats Server v2.0                 ║
║  http://localhost:${PORT}                        ║
║                                               ║
║  API Key: ${SERVER_API_KEY ? 'CONFIGURADA ✓' : 'NO CONFIGURADA ✗'}
║  Database: ${pool ? 'CONECTADA ✓' : 'NO CONFIGURADA (localStorage)'}
║  Clan API: ${pool ? '/clans/* ACTIVO' : 'DESACTIVADO'}
╚═══════════════════════════════════════════════╝
    `);
    // Pre-warm leaderboards 5s after startup, then every 2 hours
    setTimeout(prewarmLeaderboards, 5000);
    setInterval(prewarmLeaderboards, 2 * 60 * 60 * 1000);

    // ═══ CRON: Auto-refresh all clans every 24h ═══
    async function cronRefreshAllClans() {
      if (!pool) return;
      const headers = { 'Authorization': 'Bearer ' + SERVER_API_KEY, 'Accept': 'application/vnd.api+json' };
      try {
        // Phase 1: Clans WITH pubg_clan_id — direct import
        const staleDirect = await pool.query(
          "SELECT tag, pubg_clan_id FROM clans WHERE pubg_clan_id IS NOT NULL AND (stats_updated_at IS NULL OR stats_updated_at < NOW() - INTERVAL '24 hours') ORDER BY stats_updated_at ASC NULLS FIRST LIMIT 15"
        );
        // Phase 2: Clans WITHOUT pubg_clan_id — resolve via member lookup
        const staleNoId = await pool.query(
          "SELECT c.tag, c.platform, (SELECT cm.player_name FROM clan_members cm WHERE cm.clan_tag = c.tag AND (cm.kills > 0 OR cm.rounds > 0) ORDER BY cm.kills DESC LIMIT 1) AS top_member FROM clans c WHERE c.pubg_clan_id IS NULL AND (c.stats_updated_at IS NULL OR c.stats_updated_at < NOW() - INTERVAL '24 hours') ORDER BY c.stats_updated_at ASC NULLS FIRST LIMIT 10"
        );
        const totalStale = staleDirect.rows.length + staleNoId.rows.length;
        if (!totalStale) { console.log('[cron] All clans up to date'); return; }
        console.log(`[cron] Refreshing ${totalStale} stale clans (${staleDirect.rows.length} with ID, ${staleNoId.rows.length} need lookup)...`);

        // Phase 1: direct import
        for (const clan of staleDirect.rows) {
          try {
            await importClanByPubgId(clan.pubg_clan_id);
            console.log(`[cron] ✓ Updated [${clan.tag}]`);
          } catch (e) {
            console.error(`[cron] ✗ Failed [${clan.tag}]:`, e.message);
          }
          await new Promise(r => setTimeout(r, 800));  // rpm100-throttling-relax-v1: 3000→800ms
        }

        // Phase 2: resolve pubg_clan_id from top member, then import
        for (const clan of staleNoId.rows) {
          if (!clan.top_member) {
            console.log(`[cron] ⊘ Skipped [${clan.tag}]: no active members to lookup`);
            continue;
          }
          try {
            const shardsToTry = [clan.platform || 'psn', 'xbox', 'psn', 'steam'].filter((v, i, a) => a.indexOf(v) === i);
            let foundClanId = null, foundShard = null;
            for (const shard of shardsToTry) {
              try {
                const pResp = await fetchWithTimeout(fetch,
                  `https://api.pubg.com/shards/${shard}/players?filter[playerNames]=${encodeURIComponent(clan.top_member)}`,
                  { headers }, 8000);
                if (pResp.ok) {
                  const pData = await pResp.json();
                  const cId = pData.data?.[0]?.attributes?.clanId;
                  if (cId) { foundClanId = cId; foundShard = shard; break; }
                }
              } catch (e) { /* shard fail, try next */ }
            }
            if (foundClanId) {
              try { await pool.query('UPDATE clans SET pubg_clan_id = $1, platform = $2 WHERE tag = $3', [foundClanId, foundShard, clan.tag]); } catch(e) {}
              await importClanByPubgId(foundClanId);
              console.log(`[cron] ✓ Resolved + Updated [${clan.tag}] via ${clan.top_member} → ${foundClanId}`);
            } else {
              console.log(`[cron] ⊘ Could not resolve clan ID for [${clan.tag}] via ${clan.top_member}`);
            }
          } catch (e) {
            console.error(`[cron] ✗ Failed [${clan.tag}]:`, e.message);
          }
          await new Promise(r => setTimeout(r, 800));  // rpm100-throttling-relax-v1: 3000→800ms
        }

        console.log('[cron] Clan refresh cycle complete');
      } catch (e) { console.error('[cron] Error:', e.message); }
    }
    // Run 60s after startup, then every 12 hours
    setTimeout(cronRefreshAllClans, 60000);
    setInterval(cronRefreshAllClans, 12 * 60 * 60 * 1000);
  });
});
