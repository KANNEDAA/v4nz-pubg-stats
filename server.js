// ═══════════════════════════════════════════════
//  V4NZ PUBG Stats — Server + Clan API
//  Proxy PUBG API + PostgreSQL clan system
// ═══════════════════════════════════════════════

const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const compression = require('compression');
let sharp;
try { sharp = require('sharp'); } catch(e) { console.warn('⚠️  sharp not installed — OG images will serve as SVG fallback'); }

// Single dynamic import for node-fetch (ESM)
const fetch = (...args) => import('node-fetch').then(({default: f}) => f(...args));

const app = express();
const PORT = process.env.PORT || 3000;
const SERVER_API_KEY = process.env.PUBG_API_KEY || '';
const JWT_SECRET = process.env.JWT_SECRET || 'v4nz_secret_' + Math.random().toString(36).slice(2);
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

// ═══ SECURITY HEADERS ═══
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  next();
});

app.use(express.static(path.join(__dirname)));

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
        created_at TIMESTAMPTZ DEFAULT NOW(),
        last_login TIMESTAMPTZ DEFAULT NOW()
      );
      CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
      CREATE INDEX IF NOT EXISTS idx_users_discord ON users(discord_id);
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
    `);
    // Cleanup old cache entries on startup (older than 1 hour)
    await pool.query("DELETE FROM api_cache WHERE created_at < NOW() - INTERVAL '1 hour'").catch(() => {});
    // Alter existing columns to support larger values (safe to run multiple times)
    await pool.query(`
      ALTER TABLE clans ALTER COLUMN avg_kd TYPE NUMERIC(6,2);
      ALTER TABLE clans ALTER COLUMN avg_damage TYPE NUMERIC(12,1);
      ALTER TABLE clans ALTER COLUMN win_rate TYPE NUMERIC(6,2);
      ALTER TABLE clan_members ALTER COLUMN kd TYPE NUMERIC(6,2);
      ALTER TABLE clan_members ALTER COLUMN damage TYPE NUMERIC(12,1);
    `).catch(() => {}); // Ignore if already correct type
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
         FROM clans WHERE active_members > 0 ORDER BY ${order} LIMIT $1`, [limit]
      ),
      pool.query('SELECT COUNT(*)::int AS cnt, SUM(active_members)::int AS players, SUM(total_kills)::int AS kills FROM clans WHERE active_members > 0')
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
    res.json({ clan: clan.rows[0], members: members.rows });
  } catch (e) { console.error(e.message); res.status(500).json({ error: 'Error interno del servidor' }); }
});

// POST /clans/register — Register or update a clan with member stats
app.post('/clans/register', rateLimit, async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'No database configured' });
  try {
    const { tag, name, memberCount, level, platform, registeredBy, members } = req.body;
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

    // Upsert clan
    await pool.query(`
      INSERT INTO clans (tag, name, member_count, level, platform, registered_by,
                         total_kills, total_wins, avg_kd, avg_damage, total_rounds,
                         win_rate, active_members, stats_updated_at, updated_at)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,NOW(),NOW())
      ON CONFLICT (tag) DO UPDATE SET
        name=EXCLUDED.name, member_count=EXCLUDED.member_count, level=EXCLUDED.level,
        platform=EXCLUDED.platform, total_kills=EXCLUDED.total_kills, total_wins=EXCLUDED.total_wins,
        avg_kd=EXCLUDED.avg_kd, avg_damage=EXCLUDED.avg_damage, total_rounds=EXCLUDED.total_rounds,
        win_rate=EXCLUDED.win_rate, active_members=EXCLUDED.active_members,
        stats_updated_at=NOW(), updated_at=NOW()
    `, [cleanTag, cleanName, memberCount || 0, level || 0, platform || 'psn',
        registeredBy || 'anon', totalKills, totalWins, avgKd, avgDmg, totalRounds, winRate, activeCount]);

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
app.post('/clans/request-member', async (req, res) => {
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
// POST /clans/import-pubgclans — Import a clan using pubgclans.net data + PUBG API metadata
app.post('/clans/import-pubgclans', rateLimit, async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'No database configured' });

  const { clanId, gameMode } = req.body;
  if (!clanId) return res.status(400).json({ error: 'clanId required (e.g. clan.bc03cc7f04a347ef81e48070f004283c)' });

  const mode = gameMode || 'squad';
  const headers = { 'Authorization': 'Bearer ' + SERVER_API_KEY, 'Accept': 'application/vnd.api+json' };

  try {
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

    if (!clanMeta) return res.status(404).json({ error: 'Clan not found on any platform' });
    console.log(`[import] Found clan: [${clanMeta.clanTag}] ${clanMeta.clanName} (${detectedPlatform}, level ${clanMeta.clanLevel}, ${clanMeta.clanMemberCount} members)`);

    // Step 2: Fetch member stats from pubgclans.net — try ALL game modes and merge best stats
    const gameModes = ['squad', 'squad-fpp', 'solo', 'solo-fpp', 'duo', 'duo-fpp'];
    const mergedPlayers = {}; // player_name -> best stats

    for (const gm of gameModes) {
      try {
        const pcnUrl = `https://www.pubgclans.net/includes/getClanMemberDataAjax.php?clanId=${encodeURIComponent(clanId)}&mode=unranked&gameMode=${gm}`;
        const pcnResp = await fetchWithTimeout(fetch, pcnUrl, {}, 10000);
        if (!pcnResp.ok) { console.log(`[import] pubgclans.net ${gm}: HTTP ${pcnResp.status}`); continue; }
        const pcnData = await pcnResp.json();
        if (!Array.isArray(pcnData)) continue;
        console.log(`[import] pubgclans.net ${gm}: ${pcnData.length} members`);
        pcnData.forEach(p => {
          const name = p.player_name;
          if (!name) return;
          const kills = parseInt(p.kills) || 0;
          const rounds = parseInt(p.roundsplayed) || 0;
          const wins = parseInt(p.wins) || 0;
          const damage = parseFloat(p.damagedealt) || 0;
          if (mergedPlayers[name]) {
            // Accumulate stats across game modes
            mergedPlayers[name].kills += kills;
            mergedPlayers[name].wins += wins;
            mergedPlayers[name].rounds += rounds;
            mergedPlayers[name].damage += damage;
          } else {
            mergedPlayers[name] = { kills, wins, rounds, damage };
          }
        });
      } catch (e) { console.log(`[import] pubgclans.net ${gm}: error — ${e.message}`); }
    }

    // Deduplicate by lowercase name (pubgclans.net can return same player with different casing)
    const deduped = {};
    for (const [name, stats] of Object.entries(mergedPlayers)) {
      const key = name.toLowerCase();
      if (deduped[key]) {
        // Keep the name with most kills, accumulate stats
        if (stats.kills > deduped[key].stats.kills) deduped[key].displayName = name;
        deduped[key].stats.kills += stats.kills;
        deduped[key].stats.wins += stats.wins;
        deduped[key].stats.rounds += stats.rounds;
        deduped[key].stats.damage += stats.damage;
      } else {
        deduped[key] = { displayName: name, stats: { ...stats } };
      }
    }

    const playerNames = Object.keys(deduped);
    if (playerNames.length === 0) {
      return res.status(404).json({ error: 'No member data found on pubgclans.net for this clan (tried all game modes)' });
    }
    console.log(`[import] Merged ${playerNames.length} unique members across all modes`);

    // Step 3: Transform merged data to our format
    const members = playerNames.map(key => {
      const p = deduped[key];
      const s = p.stats;
      const kd = s.rounds > 0 ? parseFloat((s.kills / s.rounds).toFixed(2)) : 0;
      return {
        name: p.displayName,
        active: s.rounds > 0,
        stats: { kills: s.kills, wins: s.wins, kd, damage: s.damage, rounds: s.rounds }
      };
    }).sort((a, b) => b.stats.kills - a.stats.kills);

    // Step 4: Register the clan (upsert)
    const payload = {
      tag: clanMeta.clanTag,
      name: clanMeta.clanName,
      memberCount: clanMeta.clanMemberCount,
      level: clanMeta.clanLevel,
      platform: detectedPlatform,
      registeredBy: 'pubgclans_import',
      members: members
    };

    // Use our own register endpoint logic inline
    const cleanTag = payload.tag.toUpperCase().replace(/[^A-Z0-9_]/g, '').slice(0, 20);
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
                         win_rate, active_members, stats_updated_at, updated_at)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,NOW(),NOW())
      ON CONFLICT (tag) DO UPDATE SET
        name=EXCLUDED.name, member_count=EXCLUDED.member_count, level=EXCLUDED.level,
        platform=EXCLUDED.platform, total_kills=EXCLUDED.total_kills, total_wins=EXCLUDED.total_wins,
        avg_kd=EXCLUDED.avg_kd, avg_damage=EXCLUDED.avg_damage, total_rounds=EXCLUDED.total_rounds,
        win_rate=EXCLUDED.win_rate, active_members=EXCLUDED.active_members,
        stats_updated_at=NOW(), updated_at=NOW()
    `, [cleanTag, payload.name, payload.memberCount, payload.level, detectedPlatform,
        'pubgclans_import', totalKills, totalWins, avgKd, avgDmg, totalRounds, winRate, activeCount]);

    // Delete old members before re-importing (prevents duplicates from casing differences)
    await pool.query('DELETE FROM clan_members WHERE clan_tag = $1', [cleanTag]);

    for (const m of members) {
      const s = m.stats;
      await pool.query(`
        INSERT INTO clan_members (clan_tag, player_name, kills, wins, kd, damage, rounds, active, added_by)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
      `, [cleanTag, m.name, s.kills, s.wins, s.kd, s.damage, s.rounds, m.active, 'pubgclans_import']);
    }

    console.log(`[import] Registered [${cleanTag}] ${payload.name}: ${members.length} members, ${totalKills} kills`);

    res.json({
      ok: true,
      tag: cleanTag,
      name: payload.name,
      platform: detectedPlatform,
      level: payload.level,
      members: members.length,
      activeMembers: activeCount,
      totalKills, totalWins, avgKd, winRate,
      url: `/clan/${cleanTag}`
    });

  } catch (e) {
    console.error('[import] Error:', e.message);
    console.error(e.message); res.status(500).json({ error: 'Error interno del servidor' });
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
        // Rate limit: wait 1s between match fetches
        if (matchesProcessed > 0) await new Promise(r => setTimeout(r, 1200));

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
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (token) {
    try { req.user = jwt.verify(token, JWT_SECRET); }
    catch (e) { req.user = null; }
  }
  next();
}

// Require auth — blocks if no valid token
function requireAuth(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'No autorizado' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch (e) { return res.status(401).json({ error: 'Token invalido' }); }
}

// Require admin — blocks if no valid admin token
function requireAdmin(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'No autorizado' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    if (decoded.role !== 'admin') return res.status(403).json({ error: 'Acceso denegado' });
    req.user = decoded;
    next();
  } catch (e) { return res.status(401).json({ error: 'Token invalido' }); }
}

function generateToken(user) {
  return jwt.sign({ id: user.id, display_name: user.display_name }, JWT_SECRET, { expiresIn: '30d' });
}

// POST /auth/register — Email + password registration
app.post('/auth/register', async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'Base de datos no disponible' });
  const { email, password, displayName, gamertag, platform } = req.body;
  if (!email || !password || !displayName) return res.status(400).json({ error: 'Email, contrasena y nombre son obligatorios' });
  if (password.length < 8) return res.status(400).json({ error: 'La contrasena debe tener al menos 8 caracteres' });
  try {
    const exists = await pool.query('SELECT id FROM users WHERE email = $1', [email.toLowerCase()]);
    if (exists.rows.length) return res.status(409).json({ error: 'Este email ya esta registrado' });
    const hash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (email, password_hash, display_name, gamertag, platform) VALUES ($1, $2, $3, $4, $5) RETURNING id, display_name, gamertag, platform',
      [email.toLowerCase(), hash, displayName.slice(0, 50), (gamertag || '').slice(0, 50), platform || 'psn']
    );
    const user = result.rows[0];
    const token = generateToken(user);
    res.json({ token, user: { id: user.id, display_name: user.display_name, gamertag: user.gamertag, platform: user.platform } });
  } catch (e) { console.error(e.message); res.status(500).json({ error: 'Error interno del servidor' }); }
});

// POST /auth/login — Email + password login
app.post('/auth/login', async (req, res) => {
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
    res.json({ token, user: { id: user.id, display_name: user.display_name, gamertag: user.gamertag, platform: user.platform } });
  } catch (e) { console.error(e.message); res.status(500).json({ error: 'Error interno del servidor' }); }
});

// GET /auth/discord — Redirect to Discord OAuth
app.get('/auth/discord', (req, res) => {
  if (!DISCORD_CLIENT_ID) return res.status(503).json({ error: 'Discord OAuth no configurado' });
  const params = new URLSearchParams({
    client_id: DISCORD_CLIENT_ID,
    redirect_uri: DISCORD_REDIRECT_URI,
    response_type: 'code',
    scope: 'identify email'
  });
  res.redirect('https://discord.com/api/oauth2/authorize?' + params.toString());
});

// GET /auth/discord/callback — Discord OAuth callback
app.get('/auth/discord/callback', async (req, res) => {
  if (!pool) return res.redirect('/#auth_error=db_unavailable');

  const { code } = req.query;
  if (!code) return res.redirect('/#auth_error=no_code');
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
    // Redirect back to app with token in URL (frontend picks it up)
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
    const result = await pool.query('SELECT id, display_name, gamertag, platform, email, discord_name, avatar_url FROM users WHERE id = $1', [req.user.id]);
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
    await pool.query('DELETE FROM user_favorites WHERE user_id = $1 AND name = $2', [req.user.id, req.params.name]);
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
  leaderboards: 30,  // Leaderboards — cache 30 min
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

app.all('/api/*', rateLimit, async (req, res) => {

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

// Cleanup old cache entries every 30 minutes
setInterval(async () => {
  if (!pool) return;
  try { await pool.query("DELETE FROM api_cache WHERE created_at < NOW() - INTERVAL '2 hours'"); }
  catch (e) { /* silent */ }
}, 1800000);

// Admin verification endpoint — password never exposed in frontend
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
app.post('/auth/admin', rateLimit, (req, res) => {
  if (!ADMIN_PASSWORD) return res.status(503).json({ error: 'Admin no configurado' });
  const { password } = req.body;
  if (password && password === ADMIN_PASSWORD) {
    const token = jwt.sign({ role: 'admin' }, JWT_SECRET, { expiresIn: '24h' });
    res.json({ ok: true, token });
  } else {
    res.status(401).json({ error: 'Contraseña incorrecta' });
  }
});

// Sitemap for SEO — dynamic with clan URLs
app.get('/sitemap.xml', async (req, res) => {
  res.set('Content-Type', 'application/xml');
  const today = new Date().toISOString().split('T')[0];
  let clanUrls = '';
  if (pool) {
    try {
      const { rows } = await pool.query('SELECT tag FROM clans WHERE active_members > 0 ORDER BY total_kills DESC LIMIT 500');
      rows.forEach(r => {
        clanUrls += `  <url><loc>https://www.v4nz.com/clan/${encodeURIComponent(r.tag)}</loc><changefreq>weekly</changefreq><priority>0.6</priority><lastmod>${today}</lastmod></url>\n`;
      });
    } catch(e) { console.error('Sitemap clan error:', e.message); }
  }
  res.send(`<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://www.v4nz.com</loc><changefreq>daily</changefreq><priority>1.0</priority><lastmod>${today}</lastmod></url>
  <url><loc>https://v4nz.com/clanes</loc><changefreq>daily</changefreq><priority>0.8</priority><lastmod>${today}</lastmod></url>
  <url><loc>https://v4nz.com/ranking</loc><changefreq>daily</changefreq><priority>0.8</priority><lastmod>${today}</lastmod></url>
  <url><loc>https://v4nz.com/top500</loc><changefreq>weekly</changefreq><priority>0.7</priority><lastmod>${today}</lastmod></url>
  <url><loc>https://v4nz.com/comparar</loc><changefreq>weekly</changefreq><priority>0.6</priority><lastmod>${today}</lastmod></url>
${clanUrls}</urlset>`);
});

// Google Search Console verification
app.get('/googlef2390246b37ad8b0.html', (req, res) => {
  res.set('Content-Type', 'text/html');
  res.send('google-site-verification: googlef2390246b37ad8b0.html');
});

// Robots.txt
app.get('/robots.txt', (req, res) => {
  res.set('Content-Type', 'text/plain');
  res.send('User-agent: *\nAllow: /\nSitemap: https://www.v4nz.com/sitemap.xml');
});

// ═══ Dynamic OG Image (SVG → PNG via sharp) ═══
function escXml(s) { return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&apos;'); }

function buildPlayerSvg(player, platform) {
  const platIcon = platform === 'PSN' ? 'PlayStation' : 'Xbox';
  return `<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="630" viewBox="0 0 1200 630">
    <defs>
      <linearGradient id="bg" x1="0" y1="0" x2="1" y2="1"><stop offset="0%" stop-color="#0b0b12"/><stop offset="100%" stop-color="#12081f"/></linearGradient>
      <linearGradient id="accent" x1="0" y1="0" x2="1" y2="0"><stop offset="0%" stop-color="#00f0ff"/><stop offset="100%" stop-color="#ff6b00"/></linearGradient>
    </defs>
    <rect width="1200" height="630" fill="url(#bg)"/>
    <rect y="0" width="1200" height="4" fill="url(#accent)"/>
    <text x="80" y="100" font-family="Arial,Helvetica,sans-serif" font-size="28" font-weight="900" fill="#00f0ff" letter-spacing="6">V4NZ</text>
    <text x="190" y="100" font-family="Arial,Helvetica,sans-serif" font-size="18" fill="#666" letter-spacing="3">PUBG CONSOLE STATS</text>
    <text x="80" y="220" font-family="Arial,Helvetica,sans-serif" font-size="72" font-weight="900" fill="#ffffff" letter-spacing="2">${escXml(player)}</text>
    <text x="80" y="280" font-family="Arial,Helvetica,sans-serif" font-size="24" fill="#888" letter-spacing="3">${platIcon}</text>
    <text x="80" y="430" font-family="Arial,Helvetica,sans-serif" font-size="20" fill="#555" letter-spacing="2">STATS EN TIEMPO REAL · K/D · WIN RATE · ADN PUBG</text>
    <text x="80" y="480" font-family="Arial,Helvetica,sans-serif" font-size="18" fill="#00f0ff" letter-spacing="1">Descubre tus estadisticas en v4nz.com</text>
    <rect x="80" y="520" width="200" height="40" rx="8" fill="#00f0ff" opacity="0.15"/>
    <text x="180" y="547" font-family="Arial,Helvetica,sans-serif" font-size="16" font-weight="700" fill="#00f0ff" text-anchor="middle" letter-spacing="2">VER STATS</text>
    <circle cx="1060" cy="315" r="120" fill="none" stroke="#00f0ff" stroke-width="2" opacity="0.15"/>
    <circle cx="1060" cy="315" r="80" fill="none" stroke="#00f0ff" stroke-width="1" opacity="0.1"/>
    <text x="1060" y="330" font-family="Arial,Helvetica,sans-serif" font-size="48" font-weight="900" fill="#00f0ff" text-anchor="middle" opacity="0.3">${escXml(player.charAt(0).toUpperCase())}</text>
  </svg>`;
}

function buildClanSvg(tag) {
  return `<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="630" viewBox="0 0 1200 630">
    <defs>
      <linearGradient id="bg" x1="0" y1="0" x2="1" y2="1"><stop offset="0%" stop-color="#0b0b12"/><stop offset="100%" stop-color="#12081f"/></linearGradient>
      <linearGradient id="accent" x1="0" y1="0" x2="1" y2="0"><stop offset="0%" stop-color="#00f0ff"/><stop offset="100%" stop-color="#ff6b00"/></linearGradient>
    </defs>
    <rect width="1200" height="630" fill="url(#bg)"/>
    <rect y="0" width="1200" height="4" fill="url(#accent)"/>
    <text x="80" y="100" font-family="Arial,Helvetica,sans-serif" font-size="28" font-weight="900" fill="#00f0ff" letter-spacing="6">V4NZ</text>
    <text x="190" y="100" font-family="Arial,Helvetica,sans-serif" font-size="18" fill="#666" letter-spacing="3">PUBG CONSOLE STATS</text>
    <text x="80" y="200" font-family="Arial,Helvetica,sans-serif" font-size="24" fill="#ff6b00" letter-spacing="3">CLAN</text>
    <text x="80" y="300" font-family="Arial,Helvetica,sans-serif" font-size="96" font-weight="900" fill="#ffffff" letter-spacing="4">[${escXml(tag)}]</text>
    <text x="80" y="430" font-family="Arial,Helvetica,sans-serif" font-size="20" fill="#555" letter-spacing="2">MIEMBROS · KILLS · K/D · RANKING</text>
    <text x="80" y="480" font-family="Arial,Helvetica,sans-serif" font-size="18" fill="#00f0ff" letter-spacing="1">Ver estadisticas del clan en v4nz.com</text>
    <rect x="80" y="520" width="200" height="40" rx="8" fill="#ff6b00" opacity="0.15"/>
    <text x="180" y="547" font-family="Arial,Helvetica,sans-serif" font-size="16" font-weight="700" fill="#ff6b00" text-anchor="middle" letter-spacing="2">VER CLAN</text>
  </svg>`;
}

async function svgToPng(svgStr) {
  if (!sharp) return null;
  return sharp(Buffer.from(svgStr)).png().toBuffer();
}

// Player OG image — PNG preferred, SVG fallback
app.get('/og-image/stats/:platform/:player.png', async (req, res) => {
  try {
    const platform = req.params.platform.toUpperCase();
    const player = decodeURIComponent(req.params.player);
    const svg = buildPlayerSvg(player, platform);
    const png = await svgToPng(svg);
    if (png) {
      res.set('Content-Type', 'image/png');
      res.set('Cache-Control', 'public, max-age=3600');
      return res.send(png);
    }
    // Fallback to SVG if sharp not available
    res.set('Content-Type', 'image/svg+xml');
    res.set('Cache-Control', 'public, max-age=3600');
    res.send(svg);
  } catch (e) {
    console.error('OG image error:', e.message);
    res.status(500).send('Error generating image');
  }
});

// Clan OG image — PNG preferred, SVG fallback
app.get('/og-image/clan/:tag.png', async (req, res) => {
  try {
    const tag = decodeURIComponent(req.params.tag).toUpperCase();
    const svg = buildClanSvg(tag);
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

// Fallback: serve index.html for SPA routes with dynamic meta tags
app.get('*', (req, res) => {
  const statsMatch = req.path.match(/^\/stats\/(psn|xbox)\/(.+)$/i);
  const clanMatch = req.path.match(/^\/clan\/(.+)$/i);

  // Map SPA paths to SEO titles/descriptions for crawlers
  const spaPages = {
    '/clanes': { title: 'Clanes PUBG Consola — Busca y Compara | V4NZ', desc: 'Busca clanes de PUBG en PlayStation y Xbox. Compara estadísticas, miembros, kills y ranking entre clanes.' },
    '/ranking': { title: 'Ranking de Clanes PUBG — Top Clanes Consola | V4NZ', desc: 'Ranking de los mejores clanes de PUBG en consola. Clasificación por kills, K/D, victorias y más.' },
    '/top500': { title: 'Top 500 PUBG Consola — Leaderboard Oficial | V4NZ', desc: 'Top 500 jugadores de PUBG en PlayStation y Xbox. Leaderboard oficial con stats en tiempo real.' },
    '/comparar': { title: 'Comparar Jugadores PUBG — Stats vs Stats | V4NZ', desc: 'Compara estadísticas de dos jugadores de PUBG en consola. K/D, victorias, daño, headshots y más cara a cara.' }
  };

  try {
    let html = fs.readFileSync(path.join(__dirname, 'index.html'), 'utf8');
    let title, desc, canonicalUrl, ogImage;

    if (statsMatch) {
      const platform = statsMatch[1].toUpperCase();
      const playerName = decodeURIComponent(statsMatch[2]);
      title = `${playerName} — Stats PUBG ${platform} | V4NZ`;
      desc = `Estadísticas de ${playerName} en PUBG ${platform}. K/D, victorias, partidas, daño y más. Datos en tiempo real via PUBG API.`;
      canonicalUrl = `https://v4nz.com/stats/${statsMatch[1].toLowerCase()}/${encodeURIComponent(playerName)}`;
      ogImage = `https://www.v4nz.com/og-image/stats/${statsMatch[1].toLowerCase()}/${encodeURIComponent(playerName)}.png`;
    } else if (clanMatch) {
      const clanTag = decodeURIComponent(clanMatch[1]).toUpperCase();
      title = `Clan [${clanTag}] — PUBG Stats Consola | V4NZ`;
      desc = `Estadísticas del clan ${clanTag} en PUBG consola. Miembros, kills, K/D medio, victorias y ranking.`;
      canonicalUrl = `https://www.v4nz.com/clan/${encodeURIComponent(clanTag)}`;
      ogImage = `https://www.v4nz.com/og-image/clan/${encodeURIComponent(clanTag)}.png`;
    } else if (spaPages[req.path]) {
      title = spaPages[req.path].title;
      desc = spaPages[req.path].desc;
      canonicalUrl = `https://v4nz.com${req.path}`;
    }

    if (title) {
      html = html
        .replace(/<title>[^<]*<\/title>/, `<title>${title}</title>`)
        .replace(/<meta property="og:title"[^>]*>/, `<meta property="og:title" content="${title}">`)
        .replace(/<meta property="og:description"[^>]*>/, `<meta property="og:description" content="${desc}">`)
        .replace(/<meta name="twitter:title"[^>]*>/, `<meta name="twitter:title" content="${title}">`)
        .replace(/<meta name="twitter:description"[^>]*>/, `<meta name="twitter:description" content="${desc}">`)
        .replace(/<meta name="description"[^>]*>/, `<meta name="description" content="${desc}">`);
      if (canonicalUrl) {
        html = html
          .replace(/<meta property="og:url"[^>]*>/, `<meta property="og:url" content="${canonicalUrl}">`)
          .replace(/<link rel="canonical"[^>]*>/, `<link rel="canonical" href="${canonicalUrl}">`);
      }
      if (ogImage) {
        html = html
          .replace(/<meta property="og:image" content="[^"]*">/, `<meta property="og:image" content="${ogImage}">`)
          .replace(/<meta name="twitter:image" content="[^"]*">/, `<meta name="twitter:image" content="${ogImage}">`);
      }
    }
    res.set('Content-Type', 'text/html');
    res.send(html);
  } catch (e) {
    res.sendFile(path.join(__dirname, 'index.html'));
  }
});

// ═══ START ═══
initDB().then(() => {
  app.listen(PORT, () => {
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
  });
});
