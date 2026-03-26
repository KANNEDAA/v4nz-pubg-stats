// ═══════════════════════════════════════════════
//  V4NZ PUBG Stats — Server + Clan API
//  Proxy PUBG API + PostgreSQL clan system
// ═══════════════════════════════════════════════

const express = require('express');
const cors = require('cors');
const path = require('path');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3000;
const SERVER_API_KEY = process.env.PUBG_API_KEY || '';

// PostgreSQL connection (Railway provides DATABASE_URL automatically)
const pool = process.env.DATABASE_URL ? new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
}) : null;

app.use(cors());
app.use(express.json());
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
        avg_kd NUMERIC(5,2) DEFAULT 0,
        avg_damage NUMERIC(7,1) DEFAULT 0,
        total_rounds INT DEFAULT 0,
        win_rate NUMERIC(5,2) DEFAULT 0,
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
        kd NUMERIC(5,2) DEFAULT 0,
        damage NUMERIC(7,1) DEFAULT 0,
        rounds INT DEFAULT 0,
        active BOOLEAN DEFAULT true,
        added_by VARCHAR(50),
        created_at TIMESTAMPTZ DEFAULT NOW(),
        UNIQUE(clan_tag, player_name)
      );
      CREATE INDEX IF NOT EXISTS idx_clan_members_tag ON clan_members(clan_tag);
      CREATE INDEX IF NOT EXISTS idx_clans_kills ON clans(total_kills DESC);
      CREATE INDEX IF NOT EXISTS idx_clans_kd ON clans(avg_kd DESC);
    `);
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
      winrate: 'win_rate DESC', members: 'active_members DESC', rounds: 'total_rounds DESC'
    };
    const order = orderMap[sort] || 'total_kills DESC';
    const { rows } = await pool.query(
      `SELECT tag, name, member_count, level, platform, total_kills, total_wins,
              avg_kd, avg_damage, total_rounds, win_rate, active_members,
              stats_updated_at, created_at
       FROM clans WHERE active_members > 0 ORDER BY ${order} LIMIT $1`, [limit]
    );
    res.json({ clans: rows, total: rows.length });
  } catch (e) { res.status(500).json({ error: e.message }); }
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
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// POST /clans/register — Register or update a clan with member stats
app.post('/clans/register', async (req, res) => {
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
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// GET /clans/search/:query — Search clans by name or tag
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
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ═══ AUTO-DISCOVER CLAN MEMBERS FROM MATCHES ═══
// POST /clans/discover-members — Given one gamertag, find frequent teammates
app.post('/clans/discover-members', async (req, res) => {
  const fetch = (...args) => import('node-fetch').then(({default: f}) => f(...args));
  const { gamertag, platform } = req.body;
  if (!gamertag || !platform) return res.status(400).json({ error: 'gamertag and platform required' });
  if (!SERVER_API_KEY) return res.status(503).json({ error: 'No API key configured on server' });

  const shard = platform; // xbox, psn, steam, etc.
  const headers = { 'Authorization': 'Bearer ' + SERVER_API_KEY, 'Accept': 'application/vnd.api+json' };

  try {
    // Step 1: Look up the player to get their account ID and recent matches
    console.log(`[discover] Looking up player: ${gamertag} on ${shard}`);
    const playerResp = await fetch(
      `https://api.pubg.com/shards/${shard}/players?filter[playerNames]=${encodeURIComponent(gamertag)}`,
      { headers }
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
        const matchResp = await fetch(`https://api.pubg.com/shards/${shard}/matches/${matchId}`, { headers });
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
    res.status(500).json({ error: e.message });
  }
});

// ═══ PUBG API PROXY ═══
app.all('/api/*', async (req, res) => {
  const fetch = (...args) => import('node-fetch').then(({default: f}) => f(...args));
  const originalQuery = req.originalUrl.split('?')[1] || '';
  const pubgPath = req.params[0];
  const pubgUrl = `https://api.pubg.com/${pubgPath}${originalQuery ? '?' + originalQuery : ''}`;

  const apiKey = SERVER_API_KEY ? 'Bearer ' + SERVER_API_KEY : req.headers.authorization;
  if (!apiKey) return res.status(401).json({ error: 'Missing API Key' });

  try {
    const response = await fetch(pubgUrl, {
      method: req.method,
      headers: { 'Authorization': apiKey, 'Accept': 'application/vnd.api+json' },
    });
    const data = await response.text();
    res.status(response.status);
    res.set('Content-Type', 'application/vnd.api+json');
    res.send(data);
  } catch (err) {
    console.error('Proxy error:', err.message);
    res.status(500).json({ error: 'Proxy error', details: err.message });
  }
});

// Fallback: serve index.html for SPA routes (/clan/*, /stats/*, etc.)
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
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
