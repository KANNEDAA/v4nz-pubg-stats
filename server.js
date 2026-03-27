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
    `);
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

// GET /clans/requests/pending — Admin: list pending requests (MUST be before :tag wildcard)
app.get('/clans/requests/pending', async (req, res) => {
  if (!pool) return res.json({ requests: [] });
  try {
    const { rows } = await pool.query(
      `SELECT id, clan_tag, player_name, requested_by, created_at
       FROM member_requests WHERE status = 'pending' ORDER BY created_at DESC LIMIT 50`
    );
    res.json({ requests: rows });
  } catch (e) { res.status(500).json({ error: e.message }); }
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

// ═══ MEMBER REQUEST SYSTEM ═══
// POST /clans/request-member — Public: request to add a player to a clan (admin reviews)
app.post('/clans/request-member', async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'No database configured' });
  try {
    const { clanTag, playerName, requestedBy } = req.body;
    if (!clanTag || !playerName) return res.status(400).json({ error: 'clanTag and playerName required' });
    const cleanTag = clanTag.toUpperCase().replace(/[^A-Z0-9_]/g, '').slice(0, 20);
    const cleanName = playerName.trim().slice(0, 50);
    // Check if player already exists in clan
    const existing = await pool.query('SELECT id FROM clan_members WHERE clan_tag = $1 AND player_name = $2', [cleanTag, cleanName]);
    if (existing.rows.length) return res.json({ ok: true, message: 'Este jugador ya esta en el clan' });
    // Check for duplicate pending request
    await pool.query(`
      INSERT INTO member_requests (clan_tag, player_name, requested_by)
      VALUES ($1, $2, $3)
      ON CONFLICT (clan_tag, player_name, status) DO NOTHING
    `, [cleanTag, cleanName, requestedBy || 'web_user']);
    console.log(`[request] New member request: ${cleanName} -> [${cleanTag}]`);
    res.json({ ok: true, message: 'Solicitud enviada correctamente' });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// POST /clans/requests/:id/approve — Admin: approve a member request
app.post('/clans/requests/:id/approve', async (req, res) => {
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
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// POST /clans/requests/:id/reject — Admin: reject a member request
app.post('/clans/requests/:id/reject', async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'No database' });
  try {
    await pool.query("UPDATE member_requests SET status = 'rejected', reviewed_at = NOW() WHERE id = $1", [parseInt(req.params.id)]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ═══ IMPORT CLAN FROM PUBGCLANS.NET ═══
// POST /clans/import-pubgclans — Import a clan using pubgclans.net data + PUBG API metadata
app.post('/clans/import-pubgclans', async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'No database configured' });
  const fetch = (...args) => import('node-fetch').then(({default: f}) => f(...args));
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
        const clanResp = await fetch(`https://api.pubg.com/shards/${shard}/clans/${clanId}`, { headers });
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
        const pcnResp = await fetch(pcnUrl);
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
    res.status(500).json({ error: e.message });
  }
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

// Sitemap for SEO
app.get('/sitemap.xml', (req, res) => {
  res.set('Content-Type', 'application/xml');
  res.send(`<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://v4nz.com</loc><changefreq>daily</changefreq><priority>1.0</priority></url>
  <url><loc>https://v4nz.com/clanes</loc><changefreq>daily</changefreq><priority>0.8</priority></url>
  <url><loc>https://v4nz.com/ranking</loc><changefreq>daily</changefreq><priority>0.8</priority></url>
  <url><loc>https://v4nz.com/top500</loc><changefreq>daily</changefreq><priority>0.7</priority></url>
</urlset>`);
});

// Robots.txt
app.get('/robots.txt', (req, res) => {
  res.set('Content-Type', 'text/plain');
  res.send('User-agent: *\nAllow: /\nSitemap: https://v4nz.com/sitemap.xml');
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
