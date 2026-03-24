// ═══════════════════════════════════════════════
//  V4NZ PUBG Stats — Proxy Server
//  Evita restricciones CORS de la API de PUBG
// ═══════════════════════════════════════════════
//
//  USO:
//    1. npm install express cors node-fetch
//    2. node server.js
//    3. Abre http://localhost:3000
//
//  En Railway: configurar PUBG_API_KEY como variable de entorno
//
// ═══════════════════════════════════════════════

const express = require('express');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// API Key: primero busca en variables de entorno (seguro), luego en header del cliente (fallback)
const SERVER_API_KEY = process.env.PUBG_API_KEY || '';

app.use(cors());
app.use(express.json());

// Serve static files (index.html, etc.)
app.use(express.static(path.join(__dirname)));

// ═══ PROXY: /api/* → https://api.pubg.com/* ═══
app.all('/api/*', async (req, res) => {
  // Dynamic import for node-fetch (ESM)
  const fetch = (...args) => import('node-fetch').then(({default: f}) => f(...args));

  // Use original URL to preserve query params like filter[playerNames] exactly
  const originalQuery = req.originalUrl.split('?')[1] || '';
  const pubgPath = req.params[0]; // everything after /api/
  const pubgUrl = `https://api.pubg.com/${pubgPath}${originalQuery ? '?' + originalQuery : ''}`;

  // Use server-side key if available, otherwise forward client header
  const apiKey = SERVER_API_KEY ? 'Bearer ' + SERVER_API_KEY : req.headers.authorization;
  if (!apiKey) {
    return res.status(401).json({ error: 'Missing API Key. Set PUBG_API_KEY env variable or send Authorization header.' });
  }

  try {
    const response = await fetch(pubgUrl, {
      method: req.method,
      headers: {
        'Authorization': apiKey,
        'Accept': 'application/vnd.api+json',
      },
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

// Fallback: serve index.html for any other route
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, () => {
  console.log(`
╔═══════════════════════════════════════════════╗
║  V4NZ PUBG Stats Server                      ║
║  Running on http://localhost:${PORT}             ║
║                                               ║
║  API Key: ${SERVER_API_KEY ? 'CONFIGURADA ✓' : 'NO CONFIGURADA ✗ (usa PUBG_API_KEY)'}
║  Open your browser and start tracking!        ║
╚═══════════════════════════════════════════════╝
  `);
});
