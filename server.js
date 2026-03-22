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
//  La web se sirve automáticamente desde este servidor
//  y las peticiones a /api/* se redirigen a la API de PUBG
// ═══════════════════════════════════════════════

const express = require('express');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

// Serve static files (index.html, etc.)
app.use(express.static(path.join(__dirname)));

// ═══ PROXY: /api/* → https://api.pubg.com/* ═══
app.all('/api/*', async (req, res) => {
  // Dynamic import for node-fetch (ESM)
  const fetch = (...args) => import('node-fetch').then(({default: f}) => f(...args));

  const pubgPath = req.params[0]; // everything after /api/
  const queryString = new URLSearchParams(req.query).toString();
  const pubgUrl = `https://api.pubg.com/${pubgPath}${queryString ? '?' + queryString : ''}`;

  // Forward the Authorization header from the client
  const apiKey = req.headers.authorization;
  if (!apiKey) {
    return res.status(401).json({ error: 'Missing Authorization header' });
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
  ╔═══════════════════════════════════════════╗
  ║   V4NZ PUBG Stats Server                 ║
  ║   Running on http://localhost:${PORT}        ║
  ║                                           ║
  ║   Open your browser and start tracking!   ║
  ╚═══════════════════════════════════════════╝
  `);
});
