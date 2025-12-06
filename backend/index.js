require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');
const cors = require('cors');

const app = express();

// Basic request logging (Non-sensitive)
app.use((req, res, next) => {
  console.log(`[REQ] ${req.method} ${req.url}`);
  next();
});

app.use(express.json());

app.use(
  cors({
    origin: 'http://localhost:3000',
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
  })
);

app.use(express.json());


// --- Config from .env ---
// Prefer a backend port different from React dev server, e.g. 3001
const PORT = process.env.PORT || 3001;
const REGION = process.env.COGNITO_REGION;
const USER_POOL_ID = process.env.COGNITO_USER_POOL_ID;
const CLIENT_ID = process.env.COGNITO_CLIENT_ID; // optional

if (!REGION || !USER_POOL_ID) {
  console.error('Missing COGNITO_REGION or COGNITO_USER_POOL_ID in .env');
  process.exit(1);
}

// --- JWKS client for Cognito ---
const client = jwksClient({
  jwksUri: `https://cognito-idp.${REGION}.amazonaws.com/${USER_POOL_ID}/.well-known/jwks.json`,
});

// Helper to get signing key for JWT verification
function getKey(header, callback) {
  client.getSigningKey(header.kid, function (err, key) {
    if (err) {
      return callback(err);
    }
    const signingKey = key.getPublicKey();
    callback(null, signingKey);
  });
}

// --- Auth middleware: verifies JWT and attaches payload to req.user ---
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'] || '';
  const token = authHeader.startsWith('Bearer ')
    ? authHeader.substring('Bearer '.length)
    : null;

  if (!token) {
    console.warn('[AUTH] Missing token');
    return res.status(401).json({ error: 'Missing Authorization: Bearer <token>' });
  }

  const issuer = `https://cognito-idp.${REGION}.amazonaws.com/${USER_POOL_ID}`;

  jwt.verify(
    token,
    getKey,
    {
      algorithms: ['RS256'],
      issuer,
    },
    (err, decoded) => {
      if (err) {
        console.warn('[AUTH] JWT verification error:', err.message);
        return res.status(401).json({ error: 'Invalid or expired token' });
      }

      if (
        CLIENT_ID &&
        ((decoded.client_id && decoded.client_id !== CLIENT_ID) ||
          (decoded.aud && decoded.aud !== CLIENT_ID))
      ) {
        console.warn('[AUTH] Wrong audience/client_id');
        return res.status(401).json({ error: 'Token not issued for this client' });
      }

      // Resolve role + device_id here
      const groups = decoded['cognito:groups'] || [];
      const role = groups.includes('admin')
        ? 'admin'
        : groups.includes('user')
        ? 'user'
        : 'unknown';

      req.user = decoded;
      req.resolvedClaims = {
        role,
        device_id: decoded['custom:device_id'] || null,
      };

      console.log(
        `[AUTH] OK sub=${decoded.sub}, role=${req.resolvedClaims.role}, device_id=${req.resolvedClaims.device_id}`
      );

      next();
    }
  );
}


// --- Routes ---
app.get('/', (req, res) => {
  return res.json({
    message: 'Hello world. Use /api/profile or /api/data endpoints.',
    payload: req.user,
  });
});


app.get('/api/profile', authenticateToken, (req, res) => {
  return res.json(req.resolvedClaims); // e.g. { role: "admin" } or { role: "user", device_id: "A1" }
});

// 2) /api/data -> behaviour based on role + custom:device_id
app.get('/api/data', authenticateToken, (req, res) => {
  const { role, device_id } = req.resolvedClaims;

  // TODO: Fetch from Blob/S3 and filter based on role/device_id
  const allData = [
    { device_id: 'E-001', value: 10 },
    { device_id: 'E-002', value: 20 },
  ];

  let visibleData;

  if (role === 'admin') {
    // Admin: all devices
    visibleData = allData;
  } else if (role === 'user') {
    if (!device_id) {
      console.warn('[AUTHZ] User has no device_id');
      return res.status(403).json({ error: 'No device_id associated with this account' });
    }
    // User: only their device
    visibleData = allData.filter((d) => d.device_id === device_id);
  } else {
    console.warn('[AUTHZ] Unknown role');
    return res.status(403).json({ error: 'Insufficient permissions' });
  }

  return res.json({
    role,
    device_id,
    data: visibleData,
  });
});


// --- Start server ---
app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});
