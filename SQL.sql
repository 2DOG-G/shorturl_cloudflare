CREATE TABLE IF NOT EXISTS links (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  short_code TEXT UNIQUE NOT NULL,
  original_url TEXT NOT NULL,
  password_hash TEXT,
  expires_at TEXT,
  domain TEXT,
  created_at TEXT DEFAULT (datetime('now'))
);