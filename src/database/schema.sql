-- LIDRA v2 Database Schema

CREATE TABLE IF NOT EXISTS attackers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT UNIQUE NOT NULL,
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    attack_count INTEGER DEFAULT 1,
    threat_score INTEGER DEFAULT 0,
    country TEXT,
    org TEXT
);

CREATE TABLE IF NOT EXISTS attacks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    attacker_id INTEGER NOT NULL,
    attack_type TEXT NOT NULL,
    source_log TEXT,
    raw_line TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (attacker_id) REFERENCES attackers(id)
);

CREATE TABLE IF NOT EXISTS blocks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT NOT NULL,
    reason TEXT,
    block_until TIMESTAMP,
    applied INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS honeyfile_hits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_path TEXT NOT NULL,
    ip_address TEXT,
    event_type TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS honeypot_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT UNIQUE,
    ip_address TEXT NOT NULL,
    port INTEGER,
    start_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    end_time TIMESTAMP,
    commands TEXT,
    status TEXT DEFAULT 'active'
);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    ip_address TEXT,
    message TEXT NOT NULL,
    sent INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_attackers_ip ON attackers(ip_address);
CREATE INDEX IF NOT EXISTS idx_attacks_timestamp ON attacks(timestamp);
CREATE INDEX IF NOT EXISTS idx_blocks_until ON blocks(block_until);
