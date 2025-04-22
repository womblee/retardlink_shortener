-- Create the database (if not exists)
CREATE DATABASE IF NOT EXISTS retard_link;
USE retard_link;

-- Create the links table
CREATE TABLE IF NOT EXISTS links (
    id INT AUTO_INCREMENT PRIMARY KEY,
    original_url TEXT NOT NULL,
    short_code VARCHAR(32) NOT NULL,
    password VARCHAR(255) DEFAULT NULL,
    access_key VARCHAR(255) DEFAULT NULL,
    clicks INT DEFAULT 0,
    created_at DATETIME NOT NULL,
    last_accessed DATETIME DEFAULT NULL,
    UNIQUE KEY (short_code)
);

-- Create rate limits table
CREATE TABLE IF NOT EXISTS rate_limits (
    ip_address VARCHAR(45) NOT NULL, -- Supports both IPv4 and IPv6
    action VARCHAR(20) NOT NULL,     -- e.g., 'create', 'delete', 'change'
    request_count INT DEFAULT 0,
    last_request TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (ip_address, action)
);

-- Create index for faster lookups
CREATE INDEX idx_short_code ON links(short_code);