-- SQLite

SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';
SELECT * FROM users;