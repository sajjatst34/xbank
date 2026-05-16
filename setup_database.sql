-- ============================================================
-- X Bank - MySQL Database Setup Script
-- Run this in phpMyAdmin or MySQL CLI before starting Django
-- ============================================================

-- Create the database
CREATE DATABASE IF NOT EXISTS xbank_db
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE xbank_db;

-- Grant privileges to root (XAMPP default)
-- If using a different user, update accordingly:
GRANT ALL PRIVILEGES ON xbank_db.* TO 'root'@'localhost';
FLUSH PRIVILEGES;

-- ============================================================
-- NOTE: Django will auto-create all tables via migrations.
-- Just run:  python manage.py migrate
-- This script only creates the database itself.
-- ============================================================

-- Verify creation
SHOW DATABASES LIKE 'xbank_db';
SELECT 'xbank_db created successfully!' AS status;
