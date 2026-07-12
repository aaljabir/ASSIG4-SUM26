'use strict';

/*
 * CampusSwap - database layer (STARTER / VULNERABLE build)
 * -------------------------------------------------------
 * NOTE FOR STUDENTS:
 *   This build stores passwords in PLAINTEXT and the queries in server.js
 *   are built with string concatenation. Both are deliberate. You will
 *   change them as part of Assignment 4.
 */

const path = require('path');
const fs = require('fs');
const Database = require('better-sqlite3');

const DATA_DIR = path.join(__dirname, 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

const DB_PATH = path.join(DATA_DIR, 'campusswap.db');
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');

function createSchema() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id        INTEGER PRIMARY KEY AUTOINCREMENT,
      username  TEXT UNIQUE NOT NULL,
      password  TEXT NOT NULL,          -- plaintext in this build (intentional)
      credits   INTEGER NOT NULL DEFAULT 100,
      is_admin  INTEGER NOT NULL DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS items (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      title       TEXT NOT NULL,
      description TEXT NOT NULL,
      price       INTEGER NOT NULL,
      seller_id   INTEGER NOT NULL,
      FOREIGN KEY (seller_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS comments (
      id        INTEGER PRIMARY KEY AUTOINCREMENT,
      item_id   INTEGER NOT NULL,
      author    TEXT NOT NULL,
      body      TEXT NOT NULL,
      created   TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY (item_id) REFERENCES items(id)
    );

    CREATE TABLE IF NOT EXISTS transfers (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      from_user   TEXT NOT NULL,
      to_user     TEXT NOT NULL,
      amount      INTEGER NOT NULL,
      created     TEXT NOT NULL DEFAULT (datetime('now'))
    );
  `);
}

function seed() {
  createSchema();
  db.exec(`DELETE FROM transfers; DELETE FROM comments; DELETE FROM items; DELETE FROM users;
           DELETE FROM sqlite_sequence;`);

  const insUser = db.prepare(
    'INSERT INTO users (username, password, credits, is_admin) VALUES (?, ?, ?, ?)'
  );
  // Regular demo accounts (share these with graders in your README if you like).
  insUser.run('alice', 'sunshine22', 500, 0);
  insUser.run('bob', 'hunter2!', 320, 0);
  insUser.run('mallory', 'letmein123', 40, 0);
  // Hidden high-value account. Students should NOT be told this password;
  // they recover it through SQL injection on /search.
  insUser.run('quartermaster', 'Gr@nite-Ferry-71', 9999, 1);

  const insItem = db.prepare(
    'INSERT INTO items (title, description, price, seller_id) VALUES (?, ?, ?, ?)'
  );
  insItem.run('Graphing Calculator (TI-84)', 'Barely used, all buttons work. Great for CYSE labs.', 45, 1);
  insItem.run('Mini Fridge', 'Dorm-sized, quiet. Pickup near Fenwick Library.', 60, 2);
  insItem.run('Mechanical Keyboard', 'Brown switches, USB-C. Perfect for late-night coding.', 55, 1);
  insItem.run('Intro to Cybersecurity (textbook)', '4th edition, minimal highlighting.', 30, 3);

  const insComment = db.prepare(
    'INSERT INTO comments (item_id, author, body) VALUES (?, ?, ?)'
  );
  insComment.run(1, 'bob', 'Does it come with the charging cable?');
  insComment.run(1, 'alice', 'Yes it does! Comes with the original cable.');
  insComment.run(2, 'mallory', 'Would you take 50 credits for it?');

  console.log('Seeded database at', DB_PATH);
}

if (require.main === module && process.argv.includes('--seed')) {
  seed();
  db.close();
}

module.exports = { db, seed, createSchema };
