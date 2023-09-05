/** User class for message.ly */

const db = require("../db");
const ExpressError = require("../expressError");
const bcrypt = require("bcrypt");

/** User of the site. */

class User {
  constructor({ username, password, first_name, last_name, phone, join_at }) {
    this.username = username;
    this.password = password;
    this.first_name = first_name;
    this.last_name = last_name;
    this.phone = phone;
    this.join_at = join_at;
    this.last_login_at;
  }

  /** register new user -- returns
   *    {username, password, first_name, last_name, phone}
   */

  static async register({ username, password, first_name, last_name, phone }) {
    const timestamp = new Date();
    const hashedPassword = await bcrypt.hash(password, 12);
    const results = await db.query(
      `INSERT INTO users
        (username, password, first_name, last_name, phone, join_at)
        VALUES ($1, $2, $3, $4, $5, $6,)
        RETURNING username, password, first_name, last_name, phone, join_at`,
      [username, hashedPassword, first_name, last_name, phone, timestamp]
    );
    const newUser = new User(results.rows[0]);
    return newUser.rows[0];
  }

  /** Authenticate: is this username/password valid? Returns boolean. */

  static async authenticate(username, password) {
    const user = await db.query(
      `SELECT username, password FROM users WHERE username=$1`,
      [username]
    );
    const userPass = user.rows[0].password;
    if (await bcrypt.compare(password, userPass)) {
      return true;
    }
    return false;
  }

  /** Update last_login_at for user */

  async updateLoginTimestamp() {
    const timestamp = new Date();
    await db.query(`UPDATE users SET last_login_at=$1 WHERE username=$2`, [
      timestamp,
      this.username,
    ]);
    this.last_login_at = timestamp;
  }

  /** All: basic info on all users:
   * [{username, first_name, last_name, phone}, ...] */

  static async all() {
    const results = await db.query(
      `SELECT username, first_name, last_name, phone FROM users`
    );
    return results.rows;
  }

  /** Get: get user by username
   *
   * returns {username,
   *          first_name,
   *          last_name,
   *          phone,
   *          join_at,
   *          last_login_at } */

  static async get(username) {
    const results = await db.query(
      `SELECT username, first_name, last_name, phone, join_at, last_login_at 
        FROM users WHERE username=$1`,
      [username]
    );
    return results.rows[0];
  }

  /** Return messages from this user.
   *
   * [{id, to_user, body, sent_at, read_at}]
   *
   * where to_user is
   *   {username, first_name, last_name, phone}
   */

  async messagesFrom() {
    const results = await db.query(
      `SELECT m.id, m.to_username, m.body, m.sent_at, m.read_at, u.first_name, u.last_name, u.phone
        FROM messages AS m
        JOIN users AS u ON m.to_username = u.username
        WHERE m.from_username=$1`,
      [this.username]
    );
    return results.rows.map((row) => {
      return {
        id: row.id,
        to_user: {
          username: row.to_username,
          first_name: row.first_name,
          last_name: row.last_name,
          phone: row.phone,
        },
        body: row.body,
        sent_at: row.sent_at,
        read_at: row.read_at,
      };
    });
  }

  /** Return messages to this user.
   *
   * [{id, from_user, body, sent_at, read_at}]
   *
   * where from_user is
   *   {username, first_name, last_name, phone}
   */

  async messagesTo() {
    const results = await db.query(
      `SELECT m.id, m.from_username, m.body, m.sent_at, m.read_at, u.first_name, u.last_name, u.phone
        FROM messages AS m
        JOIN users AS u ON m.from_username = u.username
        WHERE m.to_username=$1`,
      [this.username]
    );
    return results.rows.map((row) => {
      return {
        id: row.id,
        from_user: {
          username: row.from_username,
          first_name: row.first_name,
          last_name: row.last_name,
          phone: row.phone,
        },
        body: row.body,
        sent_at: row.sent_at,
        read_at: row.read_at,
      };
    });
  }
}

module.exports = User;
