"use strict";

const { ConflictError, NotFoundError } = require('../expressError');
const bcrypt = require('bcrypt');
const { BCRYPT_WORK_FACTOR } = require('../config');

/** User of the site. */

class User {

  /** Register new user. Returns
   *    {username, password, first_name, last_name, phone}
   */

  static async register({ username, password, first_name, last_name, phone }) {
    const existingUser = await db.query(
      `SELECT username
       FROM users
       WHERE username ILIKE $1`,
      [username]
    );

    if (existingUser.rows[0]) {
      throw new ConflictError("Username already taken.");
    }

    const hashedPassword = await bcrypt.hash(password, BCRYPT_WORK_FACTOR);

    const newUser = await db.query(
      `INSERT INTO users (username, password, first_name, last_name, phone)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING username, password, first_name, last_name, phone`,
      [username, hashedPassword, first_name, last_name, phone]
    );

    const newUserData = newUser.rows[0];

    return { newUserData };
  }

  /** Authenticate: is username/password valid? Returns boolean. */

  static async authenticate(username, password) {

    const results = await db.query(
      `SELECT password
       FROM users
       WHERE username = $1`,
      [username]
    );

    if (!results.rows[0]) {
      return false;
    }

    const userPassword = results.rows[0].password;

    return await bcrypt.compare(password, userPassword);

  }

  /** Update last_login_at for user */

  static async updateLoginTimestamp(username) {

    await db.query(
      `UPDATE users
        SET last_login_at
        VALUES current_timestamp
        WHERE username = $1`,
      [username]);

  }

  /** All: basic info on all users:
   * [{username, first_name, last_name}, ...] */

  static async all() {

    const allUserQuery = await db.query(
      `SELECT username, first_name, last_name
      FROM users`
    );

    return allUserQuery.rows;
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
      `SELECT password
       FROM users
       WHERE username = $1`,
      [username]
    );

    if (!results.rows[0]) {
      throw new NotFoundError(`Username ${username} doesn't exist.`);
    }

    const userQuery = await db.query(
      `SELECT username, first_name, last_name, phone, join_at, last_login_at
      FROM users
      WHERE username = $1`,
      [username]
    );

    return userQuery.rows[0];
  }

  /** Return messages from this user.
   *
   * [{id, to_user, body, sent_at, read_at}]
   *
   * where to_user is
   *   {username, first_name, last_name, phone}
   */

  static async messagesFrom(username) {
  }

  /** Return messages to this user.
   *
   * [{id, from_user, body, sent_at, read_at}]
   *
   * where from_user is
   *   {username, first_name, last_name, phone}
   */

  static async messagesTo(username) {
  }
}


module.exports = User;
