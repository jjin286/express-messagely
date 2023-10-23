"use strict";

const { ConflictError, NotFoundError } = require('../expressError');
const bcrypt = require('bcrypt');
const { BCRYPT_WORK_FACTOR } = require('../config');
const db = require("../db");

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
      `INSERT INTO users (username, password, first_name, last_name, phone, join_at, last_login_at)
       VALUES ($1, $2, $3, $4, $5, current_timestamp, current_timestamp)
       RETURNING username, password, first_name, last_name, phone`,
      [username, hashedPassword, first_name, last_name, phone]
    );

    const newUserData = newUser.rows[0];
    
    return  newUserData;
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
        SET last_login_at = current_timestamp
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

    const results = await db.query(
      `SELECT password
       FROM users
       WHERE username = $1`,
      [username]
    );

    if (!results.rows[0]) {
      throw new NotFoundError(`Username ${username} doesn't exist.`);
    }

    const messageFromUserQuery = await db.query(
      `SELECT id,
       (users.username, users.first_name, users.last_name, users.phone) AS to_user,
       body, sent_at, read_at
       FROM messages
       JOIN users
       ON (messages.to_username = users.username)
       WHERE from_username = $1`,
       [username]
    );
    messageFromUserQuery.rows.forEach(function(message){
      const toUser = message.to_user.slice(1, -1).split(',');

      message.to_user = {
        first_name: toUser[1],
        last_name: toUser[2],
        phone: toUser[3],
        username: toUser[0]
      }
    })

    return messageFromUserQuery.rows;
  }

  /** Return messages to this user.
   *
   * [{id, from_user, body, sent_at, read_at}]
   *
   * where from_user is
   *   {username, first_name, last_name, phone}
   */

  static async messagesTo(username) {
    const results = await db.query(
      `SELECT password
       FROM users
       WHERE username = $1`,
      [username]
    );

    if (!results.rows[0]) {
      throw new NotFoundError(`Username ${username} doesn't exist.`);
    }

    const messageToUserQuery = await db.query(
      `SELECT id,
       (users.username, users.first_name, users.last_name, users.phone) AS from_user,
       body, sent_at, read_at
       FROM messages
       JOIN users
       ON (messages.from_username = users.username)
       WHERE to_username = $1`,
       [username]
    );

    messageToUserQuery.rows.forEach(function(message){
      const fromUser = message.from_user.slice(1, -1).split(',');

      message.from_user = {
        first_name: fromUser[1],
        last_name: fromUser[2],
        phone: fromUser[3],
        username: fromUser[0]
      }
    })

    return messageToUserQuery.rows;
  }
}


module.exports = User;
