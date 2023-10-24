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

    if ((await User.checkUserExists(username)) === true) {
      throw new ConflictError(`Username ${username} is taken.`);
    }

    const hashedPassword = await bcrypt.hash(password, BCRYPT_WORK_FACTOR);

    const newUser = await db.query(
      `INSERT INTO users
        (username, password, first_name, last_name, phone, join_at, last_login_at)
       VALUES
        ($1, $2, $3, $4, $5, current_timestamp, current_timestamp)
       RETURNING
        username, password, first_name, last_name, phone`,
      [username, hashedPassword, first_name, last_name, phone]
    );

    const newUserData = newUser.rows[0];

    return newUserData;
  }

  /** Authenticate: is username/password valid? Returns boolean. */

  static async authenticate(username, password) {

    const results = await db.query(
      `SELECT password
       FROM users
       WHERE username ILIKE $1`,
      [username]
    );

    if (!results.rows[0]) {
      return false;
    }

    const userPassword = results.rows[0].password;

    return (await bcrypt.compare(password, userPassword) === true);

  }

  /** Update last_login_at for user */

  static async updateLoginTimestamp(username) {
    const results = await db.query(
      `UPDATE users
        SET last_login_at = current_timestamp
        WHERE username ILIKE $1
        RETURNING last_login_at`,
      [username]);

      if (!results.rows[0]) {
        throw new NotFoundError(`Username ${username} doesn't exist.`);
      }

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

    const userResults = await db.query(
      `SELECT username, first_name, last_name, phone, join_at, last_login_at
      FROM users
      WHERE username ILIKE $1`,
      [username]
    );

    if (!userResults.rows[0]) {
      throw new NotFoundError(`Username ${username} doesn't exist.`);
    }

    return userResults.rows[0];
  }

  /** Return messages from this user.
   *
   * [{id, to_user, body, sent_at, read_at}]
   *
   * where to_user is
   *   {username, first_name, last_name, phone}
   */

  static async messagesFrom(username) {

    if ((await User.checkUserExists(username)) === false) {
      throw new NotFoundError(`Username ${username} doesn't exist.`);
    }

    const messageFromUserQuery = await db.query(
      `SELECT id,
       users.username, users.first_name, users.last_name, users.phone,
       body, sent_at, read_at
       FROM messages
       JOIN users
       ON (messages.to_username = users.username)
       WHERE from_username ILIKE $1`,
      [username]
    );

    const messagesFromUser = messageFromUserQuery.rows.map(function (message) {
      const {first_name,last_name,phone,username, id, body, sent_at, read_at} = message;
      return {
        id,
        body,
        sent_at,
        read_at,
        to_user : {
          first_name,
          last_name,
          phone,
          username
        }
      }
    });

    return messagesFromUser;
  }

  /** Return messages to this user.
   *
   * [{id, from_user, body, sent_at, read_at}]
   *
   * where from_user is
   *   {username, first_name, last_name, phone}
   */

  static async messagesTo(username) {


    if ((await User.checkUserExists(username)) === false) {
      throw new NotFoundError(`Username ${username} doesn't exist.`);
    }

    const messageToUserQuery = await db.query(
      `SELECT id,
       (users.username, users.first_name, users.last_name, users.phone) AS from_user,
       body, sent_at, read_at
       FROM messages
       JOIN users
       ON (messages.from_username = users.username)
       WHERE to_username ILIKE $1`,
      [username]
    );

    messageToUserQuery.rows.forEach(function (message) {
      const fromUser = message.from_user.slice(1, -1).split(',');

      message.from_user = {
        first_name: fromUser[1],
        last_name: fromUser[2],
        phone: fromUser[3],
        username: fromUser[0]
      };
    });

    return messageToUserQuery.rows;
  }


  /**
   * Takes in a username as a string
   * Checks if the DB has a user with that username
   * Returns boolean of existence of username
   */
  static async checkUserExists(username) {

    const results = await db.query(
      `SELECT password
       FROM users
       WHERE username ILIKE $1`,
      [username]
    );


    return Boolean(results.rows.length > 0);
  }

}


module.exports = User;
