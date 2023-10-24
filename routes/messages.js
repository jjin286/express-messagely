"use strict";

const Router = require("express").Router;
const router = new Router();
const Message = require("../models/message");
const { ensureLoggedIn } = require("../middleware/auth");
const { UnauthorizedError } = require("../expressError");

router.use(ensureLoggedIn);

/** GET /:id - get detail of message.
 *
 * => {message: {id,
 *               body,
 *               sent_at,
 *               read_at,
 *               from_user: {username, first_name, last_name, phone},
 *               to_user: {username, first_name, last_name, phone}}
 *
 * Makes sure that the currently-logged-in users is either the to or from user.
 *
 **/
router.get("/:id", async function (req, res) {

  const message = await Message.get(req.params.id);

  const currentUsername = res.locals.user.username;

  const hasUnauthorizedUsername =
    currentUsername !== message.to_user.username &&
    currentUsername !== message.from_user.username;

  if (hasUnauthorizedUsername) {
    throw new UnauthorizedError("You are not authorized to view this message.");
  }

  return res.json({ message });

});


/** POST / - post message.
 *
 * {to_username, body} =>
 *   {message: {id, from_username, to_username, body, sent_at}}
 *
 **/
router.post("/", async function (req, res) {

  const { to_username, body } = req.body;
  const currentUsername = res.locals.user.username;

  const message = await Message.create(
    {
      from_username: currentUsername,
      to_username,
      body
    });

    return res.status(201)
              .json({ message });

});


/** POST/:id/read - mark message as read:
 *
 *  => {message: {id, read_at}}
 *
 * Makes sure that the only the intended recipient can mark as read.
 *
 **/
router.post("/:id/read", async function (req, res) {

  const id = req.params.id;

  const messageDetails = await Message.get(id);
  const toUsername = messageDetails.to_user.username;

  const currentUsername = res.locals.user.username;
  const hasUnauthorizedUsername = currentUsername !== toUsername;

  if (hasUnauthorizedUsername) {
    throw new UnauthorizedError("You are not authorized to view this message.");
  }

  const message = await Message.markRead(id);

  return res.json({ message });

});


module.exports = router;