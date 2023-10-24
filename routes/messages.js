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
  // TODO: currentUser is already checked, no need for optional chaining
  const currentUser = res.locals.user;
  const hasUnauthorizedUsername =
    currentUser?.username !== message.to_user.username &&
    currentUser?.username !== message.from_user.username;

  if (!currentUser || hasUnauthorizedUsername) {
    // console.log("to", currentUser.)
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
  // TODO: consistent variable names, currentUsername
  const currentUser = res.locals.user.username;

  console.log("from", currentUser, "to", to_username)
  const message = await Message.create(
    {
      from_username: currentUser,
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
  const to_username = messageDetails.to_user.username;

  const currentUser = res.locals.user;
  const hasUnauthorizedUsername =
    currentUser?.username !== to_username;
// TODO: don't need to check current User
  if (!currentUser || hasUnauthorizedUsername) {
    throw new UnauthorizedError("You are not authorized to view this message.");
  }

  const message = await Message.markRead(id);

  return res.json({ message });

});


module.exports = router;