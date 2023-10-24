"use strict";

const Router = require("express").Router;
const router = new Router();
const { SECRET_KEY } = require("../config");
const { UnauthorizedError, BadRequestError } = require("../expressError");
const User = require('../models/user');
const jwt = require('jsonwebtoken');


/** POST /login: {username, password} => {token} */
router.post('/login', async function(req, res){
  if(req.body === undefined) throw new BadRequestError();

  const {username, password} = req.body;

  const authenticated = await User.authenticate(username, password);

  if(authenticated === false){
    throw new UnauthorizedError("Invalid credentials");
  }

  const payload = { username };
  const token = jwt.sign(payload, SECRET_KEY);

  return res.json({token});
})

/** POST /register: registers, logs in, and returns token.
 *
 * {username, password, first_name, last_name, phone} => {token}.
 */
router.post('/register', async function(req, res){
  if(req.body === undefined) throw new BadRequestError();

  const newUser = await User.register(req.body);

  const payload = newUser;
  const token = jwt.sign(payload, SECRET_KEY);

  return res.status(201).json({token});
})

module.exports = router;