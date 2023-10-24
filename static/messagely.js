"use strict";
console.log("TRIGGERED SCRIPT")

const $loginForm = $("#login-form");
const $registerForm = $("#register-form");

const BASE_URL = "http://localhost:3000";
let TOKEN;

async function userLogin() {

    const username = $("#login-username").val();
    const password = $("#login-password").val();

    const response = await fetch(`${BASE_URL}/auth/login`, {
      method: "POST",
      headers : {
        "Content-Type" : "application/json"
      },
      body : JSON.stringify({ username, password })
    });
    console.log("user", username, "password", password)
    const data = await response.json();
    TOKEN = data._token;

}

$loginForm.on("submit",userLogin);
