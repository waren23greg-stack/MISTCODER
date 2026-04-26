// test_vuln.js — deliberately vulnerable JS for scanner testing
const express = require('express');
const db = require('./db');
const exec = require('child_process').exec;
const md5 = require('md5');

// SQL injection
app.get('/user', (req, res) => {
    db.query("SELECT * FROM users WHERE id = " + req.query.id);
});

// eval injection
app.post('/calc', (req, res) => {
    const result = eval(req.body.expression);
});

// Command injection
app.get('/ping', (req, res) => {
    exec("ping " + req.query.host, (err, stdout) => res.send(stdout));
});

// Hardcoded secret
const API_KEY = "sk-prod-abc123def456ghi789";
const password = "SuperSecret123!";

// Weak crypto
const hash = md5(userPassword);
const h2   = crypto.createHash('sha1').update(data).digest('hex');

// XSS
document.getElementById('output').innerHTML = req.query.input;