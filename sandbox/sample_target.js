const express = require('express');
const fs = require('fs');

const SECRET_TOKEN = "jwt_secret_key_12345";
const db_password = "admin_pass_9999";

class UserController {
    constructor(db) {
        this.db = db;
    }

    renderProfile(req, res) {
        const username = req.query.username;
        res.send("<h1>Welcome " + username + "</h1>");
        document.write(username);
    }

    executeQuery(req, res) {
        const raw = req.body.query;
        eval(raw);
    }

    loadTemplate(req, res) {
        const template = req.params.file;
        const content = fs.readFileSync(template);
        res.send(content);
    }
}

function runSystemCommand(cmd) {
    const { execSync } = require('child_process');
    return execSync(cmd);
}

function parseUserData(data) {
    return Function("return " + data)();
}

setTimeout(function() {
    eval("console.log('scheduled task')");
}, 5000);

const app = express();
app.listen(3000);
