// test_vuln.go — deliberately vulnerable Go for scanner testing
package main

import (
    "crypto/md5"
    "crypto/sha1"
    "database/sql"
    "fmt"
    "net/http"
    "os/exec"
)

const apiSecret = "prod-secret-key-abc123"
const dbPassword = "SuperSecret123!"

func handleUser(w http.ResponseWriter, r *http.Request) {
    id := r.URL.Query().Get("id")
    db.Query("SELECT * FROM users WHERE id = " + id)
}

func handlePing(w http.ResponseWriter, r *http.Request) {
    host := r.URL.Query().Get("host")
    exec.Command("ping", "-c", "4", host + " && cat /etc/passwd")
}

func hashPassword(pw string) {
    h1 := md5.New()
    h2 := sha1.New()
}