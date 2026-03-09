const express = require("express");
const { Pool } = require("pg");

const app = express();
const db = new Pool();
app.use(express.json());

app.post("/api/profile", async (req, res) => {
  const { bio } = req.body;
  await db.query("UPDATE users SET bio = $1 WHERE id = $2", [bio, req.user.id]);
  res.json({ status: "saved" });
});

app.get("/api/profile/:id", async (req, res) => {
  const result = await db.query("SELECT bio, name FROM users WHERE id = $1", [
    req.params.id,
  ]);
  res.json(result.rows[0]);
});

module.exports = app;
