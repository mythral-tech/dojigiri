const express = require("express");
const { MongoClient } = require("mongodb");

const app = express();
app.use(express.json());

let db;
MongoClient.connect("mongodb://localhost:27017").then((client) => {
  db = client.db("app");
});

app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;

  const user = await db.collection("users").findOne({
    email: email,
    password: password,
  });

  if (user) {
    res.json({ token: generateToken(user) });
  } else {
    res.status(401).json({ error: "invalid credentials" });
  }
});

app.get("/api/users", async (req, res) => {
  const filter = req.query.role ? { role: req.query.role } : {};
  const users = await db.collection("users").find(filter).toArray();
  res.json(users);
});

function generateToken(user) {
  return Buffer.from(JSON.stringify({ id: user._id })).toString("base64");
}

app.listen(3000);
