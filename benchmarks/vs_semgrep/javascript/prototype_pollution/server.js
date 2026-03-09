const express = require("express");
const _ = require("lodash");

const app = express();
app.use(express.json());

const config = {
  isAdmin: false,
  theme: "default",
  maxRetries: 3,
};

app.post("/api/settings", (req, res) => {
  const userPrefs = req.body.preferences;
  _.merge(config, userPrefs);
  res.json({ status: "updated", config });
});

app.get("/api/admin", (req, res) => {
  if (config.isAdmin) {
    return res.json({ secret: process.env.ADMIN_KEY });
  }
  res.status(403).json({ error: "forbidden" });
});

app.listen(3000);
