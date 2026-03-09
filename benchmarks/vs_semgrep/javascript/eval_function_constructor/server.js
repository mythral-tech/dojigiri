const express = require("express");

const app = express();
app.use(express.json());

app.post("/api/calculate", (req, res) => {
  const { expression } = req.body;

  try {
    const compute = new Function("return " + expression);
    const result = compute();
    res.json({ result });
  } catch (err) {
    res.status(400).json({ error: "Invalid expression" });
  }
});

app.post("/api/transform", (req, res) => {
  const { code, data } = req.body;

  try {
    const transform = new Function("input", code);
    const output = transform(data);
    res.json({ output });
  } catch (err) {
    res.status(400).json({ error: "Transform failed" });
  }
});

app.listen(3000);
