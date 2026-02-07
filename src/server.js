import express from "express";
import { exec } from "child_process";

const app = express();

app.get("/dns", (req, res) => {
  const name = req.query.name || "example.com";
  // VULNERABLE: command injection via concatenation
  exec("nslookup " + name, (err, stdout) => {
    res.json({ err: String(err || ""), out: stdout });
  });
});

app.listen(3000, () => console.log("listening on 3000"));
