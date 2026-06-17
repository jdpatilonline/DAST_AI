import express from "express";
import { execFile } from "child_process";

const app = express();

app.get("/dns", (req, res) => {
  const name = req.query.name || "example.com";
  // FIX: command injection via concatenation
  execFile("nslookup", [name], (err, stdout) => {
    res.json({ err: String(err || ""), out: stdout });
  });
});

app.listen(3000, () => console.log("listening on 3000"));
