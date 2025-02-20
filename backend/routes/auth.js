const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const pool = require("../config/db");
require("dotenv").config();

const router = express.Router();

router.post("/register", async (req, res) => {
  const { name, email, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  try {
    await pool.query("INSERT INTO users (name, email, password) VALUES (?, ?, ?)", [name, email, hashedPassword]);
    res.status(201).json({ message: "User registered" });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const [users] = await pool.query("SELECT * FROM users WHERE email = ?", [email]);
  if (users.length === 0) return res.status(400).json({ error: "User not found" });

  const isValid = await bcrypt.compare(password, users[0].password);
  if (!isValid) return res.status(400).json({ error: "Invalid password" });

  const token = jwt.sign({ userId: users[0].id }, process.env.JWT_SECRET, { expiresIn: "1d" });
  res.json({ token });
});

module.exports = router;
