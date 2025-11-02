const express = require("express");
const bodyParser = require("body-parser");
const cors = require("cors");
const mysql = require("mysql2");
const bcrypt = require("bcryptjs");
require("dotenv").config();
const path = require("path");

const app = express();
app.use(cors());
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, "public")));

// ✅ Connect to MySQL
const db = mysql.createConnection({
  host: "localhost",
  user: "root", // change if you use a different MySQL user
  password: "", // add password if you set one
  database: "auth_db",
});

db.connect((err) => {
  if (err) {
    console.error("❌ Database connection failed:", err);
    return;
  }
  console.log("✅ Connected to MySQL Database");
});

// ✅ Registration endpoint
app.post("/register", async (req, res) => {
  const { first_name, last_name, phone_number, email, password } = req.body;

  if (!first_name || !last_name || !phone_number || !email || !password) {
    return res.status(400).json({ error: "All fields are required" });
  }

  try {
    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert into database
    const sql = `INSERT INTO users (first_name, last_name, phone_number, email, password)
                 VALUES (?, ?, ?, ?, ?)`;
    db.query(
      sql,
      [first_name, last_name, phone_number, email, hashedPassword],
      (err) => {
        if (err) {
          console.error("Error inserting user:", err);
          return res.status(500).json({ error: "Database error" });
        }
        res.json({ message: "Registration successful!" });
      }
    );
  } catch (error) {
    console.error("Error in registration:", error);
    res.status(500).json({ error: "Server error" });
  }
});

app.listen(5000, () => console.log("🚀 Server running on port 5000"));

// ✅ Login endpoint
app.post("/login", (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: "Email and password are required" });
  }

  const sql = "SELECT * FROM users WHERE email = ?";
  db.query(sql, [email], async (err, results) => {
    if (err) {
      console.error("Database error:", err);
      return res.status(500).json({ error: "Database error" });
    }

    if (results.length === 0) {
      return res.status(401).json({ error: "Invalid email or password" });
    }

    const user = results[0];
    const passwordMatch = await bcrypt.compare(password, user.password);

    if (!passwordMatch) {
      return res.status(401).json({ error: "Invalid email or password" });
    }

    res.json({ message: "Login successful!" });
  });
});

