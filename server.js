const express = require("express");
const mysql = require("mysql2");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const session = require("express-session");
const dotenv = require("dotenv");
const { OAuth2Client } = require("google-auth-library");

dotenv.config();

const app = express();
const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID); // Use your Google Client ID
const port = process.env.PORT || 3000;

const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

db.connect((err) => {
  if (err) {
    console.error("Error connecting to the database:", err.stack);
    return;
  }
  console.log("Connected to the database successfully!");
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false }, // Should be true in production with HTTPS
  })
);

// Middleware to check API Key
const apiKeyRequired = (req, res, next) => {
  const apiKey = req.headers["x-api-key"];
  if (apiKey !== process.env.API_KEY) {
    return res
      .status(401)
      .json({ message: "Unauthorized access. Invalid API key." });
  }
  next();
};

// Middleware to check session activity
const updateSessionActivity = (req, res, next) => {
  if (req.session.user_id) {
    const lastActive = req.session.last_active;
    const now = new Date();

    const lastActiveTime = new Date(lastActive);
    const inactiveTime = (now - lastActiveTime) / 1000; // in seconds

    if (inactiveTime > 900) {
      // 15 minutes timeout
      req.session.destroy((err) => {
        if (err) {
          return res.status(500).json({ message: "Error clearing session" });
        }
        return res
          .status(401)
          .json({ message: "Session timed out. Please log in again." });
      });
    }

    req.session.last_active = now.toISOString();
  }
  next();
};

app.use(updateSessionActivity);

// Fetch Google Key
const googleKeyRequired = async () => {
  const [rows] = await db
    .promise()
    .query("SELECT google_key FROM secret_key LIMIT 1");
  if (rows.length > 0) {
    return rows[0].google_key;
  } else {
    throw new Error("google_key not found in the database");
  }
};

// Login Route
app.post("/api/login", async (req, res) => {
  try {
    const data = req.body;
    if (!data) {
      return res.status(400).json({ message: "No JSON data received." });
    }

    // Google OAuth Login
    if (data.token) {
      try {
        const googleKey = await googleKeyRequired();
        const ticket = await googleClient.verifyIdToken({
          idToken: data.token,
          audience: googleKey,
        });
        const userEmail = ticket.getPayload().email;

        if (!userEmail.endsWith("@nirwanalestari.com")) {
          logFailedAttempt(userEmail, "Invalid username domain", req.ip);
          return res
            .status(403)
            .json({ message: "Only @nirwanalestari.com emails are allowed." });
        }

        const [rows] = await db
          .promise()
          .query("SELECT id, role FROM users WHERE username = ?", [userEmail]);
        let user_id, role;
        if (rows.length > 0) {
          user_id = rows[0].id;
          role = rows[0].role;
        } else {
          role = "guest";
          const [result] = await db
            .promise()
            .query("INSERT INTO users (username, role) VALUES (?, ?)", [
              userEmail,
              role,
            ]);
          user_id = result.insertId;
        }

        req.session.user_id = user_id;
        req.session.username = userEmail;
        req.session.role = role;
        req.session.last_active = new Date().toISOString();

        return res.status(200).json({ message: "Login successful", role });
      } catch (error) {
        return res.status(401).json({ message: "Invalid Google token" });
      }
    }

    // Regular username/password login
    const { username, password } = data;
    if (!username || !password) {
      logFailedAttempt(
        username || "Unknown",
        "Missing username or password",
        req.ip
      );
      return res
        .status(400)
        .json({ message: "Username and password are required." });
    }

    if (!username.endsWith("@nirwanalestari.com")) {
      logFailedAttempt(username, "Invalid username domain", req.ip);
      return res
        .status(403)
        .json({ message: "Only @nirwanalestari.com usernames are allowed." });
    }

    const [rows] = await db
      .promise()
      .query("SELECT id, password, role FROM users WHERE username = ?", [
        username,
      ]);

    if (rows.length > 0) {
      const user = rows[0];
      const isMatch = await bcrypt.compare(password, user.password);

      if (isMatch) {
        req.session.user_id = user.id;
        req.session.username = username;
        req.session.role = user.role;
        req.session.last_active = new Date().toISOString();
        return res
          .status(200)
          .json({ message: "Login successful", role: user.role });
      } else {
        logFailedAttempt(username, "Invalid username or password", req.ip);
        return res
          .status(401)
          .json({ message: "Invalid username or password" });
      }
    } else {
      logFailedAttempt(username, "User not found", req.ip);
      return res.status(401).json({ message: "Invalid username or password" });
    }
  } catch (error) {
    logFailedAttempt("Unknown", "Error processing request", req.ip);
    console.error("==== ERROR TRACEBACK ====");
    console.error(error);
    console.error("=========================");
    return res
      .status(500)
      .json({ message: "Error processing request", error: error.message });
  }
});

// Logging failed login attempts
const logFailedAttempt = (username, reason, ipAddress) => {
  const timestamp = new Date().toISOString();
  db.promise().query(
    "INSERT INTO login_attempts (username, reason, ip_address, timestamp) VALUES (?, ?, ?, ?)",
    [username, reason, ipAddress, timestamp]
  );
  const logMessage = `${timestamp} - ${username} - ${reason} - ${ipAddress}\n`;
  require("fs").appendFileSync("login_attempts.log", logMessage);
};

// Session Check Route
app.get("/api/session", (req, res) => {
  if (req.session.user_id) {
    return res.status(200).json({
      isAuthenticated: true,
      role: req.session.role,
      username: req.session.username,
    });
  } else {
    return res.status(401).json({ isAuthenticated: false });
  }
});

// Download Route
app.get("/api/download", (req, res) => {
  const filename = "react.txt";
  res.download(filename, (err) => {
    if (err) {
      return res.status(404).json({ message: "File not found" });
    }
  });
});

// Logout Route
app.get("/api/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ message: "Error logging out" });
    }
    res.status(200).json({ message: "Logged out successfully" });
  });
});

app.post("/api/create-financial-report", async (req, res) => {
  const { date, revenue, expense, area } = req.body;

  if (!date || !revenue || !expense || !area) {
    return res.status(400).json({ message: "Missing required fields" });
  }

  try {
    await db
      .promise()
      .query(
        "INSERT INTO financial_data (date, revenue, expense, area) VALUES (?, ?, ?, ?)",
        [date, revenue, expense, area]
      );
    res.status(201).json({ message: "Financial report successfully created" });
  } catch (error) {
    res.status(500).json({
      message: "Error while creating financial report",
      error: error.message,
    });
  }
});

app.get("/api/users", async (req, res) => {
  const { role } = req.query;

  try {
    const [validRoles] = await db
      .promise()
      .query("SELECT DISTINCT role FROM users");
    const validRoleList = validRoles.map((row) => row.role);

    if (role && !validRoleList.includes(role)) {
      return res.status(400).json({ error: "Invalid role provided" });
    }

    let query = "SELECT id, username, role FROM users";
    let params = [];

    if (role) {
      query += " WHERE role = ?";
      params.push(role);
    }

    const [users] = await db.promise().query(query, params);

    res.json(
      users.map((user) => ({
        id: user.id,
        username: user.username,
        role: user.role,
      }))
    );
  } catch (error) {
    res
      .status(500)
      .json({ error: "Error fetching users", message: error.message });
  }
});

app.post("/api/assign_profile", async (req, res) => {
  const { user_id, routes, fitur } = req.body;

  try {
    for (let route of routes) {
      await db
        .promise()
        .query("INSERT INTO profile (user_id, route, fitur) VALUES (?, ?, ?)", [
          user_id,
          route,
          fitur,
        ]);
    }
    res.status(200).json({
      message: "Routes successfully added (existing routes preserved)",
    });
  } catch (error) {
    res
      .status(500)
      .json({ error: "Error assigning routes", message: error.message });
  }
});

app.post("/api/assign-routes", async (req, res) => {
  const { user_id, routes, nama_fitur } = req.body;

  try {
    for (let route of routes) {
      await db
        .promise()
        .query(
          "INSERT INTO user_routes (user_id, route, nama_fitur) VALUES (?, ?, ?)",
          [user_id, route, nama_fitur]
        );
    }
    res.status(200).json({
      message: "Routes successfully added (existing routes preserved)",
    });
  } catch (error) {
    res
      .status(500)
      .json({ error: "Error adding routes", message: error.message });
  }
});

app.get("/api/user-routes", async (req, res) => {
  const user_id = req.session.user_id;

  if (!user_id) {
    return res.status(401).json({ message: "User not logged in" });
  }

  try {
    const [results] = await db.promise().query(
      `SELECT u.username, ur.route, ur.nama_fitur
         FROM users u
         INNER JOIN user_routes ur ON u.id = ur.user_id
         WHERE u.id = ?`,
      [user_id]
    );

    const userRoutes = results.map((row) => ({
      username: row.username,
      route: row.route,
      nama_fitur: row.nama_fitur,
    }));

    res.json(userRoutes);
  } catch (error) {
    res
      .status(500)
      .json({ message: "Error fetching user routes", error: error.message });
  }
});

app.get("/api/financial-report", apiKeyRequired, async (req, res) => {
  const { start_date, end_date, area } = req.query;

  if (!start_date || !end_date) {
    return res.status(400).json({ error: "Missing start_date or end_date" });
  }

  try {
    let formattedStartDate, formattedEndDate;

    if (start_date.includes("-") && start_date.split("-")[0].length === 4) {
      formattedStartDate = start_date;
      formattedEndDate = end_date;
    } else {
      formattedStartDate = moment(start_date, "MM-DD-YYYY").format(
        "YYYY-MM-DD"
      );
      formattedEndDate = moment(end_date, "MM-DD-YYYY").format("YYYY-MM-DD");
    }

    const [areas] = await db
      .promise()
      .query("SELECT DISTINCT area FROM financial_data");

    let query = "SELECT * FROM financial_data WHERE date BETWEEN ? AND ?";
    let params = [formattedStartDate, formattedEndDate];

    if (area) {
      query += " AND area = ?";
      params.push(area);
    }

    const [results] = await db.promise().query(query, params);

    const reports = results.map((row) => ({
      id: row.id,
      date: row.date,
      revenue: row.revenue,
      expense: row.expense,
      area: row.area,
    }));

    res.json({
      reports,
      areas: areas.map((a) => a.area),
    });
  } catch (error) {
    res
      .status(500)
      .json({
        error: "Error fetching financial report",
        message: error.message,
      });
  }
});

// Serve the connected message on the home route
app.get("/", (req, res) => {
  res.send("Connected successfully");
});

app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});
