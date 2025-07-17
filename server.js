// server.js

const express = require("express");
const mysql = require("mysql2");
const app = express();
const bcrypt = require("bcrypt");
const bodyParser = require("body-parser");
const cors = require("cors");
const regex = /^[a-zA-Z0-9]([\w.-]*[a-zA-Z0-9])?@[a-zA-Z0-9.-]+\.(com|net|org|edu)$/; //登録するときメールが正確なメールアドレスのエクスプレッション
const jwt = require("jsonwebtoken");
const JWT_KEY = "walkinonDAbeach";
module.exports = verifyToken;


app.use(cors());
app.use(bodyParser.json());

// Database connection settings
const pool = mysql.createPool({
  host: "catapp-users-catapp.h.aivencloud.com", // ホストサイト
  user: "avnadmin", // アドミン名
  password: process.env.DB_PASSWORD, // パスワード
  database: "defaultdb", // データベース名
  port: 26816,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});

const util = require("util");
const query = util.promisify(pool.query).bind(pool);

//接続を確認、ログに記載する
pool.getConnection((err, connection) => {
   if (err) {
    console.error("❌ Failed to connect to database:", err);
  } else {
    console.log("✅ Successfully connected to the database!");
    connection.release();
  }
});

function verifyToken(req, res, next) {
  // トーケンを貰って
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: "トークンがありません" });
  }

  // トーケンを確認して
  jwt.verify(token, JWT_KEY, (err, decoded) => {
    if (err) {
      return res.status(403).json({ message: "トークンが無効です" });
    }

    // トーケンを添付して送る
    req.user = decoded;
    next();
  });
}

app.delete("/users", verifyToken, async (req, res) => {
  const password = req.body;
  const id = req.user.id;
    
  try {
    const results = await query("SELECT * FROM users WHERE id = ?", [id]);
    const user = results[0];
    const match = await bcrypt.compare(password, user.password_hash);

    if (match) {
    const result = await query("DELETE FROM USERS WHERE id = ?", [id]);
    res.json(result[0]);
    } else {
      res.status(401).json({ message: "パスワードは間違えています" });
    }
  }catch (err) {
    console.error(err);
    res.status(500).json({ message: "サーバーエラー" });
  }
});





//ログイン機能
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const results = await query("SELECT * FROM users WHERE email = ?", [email]);

    if (results.length === 0) {
      return res.status(401).json({ message: "ユーザー名は存在していません" });
    }

    const user = results[0];
    const match = await bcrypt.compare(password, user.password_hash);

    if (match) {
      const token = jwt.sign(
        {id: user.id, email: user.email}, JWT_KEY
      );
      res.json({token: token, username: user.username, points: user.points, message: "ログインできました"});
    } else {
      res.status(401).json({ message: "パスワードは間違えています" });
    }
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "サーバーエラー" });
  }
});


app.post("/updatepoints", verifyToken, async (req, res) => {
  try {
    // Get the new points from client request body
    const { points } = req.body;

    if (typeof points !== 'number') {
      return res.status(400).json({ message: "ポイントは数字でなければなりません" });
    }

    // Get the user ID from the verified token
    const userId = req.user.id;

    // Update DB (adjust query to your DB driver)
    await query("UPDATE users SET points = ? WHERE id = ?", [points, userId]);

    const [result] = await query("SELECT points FROM users WHERE id = ?", [userId]);

    if (!result) {
      return res.status(404).json({ message: "ユーザーが見つかりませんでした" });
    }

    // Return updated value
    res.json({
      message: "ポイントが更新されました",
      updatedPoints: result.points
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "サーバーエラー" });
  }
});


//登録する機能
app.post("/register", async (req, res) => {
  const { email, password, username } = req.body;

  if (!email || !password || !username) {
    return res
      .status(400)
      .json({ error: "メールアドレス、パスワード、ユーザー名が必要です" });
  }
  
  if (regex.test(email)){
    console.log("Valid email");
  } else {
    console.log ("Invalid email");
    return res
    .status(400)
    .json({ error: "メールアドレスの形式は正しくありません"});
  }

  try {
    const users = await query("SELECT * FROM users WHERE email = ?", [email]);　//メールが既に登録していないのを確認する

    if (users.length > 0) {
      return res
        .status(409)
        .json({ error: "メールアドレスは既に登録しています" });
    }

    const hash = await bcrypt.hash(password, 10);

    await query(
      "INSERT INTO users (email, password_hash, username) VALUES (?, ?, ?)", //データベースに登録する
      [email, hash, username]
    );

    const user = await query("SELECT id, username FROM users WHERE email = ?", [email]);

      res.status(201).json({
      message: "ユーザー登録できました",
      token: token,
      username: user.username,
      points: user.points
    });

  } catch (err) {
    console.error("DB error:", err);
    res.status(500).json({ error: "サーバーエラーまたはデータベースエラー" });
  }
});


//TODO Reinstate this if you need a response from the server for my page. You shouldnt though

// app.post("/mypage", async (req, res) => {
//   try {
//     const userId = req.user.id; // Get user id from the verified token middleware

//     // Run the query with userId inside an array as the parameter
//     const results = await query("SELECT username, points FROM users WHERE id = ?", [userId]);

//     if (results.length === 0) {
//       return res.status(404).json({ message: "ユーザーが見つかりません" });
//     }

//     // Send back the user info
//     res.json({ username: results[0].username, points: results[0].points });

//   } catch (err) {
//     console.error(err);
//     res.status(500).json({ message: "サーバーエラー" });
//   }
// });



// pool.getConnection((err, connection) => {
//   if (err) {
//     console.error("❌ Failed to connect to database:", err.message);
//   } else {
//     console.log("✅ Successfully connected to the database!");
//     connection.release();
//   }
// });

// ユーザーを読み取る、テストするのに使った
// app.get("/users", async (req, res) => {
//   try {
//     const results = await query("SELECT id, email, username FROM users");
//     res.json(results);
//   } catch (err) {
//     console.error("Fetch users error:", err);
//     res.status(500).json({ error: "データベースエラー" });
//   }
// });

// サーバー起動
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ API is running at http://localhost:${PORT}`);
});
