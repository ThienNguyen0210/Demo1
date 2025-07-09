const express = require('express');
const path = require('path');
const mysql = require('mysql');
const crypto = require('crypto');
const fs = require('fs');
const session = require('express-session');
const app = express();
const PORT = 3000;
const os = require('os');

// Session
app.use(session({
  secret: 'matkhau-bi-mat',
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false }
}));

// MySQL
const connection = mysql.createConnection({
  host: 'localhost',
  port: '3306',
  user: 'root',
  password: 'Thien0210@',
  database: 'authme'
});
connection.connect(err => {
  if (err) return console.error('❌ Lỗi kết nối MySQL:', err);
  console.log('✅ Đã kết nối MySQL');
});

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use('/route', express.static(path.join(__dirname, 'route')));
app.use('/route/picture', express.static(path.join(__dirname, 'route/picture')));

// Helper
function normalizeIp(req) {
  const forwarded = req.headers['x-forwarded-for'];
  const ip = forwarded ? forwarded.split(',')[0] : req.socket.remoteAddress;
  return ip.replace(/^::ffff:/, '').replace(/^::1$/, '127.0.0.1');
}
function getLocalIp() {
  const nets = os.networkInterfaces();
  for (const name of Object.keys(nets)) {
    for (const net of nets[name]) {
      if (net.family === 'IPv4' && !net.internal) {
        return net.address;
      }
    }
  }
  return '127.0.0.1';
}

function hashPassword(password) {
  const salt = crypto.randomBytes(8).toString('hex');
  const inner = crypto.createHash('sha256').update(password.trim()).digest('hex');
  const final = crypto.createHash('sha256').update(inner + salt).digest('hex');
  return `$SHA$${salt}$${final}`;
}
function checkPassword(inputPassword, dbHash) {
  const parts = dbHash.split('$');
  if (parts.length !== 4 || parts[1] !== 'SHA') return false;
  const inner = crypto.createHash('sha256').update(inputPassword.trim()).digest('hex');
  const computed = crypto.createHash('sha256').update(inner + parts[2]).digest('hex');
  return computed === parts[3];
}

// Inject user info vào HTML
function injectUserInfo(html, username) {
  const userHTML = `
    <div class="flex space-x-4">
      <a href="/profile" class="text-green-400 text-base font-semibold no-underline hover:text-green-300">👤 ${username}</a>
      <a href="/logout" class="text-red-400 hover:text-red-300 text-sm font-medium">Đăng xuất</a>
    </div>
  `;
  return html.replace(/<div class="flex space-x-4">[\s\S]*?<\/div>/, userHTML);
}

// Route HTML
function renderWithUser(filePath, req, res) {
  fs.readFile(filePath, 'utf8', (err, html) => {
    if (err) return res.send("Lỗi tải trang");
    const content = req.session.username ? injectUserInfo(html, req.session.username) : html;
    res.send(content);
  });
}
app.get('/', (req, res) => renderWithUser(path.join(__dirname, 'index.html'), req, res));
app.get('/login', (req, res) => {
  if (req.session.username) {
    return res.send("✅ Bạn đã đăng nhập rồi");
  }
  renderWithUser(path.join(__dirname, 'route/login.html'), req, res);
});

app.get('/register', (req, res) => {
  if (req.session.username) {
    return res.send("✅ Bạn đã đăng nhập rồi");
  }
  renderWithUser(path.join(__dirname, 'route/register.html'), req, res);
});


app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/login');
  });
});

// Đăng ký
app.post('/register', (req, res) => {
  const { username, email, password, 'confirm-password': confirmPassword } = req.body;
  const ip = normalizeIp(req);
  const now = Math.floor(Date.now() / 1000);

  function sendWithMessage(msg, color = "red") {
    fs.readFile(path.join(__dirname, 'route/register.html'), 'utf8', (err, html) => {
      if (err) return res.send("Lỗi đọc giao diện");
      const final = html.replace(
        /<p id="thongbao"[^>]*>.*?<\/p>/,
        `<p id="thongbao" style="color: ${color}; font-weight: bold; display: block;">${msg}</p>`
      );
      const injected = req.session.username ? injectUserInfo(final, req.session.username) : final;
      res.send(injected);
    });
  }

  if (!username || !email || !password || !confirmPassword) return sendWithMessage('Vui lòng điền đầy đủ thông tin');
  if (password !== confirmPassword) return sendWithMessage('Mật khẩu nhập lại không khớp');
  if (!/^[a-zA-Z0-9_]{3,16}$/.test(username)) return sendWithMessage('Tên không hợp lệ');
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return sendWithMessage('Email không hợp lệ');

  const inputUsername = username.trim();
  const inputEmail = email.trim().toLowerCase();

  connection.query(`SELECT 1 FROM authme WHERE username = ?`, [inputUsername], (err, userRes) => {
    if (err) return sendWithMessage('Lỗi hệ thống');
    if (userRes.length > 0) return sendWithMessage('Tên đăng nhập đã tồn tại');
    connection.query(`SELECT COUNT(*) AS count FROM authme WHERE regip = ?`, [ip], (err, ipRes) => {
      if (err) return sendWithMessage('Lỗi hệ thống');
      if (ipRes[0].count >= 20) return sendWithMessage('IP vượt giới hạn');
      connection.query(`SELECT 1 FROM authme WHERE email = ?`, [inputEmail], (err, emailRes) => {
        if (err) return sendWithMessage('Lỗi hệ thống');
        if (emailRes.length > 0) return sendWithMessage('Email đã sử dụng');
        const hashed = hashPassword(password);
        const sql = `INSERT INTO authme (username, realname, password, email, ip, lastlogin, x, y, z, world, regdate, regip, isLogged, hasSession, webLogin) VALUES (?, ?, ?, ?, ?, ?, 0, 0, 0, 'world', ?, ?, 0, 0, 0)`;
        connection.query(sql, [inputUsername, inputUsername, hashed, inputEmail, ip, now, now, ip], err => {
          if (err) return sendWithMessage('Đăng ký thất bại');
          return sendWithMessage('Đăng ký thành công!', "green");
        });
      });
    });
  });
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;

  function sendLoginMessage(message, color = 'red') {
    fs.readFile(path.join(__dirname, 'route/login.html'), 'utf8', (err, html) => {
      if (err) return res.send("Lỗi tải trang đăng nhập");
      let content = html.replace(
        /<p id="thongbao"[^>]*>.*?<\/p>/,
        `<p id="thongbao" style="color: ${color}; font-weight: bold; display: block;">${message}</p>`
      );
      if (req.session.username) {
        content = injectUserInfo(content, req.session.username);
      }
      res.send(content);
    });
  }

  if (!username || !password) return sendLoginMessage('Vui lòng nhập đầy đủ');

  const inputUsername = username.trim();

  connection.query('SELECT * FROM authme WHERE username = ?', [inputUsername], (err, results) => {
    if (err) return sendLoginMessage('Lỗi truy vấn');
    if (results.length === 0) return sendLoginMessage('Tài khoản không tồn tại');

    const user = results[0];
    if (checkPassword(password, user.password)) {
      const clientIp = normalizeIp(req);

      // Nếu chưa có sessionId thì tạo
      if (!req.session.sessionId) {
        req.session.sessionId = crypto.randomBytes(16).toString('hex');
      }
      const sessionId = req.session.sessionId;

      req.session.username = user.username;
      req.session.ip = clientIp;

      // Ghi lịch sử đăng nhập vào database
      connection.query(
        'INSERT INTO login_history (username, ip, session_id) VALUES (?, ?, ?)',
        [user.username, clientIp, sessionId]
      );

      return sendLoginMessage(
        `Đăng nhập thành công!<script>setTimeout(() => window.location.href='/', 3000);</script>`,
        'lime'
      );
    } else {
      return sendLoginMessage('Sai mật khẩu');
    }
  });
});






app.get('/profile', (req, res) => {
  if (!req.session.username) {
    return res.send("❌ Bạn chưa đăng nhập");
  }

  const username = req.session.username;
  const currentSessionId = req.session.sessionId || '';
  const serverIp = req.session.serverIp || 'Không xác định';

  connection.query("SELECT email, regip FROM authme WHERE username = ?", [username], (err, results) => {
    if (err || results.length === 0) return res.send("❌ Không tìm thấy người dùng");

    const { email, regip } = results[0];

    // Ẩn email
    function maskEmail(email) {
      const [name, domain] = email.split("@");
      const nameMasked = name.length <= 2 ? "*".repeat(name.length) : name.substring(0, 2) + "*".repeat(Math.floor(name.length * 0.6));
      const domainMasked = domain.replace(/[^.]/g, "*");
      return `${nameMasked}@${domainMasked}`;
    }

    const maskedEmail = maskEmail(email);

    connection.query(
      "SELECT ip, time FROM login_history WHERE username = ? ORDER BY time DESC LIMIT 10",
      [username],
      (err2, historyRows) => {
        if (err2) return res.send("❌ Lỗi lấy lịch sử");

        let historyHTML = `
          <table class="text-sm w-full text-left border-collapse border border-gray-600">
            <thead class="bg-gray-700 text-white">
              <tr>
                <th class="border border-gray-600 px-2 py-1">#</th>
                <th class="border border-gray-600 px-2 py-1">IP</th>
                <th class="border border-gray-600 px-2 py-1">Thời gian</th>
              </tr>
            </thead>
            <tbody class="bg-gray-800">`;

        historyRows.forEach((row, index) => {
          historyHTML += `
            <tr>
              <td class="border border-gray-600 px-2 py-1">${index + 1}</td>
              <td class="border border-gray-600 px-2 py-1">${row.ip}</td>
              <td class="border border-gray-600 px-2 py-1">${new Date(row.time).toLocaleString()}</td>
            </tr>`;
        });

        historyHTML += `</tbody></table>`;

        // Liệt kê các tài khoản liên quan (KHÔNG hiển thị email)
        connection.query(
          `SELECT username FROM authme 
           WHERE (regip = ? OR sessionId = ?) AND username != ? 
           LIMIT 20`,
          [regip, currentSessionId, username],
          (err3, relatedUsers) => {
            if (err3) return res.send("❌ Lỗi truy vấn tài khoản liên quan");

            let relatedHTML = '<ul class="list-disc ml-6 space-y-1">';
            if (relatedUsers.length === 0) {
              relatedHTML += '<li class="text-gray-400 italic">Không có tài khoản liên quan nào.</li>';
            } else {
              relatedUsers.forEach((u) => {
                relatedHTML += `<li><span class="text-blue-400 font-medium">${u.username}</span></li>`;
              });
            }
            relatedHTML += '</ul>';

            fs.readFile(path.join(__dirname, 'route/profile.html'), 'utf8', (err4, html) => {
              if (err4) return res.send("Lỗi tải giao diện hồ sơ");

              let htmlWithData = html
                .replace(/<span id="playerName">.*?<\/span>/, `<span id="playerName">${username}</span>`)
                .replace(/<span id="emailMask">.*?<\/span>/, `<span id="emailMask">${maskedEmail}</span>`)
                .replace(/<span id="ipMask">.*?<\/span>/, `<span id="ipMask">${regip}</span>`)
                .replace(/<span id="serverIp">.*?<\/span>/, `<span id="serverIp">${serverIp}</span>`)
                .replace('<!--LOGIN_HISTORY-->', historyHTML)
                .replace('<!--RELATED_ACCOUNTS-->', relatedHTML);

              const injected = injectUserInfo(htmlWithData, username);
              res.send(injected);
            });
          }
        );
      }
    );
  });
});





app.post('/change-password', (req, res) => {
  if (!req.session.username) return res.send("❌ Bạn chưa đăng nhập");

  const { oldPassword, newPassword, confirmPassword } = req.body;
  const username = req.session.username;

  function sendMessageToProfile(msg, color = 'red') {
    // Gọi lại GET /profile nhưng chèn thêm thông báo
    connection.query("SELECT email, regip FROM authme WHERE username = ?", [username], (err, results) => {
      if (err || results.length === 0) return res.send("❌ Không tìm thấy người dùng");

      const { email, regip } = results[0];
      const [name, domain] = email.split("@");
      const nameMasked = name.length <= 2 ? "*".repeat(name.length) : name.substring(0, 2) + "*".repeat(Math.floor(name.length * 0.6));
      const domainMasked = domain.replace(/[^.]/g, "*");
      const maskedEmail = `${nameMasked}@${domainMasked}`;

      connection.query("SELECT ip, time FROM login_history WHERE username = ? ORDER BY time DESC LIMIT 10", [username], (err2, historyRows) => {
        if (err2) return res.send("❌ Lỗi lấy lịch sử");

        let historyHTML = `<table class="text-sm w-full text-left border-collapse border border-gray-600">
          <thead class="bg-gray-700 text-white">
            <tr>
              <th class="border border-gray-600 px-2 py-1">#</th>
              <th class="border border-gray-600 px-2 py-1">IP</th>
              <th class="border border-gray-600 px-2 py-1">Thời gian</th>
            </tr>
          </thead>
          <tbody class="bg-gray-800">`;

        historyRows.forEach((row, index) => {
          historyHTML += `
            <tr>
              <td class="border border-gray-600 px-2 py-1">${index + 1}</td>
              <td class="border border-gray-600 px-2 py-1">${row.ip}</td>
              <td class="border border-gray-600 px-2 py-1">${new Date(row.time).toLocaleString()}</td>
            </tr>`;
        });

        historyHTML += `</tbody></table>`;

        fs.readFile(path.join(__dirname, 'route/profile.html'), 'utf8', (err, html) => {
          if (err) return res.send("Lỗi tải profile");

          let htmlWithData = html
            .replace(/<span id="playerName">.*?<\/span>/, `<span id="playerName">${username}</span>`)
            .replace(/<span id="emailMask">.*?<\/span>/, `<span id="emailMask">${maskedEmail}</span>`)
            .replace(/<span id="ipMask">.*?<\/span>/, `<span id="ipMask">${regip}</span>`)
            .replace(/<span id="serverIp">.*?<\/span>/, `<span id="serverIp">${req.session.serverIp || 'Không xác định'}</span>`)
            .replace('<!--LOGIN_HISTORY-->', historyHTML)
            .replace(/<p id="changePasswordMessage"[^>]*>.*?<\/p>/, `<p id="changePasswordMessage" style="color:${color}; font-weight:bold;">${msg}</p>`);

          const injected = injectUserInfo(htmlWithData, username);
          res.send(injected);
        });
      });
    });
  }

  if (!oldPassword || !newPassword || !confirmPassword)
    return sendMessageToProfile("Vui lòng điền đầy đủ thông tin");

  if (newPassword !== confirmPassword)
    return sendMessageToProfile("Mật khẩu mới không khớp");

  connection.query("SELECT password FROM authme WHERE username = ?", [username], (err, results) => {
    if (err || results.length === 0) return sendMessageToProfile("Lỗi hệ thống");

    if (!checkPassword(oldPassword, results[0].password))
      return sendMessageToProfile("Mật khẩu cũ không đúng");

    const newHash = hashPassword(newPassword);
    connection.query("UPDATE authme SET password = ? WHERE username = ?", [newHash, username], (err) => {
      if (err) return sendMessageToProfile("Đổi mật khẩu thất bại");
      return sendMessageToProfile("✅ Đổi mật khẩu thành công!", 'lime');
    });
  });
});




app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

const multer = require('multer');
const upload = multer({ dest: path.join(__dirname, 'uploads') });

// Giao diện cộng đồng
app.get('/confession', (req, res) => {
  if (!req.session.username) return res.redirect('/login');
  renderWithUser(path.join(__dirname, 'route/confession.html'), req, res);
});

// API lấy danh sách bài viết
app.get('/confession/posts', (req, res) => {
  connection.query(`SELECT * FROM posts ORDER BY created_at DESC`, (err, posts) => {
    if (err || posts.length === 0) return res.json([]);

    const postIds = posts.map(p => p.id);
    if (postIds.length === 0) return res.json([]);

    connection.query(`SELECT * FROM comments WHERE post_id IN (?)`, [postIds], (err2, comments) => {
      connection.query(`
        SELECT post_id, COUNT(*) AS count FROM likes 
        WHERE post_id IN (?) GROUP BY post_id
      `, [postIds], (err3, likeCounts) => {
        const likeMap = {};
        likeCounts.forEach(l => likeMap[l.post_id] = l.count);

        posts.forEach(p => {
          p.comments = comments.filter(c => c.post_id === p.id);
          p.likes = likeMap[p.id] || 0;
        });

        res.json(posts);
      });
    });
  });
});

// Đăng bài mới
app.post('/confession/post', upload.single('image'), (req, res) => {
  if (!req.session.username) return res.redirect('/login');

  console.log('Dữ liệu nhận được:', req.body, req.file); // Thêm dòng này để debug
  const { content } = req.body;
  const image = req.file ? req.file.filename : null;

  connection.query(`
    INSERT INTO posts (username, content, image) VALUES (?, ?, ?)
  `, [req.session.username, content, image], (err) => {
    if (err) {
      console.error('Lỗi khi chèn bài đăng:', err);
      return res.status(500).send('Lỗi server');
    }
    res.redirect('/confession');
  });
});

// Bình luận bài viết
app.post('/confession/comment', (req, res) => {
  if (!req.session.username) return res.redirect('/login');

  const { post_id, comment } = req.body;

  connection.query(`
    INSERT INTO comments (post_id, username, content) VALUES (?, ?, ?)
  `, [post_id, req.session.username, comment], () => {
    res.redirect('/confession');
  });
});

// Like bài viết
app.post('/confession/like', (req, res) => {
  if (!req.session.username) return res.redirect('/login');

  const { post_id } = req.body;

  connection.query(`
    SELECT 1 FROM likes WHERE post_id = ? AND username = ?
  `, [post_id, req.session.username], (err, rows) => {
    if (rows.length === 0) {
      connection.query(`
        INSERT INTO likes (post_id, username) VALUES (?, ?)
      `, [post_id, req.session.username], () => {
        res.redirect('/confession');
      });
    } else {
      res.redirect('/confession'); // đã like rồi
    }
  });
});


// Start server
app.listen(PORT, () => {
  console.log(`🌐 Server đang chạy tại http://localhost:${PORT}`);
});
