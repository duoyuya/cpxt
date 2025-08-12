const express = require('express');
const fs = require('fs');
const path = require('path');
const dotenv = require('dotenv');
const fetch = require('node-fetch');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const { v4: uuidv4 } = require('uuid');
const sqlite3 = require('sqlite3').verbose();

// 加载环境变量
dotenv.config();
const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret_key';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '24h';
const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';

// 初始化数据库
const db = new sqlite3.Database(path.join(__dirname, 'data', 'car_notify.db'), (err) => {
  if (err) {
    console.error('数据库连接错误:', err.message);
  } else {
    console.log('✅ SQLite 数据库连接成功');
    // 创建表结构
    db.run(`CREATE TABLE IF NOT EXISTS plates (
      id TEXT PRIMARY KEY,
      plate TEXT NOT NULL UNIQUE,
      uids TEXT NOT NULL,
      remark TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`);
    
    db.run(`CREATE TABLE IF NOT EXISTS settings (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`);
    
    db.run(`CREATE TABLE IF NOT EXISTS logs (
      id TEXT PRIMARY KEY,
      action TEXT NOT NULL,
      details TEXT,
      ip TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`);
    
    // 创建访问令牌表
    db.run(`CREATE TABLE IF NOT EXISTS access_tokens (
      id TEXT PRIMARY KEY,
      plate TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      expires_at TIMESTAMP NOT NULL,
      used INTEGER DEFAULT 0
    )`);
    
    // 初始化默认设置
    db.get("SELECT * FROM settings WHERE key = 'app_token'", (err, row) => {
      if (!row) {
        db.run("INSERT INTO settings (key, value) VALUES (?, ?)", 
          ['app_token', 'AT_dHj0kby8R58ywAo8MW272n2ike2Uv7rs']);
      }
    });
  }
});

// 每小时清理过期令牌
setInterval(() => {
  const now = new Date().toISOString();
  db.run("DELETE FROM access_tokens WHERE expires_at < ?", [now], function(err) {
    if (err) {
      console.error('清理过期令牌失败:', err.message);
    } else {
      console.log(`清理过期令牌: ${this.changes} 条`);
    }
  });
}, 3600000); // 3600000ms = 1小时

// 中间件
app.use(express.json());
app.use('/admin', express.static(path.join(__dirname, 'admin')));

// 登录限流
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { msg: '尝试次数过多，请 15 分钟后重试' },
  standardHeaders: true,
  legacyHeaders: false
});

// JWT 认证中间件
const authenticateJWT = (req, res, next) => {
  const authHeader = req.headers.authorization;
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ msg: '未提供认证令牌' });
  }
  
  const token = authHeader.split(' ')[1];
  
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ msg: '无效的或已过期的令牌' });
    }
    req.user = user;
    next();
  });
};

// 日志记录中间件 - 增强版
const logAction = (action) => {
  return (req, res, next) => {
    const originalSend = res.send;
    res.send = function(body) {
      const logId = uuidv4();
      const details = {
        path: req.path,
        method: req.method,
        body: req.body,
        statusCode: res.statusCode,
        response: body
      };
      
      db.run(
        "INSERT INTO logs (id, action, details, ip) VALUES (?, ?, ?, ?)",
        [logId, action, JSON.stringify(details), req.ip],
        (err) => {
          if (err) console.error('日志记录失败:', err.message);
        }
      );
      
      originalSend.call(this, body);
    };
    
    // 捕获未处理的Promise错误
    process.on('unhandledRejection', (reason, promise) => {
      const logId = uuidv4();
      const details = {
        path: req.path,
        method: req.method,
        error: reason.toString(),
        stack: reason.stack,
        promise: promise.toString()
      };
      
      db.run(
        "INSERT INTO logs (id, action, details, ip) VALUES (?, ?, ?, ?)",
        [logId, 'error', JSON.stringify(details), req.ip],
        (err) => {
          if (err) console.error('错误日志记录失败:', err.message);
        }
      );
    });
    
    next();
  };
};

// 登录接口 (使用 JWT)
app.post('/admin/login', loginLimiter, async (req, res) => {
  try {
    const { username, password } = req.body;
    const { ADMIN_USER, ADMIN_PASSWORD_HASH } = process.env;
    
    if (!username || !password) {
      return res.status(400).json({ msg: '用户名和密码必填' });
    }
    
    if (username !== ADMIN_USER || !(await bcrypt.compare(password, ADMIN_PASSWORD_HASH))) {
      return res.status(401).json({ msg: '用户名或密码错误' });
    }
    
    // 生成 JWT 令牌
    const token = jwt.sign(
      { username: ADMIN_USER, role: 'admin' },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES_IN }
    );
    
    res.json({ 
      token,
      expiresIn: JWT_EXPIRES_IN,
      msg: '登录成功'
    });
  } catch (error) {
    res.status(500).json({ msg: '服务器错误', error: error.message });
  }
});

// 生成临时访问令牌 API
app.get('/api/generate-token', authenticateJWT, (req, res) => {
  try {
    const { plate } = req.query;
    
    if (!plate) {
      return res.status(400).json({ msg: '车牌号必填' });
    }
    
    // 验证车牌是否存在
    db.get("SELECT * FROM plates WHERE plate = ?", [plate], (err, plateInfo) => {
      if (err) {
        return res.status(500).json({ msg: '查询车牌失败', error: err.message });
      }
      
      if (!plateInfo) {
        return res.status(404).json({ msg: '车牌不存在' });
      }
      
      // 生成令牌（UUID+时间戳）
      const token = uuidv4();
      const expiresIn = 15 * 60 * 1000; // 15分钟有效期
      const expiresAt = new Date(Date.now() + expiresIn).toISOString();
      
      // 保存令牌
      db.run(
        "INSERT INTO access_tokens (id, plate, expires_at) VALUES (?, ?, ?)",
        [token, plate, expiresAt],
        function(err) {
          if (err) {
            return res.status(500).json({ msg: '生成令牌失败', error: err.message });
          }
          
          res.json({
            token,
            url: `${BASE_URL}/admin/index.html?token=${token}`,
            expiresIn: Math.floor(expiresIn / 60000) // 分钟数
          });
        }
      );
    });
  } catch (error) {
    res.status(500).json({ msg: '服务器错误', error: error.message });
  }
});

// 验证临时令牌 API
app.get('/api/validate-token', (req, res) => {
  try {
    const { token } = req.query;
    
    if (!token) {
      return res.status(400).json({ msg: '令牌必填' });
    }
    
    // 查询令牌
    db.get("SELECT * FROM access_tokens WHERE id = ?", [token], (err, tokenInfo) => {
      if (err) {
        return res.status(500).json({ msg: '验证令牌失败', error: err.message });
      }
      
      if (!tokenInfo) {
        return res.status(404).json({ msg: '无效的令牌' });
      }
      
      // 检查是否过期
      if (new Date(tokenInfo.expires_at) < new Date()) {
        return res.status(403).json({ msg: '令牌已过期' });
      }
      
      // 检查是否已使用
      if (tokenInfo.used) {
        return res.status(403).json({ msg: '令牌已失效' });
      }
      
      // 标记令牌为已使用（单次有效）
      db.run("UPDATE access_tokens SET used = 1 WHERE id = ?", [token]);
      
      res.json({
        valid: true,
        plate: tokenInfo.plate,
        msg: '令牌验证成功'
      });
    });
  } catch (error) {
    res.status(500).json({ msg: '服务器错误', error: error.message });
  }
});

// 车牌管理 API
app.get('/api/plates', authenticateJWT, (req, res) => {
  const { search, page = 1, limit = 10 } = req.query;
  const offset = (page - 1) * limit;
  let query = "SELECT * FROM plates";
  let countQuery = "SELECT COUNT(*) as total FROM plates";
  const params = [];
  const countParams = [];
  
  if (search) {
    query += " WHERE plate LIKE ?";
    countQuery += " WHERE plate LIKE ?";
    params.push(`%${search}%`);
    countParams.push(`%${search}%`);
  }
  
  query += " ORDER BY created_at DESC LIMIT ? OFFSET ?";
  params.push(limit, offset);
  
  db.all(query, params, (err, rows) => {
    if (err) {
      return res.status(500).json({ msg: '获取车牌数据失败', error: err.message });
    }
    
    const plates = rows.map(row => ({
      ...row,
      uids: row.uids.split(',')
    }));
    
    db.get(countQuery, countParams, (err, countRow) => {
      if (err) {
        return res.status(500).json({ msg: '获取数据总数失败', error: err.message });
      }
      
      res.json({
        plates,
        pagination: {
          total: countRow ? countRow.total : 0,
          page: parseInt(page),
          limit: parseInt(limit),
          pages: Math.ceil((countRow ? countRow.total : 0) / limit)
        }
      });
    });
  });
});

app.get('/api/plates/:id', authenticateJWT, (req, res) => {
  db.get("SELECT * FROM plates WHERE id = ?", [req.params.id], (err, row) => {
    if (err) {
      return res.status(500).json({ msg: '获取车牌数据失败', error: err.message });
    }
    
    if (!row) {
      return res.status(404).json({ msg: '车牌不存在' });
    }
    
    res.json({
      ...row,
      uids: row.uids.split(',')
    });
  });
});

app.post('/api/plates', authenticateJWT, logAction('添加车牌'), (req, res) => {
  const { plate, uids, remark } = req.body;
  
  if (!plate || !uids || !uids.length) {
    return res.status(400).json({ msg: '车牌号和 UID 必填' });
  }
  
  // 验证车牌格式
  const plateRegex = /^[京津沪渝冀豫云辽黑湘皖鲁新苏浙赣鄂桂甘晋蒙陕吉闽贵粤青藏川宁琼使领A-Za-z\u4e00-\u9fa5]{1,2}[A-Z0-9]{5,6}$/;
  if (!plateRegex.test(plate)) {
    return res.status(400).json({ msg: '车牌号格式不正确，应为省份简称(1-2位)+5-6位字母或数字' });
  }
  
  const plateId = uuidv4();
  
  // 确保uids是数组
  const uidsStr = Array.isArray(uids) ? uids.join(',') : uids;
  
  db.run(
    "INSERT INTO plates (id, plate, uids, remark) VALUES (?, ?, ?, ?)",
    [plateId, plate, uidsStr, remark || ''],
    function(err) {
      if (err) {
        if (err.message.includes('UNIQUE constraint failed')) {
          return res.status(400).json({ msg:'该车牌号已存在' });
        }
        return res.status(500).json({ msg: '添加车牌失败', error: err.message });
      }
      
      res.status(201).json({ 
        msg: '车牌添加成功', 
        id: plateId 
      });
    }
  );
});

app.put('/api/plates/:id', authenticateJWT, logAction('更新车牌'), (req, res) => {
  const { plate, uids, remark } = req.body;
  
  if (!plate || !uids || !uids.length) {
    return res.status(400).json({ msg: '车牌号和 UID 必填' });
  }
  
  // 验证车牌格式
  const plateRegex = /^[京津沪渝冀豫云辽黑湘皖鲁新苏浙赣鄂桂甘晋蒙陕吉闽贵粤青藏川宁琼使领A-Za-z\u4e00-\u9fa5]{1,2}[A-Z0-9]{5,6}$/;
  if (!plateRegex.test(plate)) {
    return res.status(400).json({ msg: '车牌号格式不正确，应为省份简称(1-2位)+5-6位字母或数字' });
  }
  
  const uidsStr = Array.isArray(uids) ? uids.join(',') : uids;
  
  db.run(
    "UPDATE plates SET plate = ?, uids = ?, remark = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
    [plate, uidsStr, remark || '', req.params.id],
    function(err) {
      if (err) {
        if (err.message.includes('UNIQUE constraint failed')) {
          return res.status(400).json({ msg: '该车牌号已存在' });
        }
        return res.status(500).json({ msg: '更新车牌失败', error: err.message });
      }
      
      if (this.changes === 0) {
        return res.status(404).json({ msg: '车牌不存在' });
      }
      
      res.json({ msg: '车牌更新成功' });
    }
  );
});

app.delete('/api/plates/:id', authenticateJWT, logAction('删除车牌'), (req, res) => {
  db.run("DELETE FROM plates WHERE id = ?", [req.params.id], function(err) {
    if (err) {
      return res.status(500).json({ msg: '删除车牌失败', error: err.message });
    }
    
    if (this.changes === 0) {
      return res.status(404).json({ msg: '车牌不存在' });
    }
    
    res.json({ msg: '车牌删除成功' });
  });
});

// APP Token 管理
app.get('/api/app-token', authenticateJWT, (req, res) => {
  db.get("SELECT value FROM settings WHERE key = 'app_token'", (err, row) => {
    if (err) {
      return res.status(500).json({ msg: '获取 APP Token 失败', error: err.message });
    }
    
    res.json({ token: row ? row.value : '' });
  });
});

app.post('/api/app-token', authenticateJWT, logAction('更新APP Token'), (req, res) => {
  const { token } = req.body;
  
  if (!token) {
    return res.status(400).json({ msg: 'APP Token 必填' });
  }
  
  db.run(
    "UPDATE settings SET value = ?, updated_at = CURRENT_TIMESTAMP WHERE key = 'app_token'",
    [token],
    function(err) {
      if (err) {
        return res.status(500).json({ msg: '更新 APP Token 失败', error: err.message });
      }
      
      res.json({ msg: 'APP Token 更新成功' });
    }
  );
});

// 通知发送 API - 修复留言为可选
app.post('/api/notify', logAction('发送通知'), async (req, res) => {
  try {
    const { plate, message } = req.body;
    
    // 验证必填参数
    if (!plate) {
      return res.status(400).json({ msg: '车牌号必填' });
    }
    
    // 查询车牌信息（完整匹配）
    db.get("SELECT * FROM plates WHERE plate = ?", [plate], (err, plateInfo) => {
      if (err) {
        return res.status(500).json({ msg: '查询车牌失败', error: err.message });
      }      
      
      if (!plateInfo) {
        return res.status(404).json({ msg: '车牌不存在' });
      }
      
      // 查询 APP Token
      db.get("SELECT value FROM settings WHERE key = 'app_token'", async (err, tokenRow) => {
        if (err) {
          return res.status(500).json({ msg: '获取 APP Token 失败', error: err.message });
        }
        
        if (!tokenRow || !tokenRow.value) {
          return res.status(500).json({ msg: 'APP Token 未配置' });
        }
        
        // 构造消息内容
        const { uids, remark } = plateInfo;
        
        // 验证UID格式
        const validUids = uids.split(',').filter(uid => uid.trim() !== '');
        if (!validUids.length) {
          return res.status(400).json({ msg: '该车牌尚未配置有效的接收用户' });
        }
        
        // 构造通知内容，留言为可选
        const content = message 
          ? `【挪车通知】车牌 ${plateInfo.plate}（备注：${remark || '无'}）需要挪车，来自 IP: ${req.ip}。留言：${message} 请及时处理！`
          : `【挪车通知】车牌 ${plateInfo.plate}（备注：${remark || '无'}）需要挪车，来自 IP: ${req.ip}。请及时处理！`;
        
        try {
          const response = await fetch("https://wxpusher.zjiecode.com/api/send/message", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              appToken: tokenRow.value,
              content,
              contentType: 1,
              uids: validUids
            })
          });          
          
          // 检查HTTP响应状态
          if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
          }
          
          const result = await response.json();
          
          if (result.code === 1000) {
            res.json({ msg: '通知发送成功', requestId: result.data[0].requestId });
          } else {
            res.status(500).json({ msg: `发送失败: ${result.msg || '未知错误'}`, code: result.code });
          }
        } catch (networkError) {
          // 记录详细错误信息
          console.error('发送通知网络错误:', networkError);
          res.status(500).json({ 
            msg: '发送通知时网络错误', 
            error: networkError.message,
            stack: networkError.stack
          });
        }
      });
    });
  } catch (error) {
    res.status(500).json({ msg: '服务器错误', error: error.message });
  }
});

// 日志查询 API - 修复日志详情显示错误
app.get('/api/logs', authenticateJWT, (req, res) => {
  const { page = 1, limit = 20, action } = req.query;
  const offset = (page - 1) * limit;
  let query = "SELECT * FROM logs";
  let countQuery = "SELECT COUNT(*) as total FROM logs";
  const params = [];
  const countParams = [];
  
  if (action) {
    query += " WHERE action = ?";
    countQuery += " WHERE action = ?";
    params.push(action);
    countParams.push(action);
  }
  
  query += " ORDER BY created_at DESC LIMIT ? OFFSET ?";
  params.push(limit, offset);
  
  db.all(query, params, (err, rows) => {
    if (err) {
      return res.status(500).json({ msg: '获取日志失败', error: err.message });
    }
    
    // 解析details字段的JSON数据
    const logsWithDetails = rows.map(row => {
      try {
        return {
          ...row,
          details: row.details ? JSON.parse(row.details) : null
        };
      } catch (e) {
        console.error('解析日志详情失败:', e);
        return {
          ...row,
          details: { error: '日志详情解析失败', raw: row.details }
        };
      }
    });
    
    db.get(countQuery, countParams, (err, countRow) => {
      res.json({
        logs: logsWithDetails,
        pagination: {
          total: countRow ? countRow.total : 0,
          page: parseInt(page),
          limit: parseInt(limit),
          pages: Math.ceil((countRow ? countRow.total : 0) / limit)
        }
      });
    });
  });
});

// 批量删除日志 API - 修复删除功能
app.delete('/api/logs', authenticateJWT, logAction('删除日志'), (req, res) => {
  try {
    const { ids } = req.body;
    
    // 验证ids参数是否为数组且不为空
    if (!Array.isArray(ids) || ids.length === 0) {
      return res.status(400).json({ msg: '请提供有效的日志ID数组' });
    }
    
    // 过滤并验证ID格式（UUID格式简单验证）
    const validIds = ids.filter(id => /^[0-9a-fA-F-]{36}$/.test(id));
    if (validIds.length === 0) {
      return res.status(400).json({ msg: '未提供有效的日志ID' });
    }
    
    const placeholders = validIds.map(() => '?').join(',');
    
    db.run(
      `DELETE FROM logs WHERE id IN (${placeholders})`,
      validIds,
      function(err) {
        if (err) {
          console.error('删除日志数据库错误:', err);
          return res.status(500).json({ msg: '删除日志失败', error: err.message });
        }
        
        res.json({ 
          msg: `成功删除 ${this.changes} 条日志`,
          deletedCount: this.changes,
          requestedCount: validIds.length
        });
      }
    );
  } catch (error) {
    console.error('删除日志请求处理错误:', error);
    res.status(500).json({ msg: '服务器处理删除请求时出错', error: error.message });
  }
});

// 根路径重定向到发送通知页面
app.get('/', (req, res) => {
  res.redirect('/admin/index.html');
});

// 404 处理
app.use((req, res) => {
  res.status(404).json({ msg: '接口不存在' });
});

// 启动服务器
app.listen(PORT, () => {
  console.log(`✅ 服务已启动：http://localhost:${PORT}`);
  console.log(`🔑 后台登录：http://localhost:${PORT}/admin/login.html`);
});

// 优雅关闭
process.on('SIGINT', () => {
  db.close((err) => {
    if (err) {
      console.error('关闭数据库连接失败:', err.message);
    } else {
      console.log('数据库连接已关闭');
    }
    process.exit(0);
  });
});
