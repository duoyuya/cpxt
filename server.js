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
const plateRegex = /^[\u4e00-\u9fa5][A-Z0-9]{6,7}$/;
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
    process.on('unhandledRejection', (reason) => {
      const logId = uuidv4();
      const details = {
        path: req.path,
        method: req.method,
        error: reason.toString(),
        stack: reason.stack
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
  
  // 验证车牌格式 - 第一位为汉字，总长度7-8位，后续为字母或数字
  const plateRegex = /^[\u4e00-\u9fa5][A-Z0-9]{6,7}$/;
  if (!plateRegex.test(plate)) {
    return res.status(400).json({ msg: '车牌号格式不正确，第一位必须为汉字，总长度7-8位，后续为字母或数字' });
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
  
  // 使用全局定义的车牌验证正则表达式
  if (!plateRegex.test(plate)) {
    return res.status(400).json({ 
      msg: '车牌号格式不正确，第一位必须为汉字（标准车牌7位：如云A12345，新能源车牌8位：如云A1234567），后续为字母或数字' 
    });
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

// 系统设置 API
app.get('/api/system-settings', authenticateJWT, (req, res) => {
  try {
    db.all("SELECT key, value FROM settings", (err, settings) => {
      if (err) {
    return res.status(500).json({ msg: '获取系统设置失败', error: err.message });
      }
      
      const result = {};
      settings.forEach(item => {
        result[item.key] = item.value;
      });
      
      res.json(result);
    });
  } catch (error) {
    res.status(500).json({ msg: '服务器错误', error: error.message });
  }
});

app.post('/api/system-settings', authenticateJWT, logAction('更新系统设置'), (req, res) => {
  try {
    const settings = req.body;
    const keys = Object.keys(settings);
    
    if (keys.length === 0) {
      return res.status(400).json({ msg: '没有需要更新的设置' });
    } 
    
    // 使用事务处理多个更新
    db.run("BEGIN TRANSACTION", function(err) {
      if (err) {
        return res.status(500).json({ msg: '事务开始失败', error: err.message });
      }
      
      let completed = 0;
      let hasError = false;
      
      keys.forEach(key => {
        db.run(
          "UPDATE settings SET value = ?, updated_at = CURRENT_TIMESTAMP WHERE key = ?",
          [settings[key], key],
          function(err) {
            if (err) {
              hasError = true;
              console.error(`更新设置 ${key} 失败:`, err.message);
            }
            
            completed++;
            
            // 所有设置都已处理
            if (completed === keys.length) {
              if (hasError) {
                db.run("ROLLBACK", function() {
                  res.status(500).json({ msg: '部分设置更新失败，已回滚' });
                });
              } else {
                db.run("COMMIT", function() {
                  res.json({ msg: '系统设置更新成功' });
                });
              }
            }
          }
        );
      });
    });
  } catch (error) {
    res.status(500).json({ msg: '服务器错误', error: error.message });
  }
});

// APP Token 管理 (保留向后兼容)
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

// 发送企业微信通知
async function sendWechatWorkNotification(webhook, content) {
  try {
    const response = await fetch(webhook, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        msgtype: "text",
        text: { content: content }
      })
    });
    return await response.json();
  } catch (error) {
    console.error("企业微信通知发送失败:", error);
    throw error;
  }
}

// 发送钉钉通知
async function sendDingtalkNotification(webhook, content) {
  try {
    const response = await fetch(webhook, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        msgtype: "text",
        text: { content: content }
      })
    });
    return await response.json();
  } catch (error) {
    console.error("钉钉通知发送失败:", error);
    throw error;
  }
}

// 发送Bark通知
async function sendBarkNotification(webhook, content) {
  try {
    const title = "挪车通知";
    const encodedTitle = encodeURIComponent(title);
    const encodedContent = encodeURIComponent(content);
    const url = webhook + "/" + encodedTitle + "/" + encodedContent;
    const response = await fetch(url);
    return await response.json();
  } catch (error) {
    console.error("Bark通知发送失败:", error);
    throw error;
  }
}

// 通知发送 API - 已修复语法错误
app.post('/api/notify', logAction('发送通知'), async (req, res) => {
  try {
    const { plate, phone, channels } = req.body;
    
    // 验证必填参数
    if (!plate) {
      return res.status(400).json({ msg: '车牌号必填' });
    }
    
    if (!phone || phone.length !== 11 || !phone.startsWith('1')) {
      return res.status(400).json({ msg: '请输入有效的11位手机号' });
    }
    
    // 查询车牌信息（完整匹配）
    db.get("SELECT * FROM plates WHERE plate = ?", [plate], (err, plateInfo) => {
      if (err) {
        return res.status(500).json({ msg: '查询车牌失败', error: err.message });
      }      
      
      if (!plateInfo) {
        return res.status(404).json({ msg: '车牌不存在' });
      }
      
      // 查询所有通知配置
      db.all("SELECT key, value FROM settings WHERE key IN ('app_token', 'wechat_work_webhook', 'dingtalk_webhook', 'bark_webhook', 'notification_channels')", 
        async (err, settings) => {
          if (err) {
            return res.status(500).json({ msg: '获取配置失败', error: err.message });
          }
          
          // 解析配置
          const config = {};
          settings.forEach(item => {
            if (item.key === 'notification_channels') {
              config[item.key] = JSON.parse(item.value);
            } else {
              config[item.key] = item.value;
            }
          });
          
          // 确定发送渠道（请求指定或使用默认）
          const sendChannels = channels && channels.length 
            ? channels 
            : config.notification_channels || ['wxpusher'];
          
          // 构造通知内容
          const { remark } = plateInfo;
          const content = "【挪车通知】车牌 " + plateInfo.plate + "（备注：" + (remark || "无") + "）需要挪车，联系电话：" + phone + "。请及时处理！";
          
          // 发送结果
          const results = {};
          
          try {
            // 发送到选中的渠道
            for (const channel of sendChannels) {
              switch (channel) {
                case 'wxpusher':
                  if (config.app_token) {
                    const response = await fetch("https://wxpusher.zjiecode.com/api/send/message", {
                      method: "POST",
                      headers: { "Content-Type": "application/json" },
                      body: JSON.stringify({
                        appToken: config.app_token,
                        content: content,
                        contentType: 1,
                        uids: plateInfo.uids.split(',').filter(uid => uid.trim() !== '')
                      })
                    });
                    results.wxpusher = await response.json();
                  } else {
                    results.wxpusher = { error: '未配置wxpusher token' };
                  }
                  break;
                  
                case 'wechat_work':
                  if (config.wechat_work_webhook) {
                    results.wechat_work = await sendWechatWorkNotification(config.wechat_work_webhook, content);
                  } else {
                    results.wechat_work = { error: '未配置企业微信webhook' };
                  }
                  break;
                  
                case 'dingtalk':
                  if (config.dingtalk_webhook) {
                    results.dingtalk = await sendDingtalkNotification(config.dingtalk_webhook, content);
                  } else {
                    results.dingtalk = { error: '未配置钉钉webhook' };
                  }
                  break;
                  
                case 'bark':
                  if (config.bark_webhook) {
                    results.bark = await sendBarkNotification(config.bark_webhook, content);
                  } else {
                    results.bark = { error: '未配置Bark webhook' };
                  }
                  break;
                  
                default:
                  results[channel] = { error: '不支持的通知渠道' };
              }
            }
            
            res.json({ 
              msg: '通知发送完成', 
              results: results 
            });
            
          } catch (networkError) {
            res.status(500).json({ 
              msg: '发送通知时网络错误', 
              error: networkError.message
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

// 删除选中日志 API - 修复删除功能
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
      "DELETE FROM logs WHERE id IN (" + placeholders + ")",
      validIds,
      function(err) {
        if (err) {
          console.error('删除日志数据库错误:', err);
          return res.status(500).json({ msg: '删除日志失败', error: err.message });
        }
        
        res.json({ 
          msg: "成功删除 " + this.changes + " 条日志",
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
  console.log("✅ 服务已启动：http://localhost:" + PORT);
  console.log("🔑 后台登录：http://localhost:" + PORT + "/admin/login.html");
});