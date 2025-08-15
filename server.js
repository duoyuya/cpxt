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

// 启动日志 - 非常详细的启动过程记录
console.log('=============================================');
console.log('🚀 开始启动 car-notify-system v1.0.0');
console.log('=============================================');
console.log('⏰ 启动时间:', new Date().toISOString());
console.log('📦 加载核心模块...');

// 确保数据目录存在并检查权限
const dataDir = path.join(__dirname, 'data');
function checkDataDirPermissions() {
  try {
    console.log('📂 检查数据目录:', dataDir);
    // 检查目录是否存在
    if (!fs.existsSync(dataDir)) {
      console.log('📂 数据目录不存在，尝试创建...');
      fs.mkdirSync(dataDir, { recursive: true, mode: 0o755 });
    }
    
    // 检查写入权限
    const testFile = path.join(dataDir, 'test_permission.txt');
    console.log('📝 测试文件写入:', testFile);
    fs.writeFileSync(testFile, 'test');
    fs.unlinkSync(testFile);
    console.log('✅ 数据目录权限检查通过');
  } catch (err) {
    console.error('❌ 数据目录权限检查失败:', err.message);
    console.error('💡 解决方案: 确保容器内/data目录具有读写权限');
    process.exit(1);
  }
}

try {
  console.log('🔧 执行数据目录检查...');
  checkDataDirPermissions();
} catch (err) {
  console.error('💥 数据目录检查过程出错:', err.message);
  process.exit(1);
}

// 加载环境变量
console.log('🔧 加载环境变量...');
dotenv.config();
console.log('🔧 验证必要的环境变量...');
const requiredEnvVars = ['JWT_SECRET'];
const missingEnvVars = requiredEnvVars.filter(env => !process.env[env]);
if (missingEnvVars.length > 0) {
  console.error('❌ 缺少必要的环境变量:', missingEnvVars.join(', '));
  console.error('💡 解决方案: 在.env文件中设置必要的环境变量');
  process.exit(1);
}
console.log('✅ 环境变量检查通过');

// 引入通知服务并处理可能的错误
let notificationService;
try {
  console.log('🔧 加载通知服务模块...');
  notificationService = require('./notificationService');
  console.log('✅ 通知服务加载成功');
} catch (err) {
  console.error('❌ 加载通知服务失败:', err.message);
  console.error('💡 解决方案: 检查notificationService.js文件是否存在且格式正确');
  process.exit(1);
}

console.log('🔧 初始化Express应用...');
const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '24h';
const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';

console.log('🔧 配置Express中间件...');
app.use(express.json());
app.use('/admin', express.static(path.join(__dirname, 'admin')));
console.log('✅ Express应用初始化完成');

// 初始化数据库并添加错误处理
let db;
try {
  const dbPath = path.join(dataDir, 'car_notify.db');
  console.log('📦 数据库路径: ', dbPath);
  
  console.log('🔧 尝试连接数据库...');
  db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
      console.error('❌ 数据库连接错误:', err.message);
      console.error('💡 解决方案: 检查数据库文件权限或删除旧数据库文件重试');
      process.exit(1);
    } else {
      console.log('✅ SQLite 数据库连接成功');
      console.log('🔧 开始数据库初始化...');
      initDatabase();
    }
  });
  
  // 监听数据库错误
  db.on('error', (err) => {
    console.error('❌ 数据库运行错误:', err.message);
  });
} catch (err) {
  console.error('❌ 数据库初始化失败:', err.message);
  process.exit(1);
}

// 数据库初始化函数 - 包含表结构迁移
function initDatabase() {
  try {
    console.log('🔧 开始数据库表结构初始化...');
    // 先创建新表结构
    db.run(`CREATE TABLE IF NOT EXISTS plates_new (
      id TEXT PRIMARY KEY,
      plate TEXT NOT NULL UNIQUE,
      uids TEXT NOT NULL,
      remark TEXT,
      notification_types TEXT DEFAULT '["wxpusher"]',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`, (err) => {
      if (err) {
        console.error('❌ 创建新plates表错误:', err.message);
        // 如果是表已存在错误，则跳过
        if (!err.message.includes('already exists')) {
          console.error('💡 解决方案: 删除旧数据库文件后重试');
          return;
        }
        console.log('ℹ️ 新plates表已存在，跳过创建');
      } else {
        console.log('✅ 新plates表创建成功');
      }
      
      // 检查旧表是否存在
      console.log('🔍 检查旧表是否存在...');
      db.get("SELECT name FROM sqlite_master WHERE type='table' AND name='plates'", (err, row) => {
        if (err) {
          console.error('❌ 检查旧表错误:', err.message);
          return;
        }
        
        if (row) {
          console.log('ℹ️ 发现旧表结构，需要检查是否需要迁移...');
          // 查询表结构
          db.all("PRAGMA table_info(plates)", (err, columns) => {
            if (err) {
              console.error('❌ 查询表结构错误:', err.message);
              return;
            }
            
            const hasNotificationColumn = columns.some(col => col.name === 'notification_types');
            
            if (!hasNotificationColumn) {
              console.log('🔄 检测到旧表结构，需要迁移数据...');
              migratePlateData();
            } else {
              console.log('✅ plates表结构已存在且最新');
              continueDatabaseInit();
            }
          });
        } else {
          console.log('ℹ️ 未发现旧表，直接重命名新表...');
          // 旧表不存在，直接重命名新表
          db.run("ALTER TABLE plates_new RENAME TO plates", (err) => {
            if (err) {
              console.error('❌ 重命名新表错误:', err.message);
              console.error('💡 解决方案: 删除旧数据库文件后重试');
              return;
            }
            console.log('✅ plates表重命名成功');
            continueDatabaseInit();
          });
        }
      });
    });
  } catch (err) {
    console.error('❌ 数据库表初始化失败:', err.message);
    process.exit(1);
  }
}

// 迁移旧表数据到新表
function migratePlateData() {
  console.log('🚚 开始数据迁移...');
  db.run("BEGIN TRANSACTION", err => {
    if (err) {
      console.error('❌ 开始迁移事务失败:', err.message);
      continueDatabaseInit();
      return;
    }
    
    // 复制旧表数据到新表
    db.run(`INSERT INTO plates_new (id, plate, uids, remark, created_at, updated_at)
            SELECT id, plate, uids, remark, created_at, updated_at FROM plates`, function(err) {
      if (err) {
        console.error('❌ 迁移数据错误:', err.message);
        db.run("ROLLBACK", () => {
          console.log('🔄 事务回滚完成');
          continueDatabaseInit();
        });
        return;
      }
      
      console.log(`✅ 迁移数据成功，共迁移 ${this.changes} 条记录`);
      
      // 删除旧表
      db.run("DROP TABLE plates", (err) => {
        if (err) {
          console.error('❌ 删除旧表错误:', err.message);
          db.run("ROLLBACK", () => {
            console.log('🔄 事务回滚完成');
            continueDatabaseInit();
          });
          return;
        }
        
        console.log('✅ 旧表删除成功');
        
        // 重命名新表
        db.run("ALTER TABLE plates_new RENAME TO plates", (err) => {
          if (err) {
            console.error('❌ 重命名新表错误:', err.message);
            db.run("ROLLBACK", () => {
              console.log('🔄 事务回滚完成');
              continueDatabaseInit();
            });
            return;
          }
          
          db.run("COMMIT", (err) => {
            if (err) {
              console.error('❌ 提交迁移事务错误:', err.message);
            } else {
              console.log('✅ 表结构迁移事务提交成功');
            }
            continueDatabaseInit();
          });
        });
      });
    });
  });
}

// 继续初始化其他表
function continueDatabaseInit() {
  console.log('🔧 继续初始化其他表结构...');
  
  // 创建其他表结构
  db.run(`CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  )`, (err) => {
    if (err) {
      console.error('❌ 创建settings表错误:', err.message);
    } else {
      console.log('✅ settings表初始化成功');
    }
  });
  
  db.run(`CREATE TABLE IF NOT EXISTS logs (
    id TEXT PRIMARY KEY,
    action TEXT NOT NULL,
    details TEXT,
    ip TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  )`, (err) => {
    if (err) {
      console.error('❌ 创建logs表错误:', err.message);
    } else {
      console.log('✅ logs表初始化成功');
    }
  });
  
  db.run(`CREATE TABLE IF NOT EXISTS access_tokens (
    id TEXT PRIMARY KEY,
    plate TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    used INTEGER DEFAULT 0
  )`, (err) => {
    if (err) {
      console.error('❌ 创建access_tokens表错误:', err.message);
    } else {
      console.log('✅ access_tokens表初始化成功');
    }
  });
  
  // 初始化默认设置
  console.log('🔧 初始化默认系统设置...');
  const defaultSettings = [
    { key: 'app_token', value: 'AT_dHj0kby8R58ywAo8MW272n2ike2Uv7rs' },
    { key: 'wechat_work_webhook', value: '' },
    { key: 'dingtalk_webhook', value: '' },
    { key: 'bark_server', value: 'https://api.day.app/' },
    { key: 'bark_token', value: '' }
  ];
  
  let initializedCount = 0;
  defaultSettings.forEach(({ key, value }) => {
    db.get(`SELECT * FROM settings WHERE key = ?`, [key], (err, row) => {
      if (err) {
        console.error(`❌ 查询设置 ${key} 失败:`, err.message);
        return;
      }
      if (!row) {
        db.run(`INSERT INTO settings (key, value) VALUES (?, ?)`, [key, value], function(err) {
          if (err) {
            console.error(`❌ 初始化设置 ${key} 失败:`, err.message);
          } else {
            console.log(`✅ 初始化设置 ${key} 成功`);
          }
          initializedCount++;
          if (initializedCount === defaultSettings.length) {
            completeInitialization();
          }
        });
      } else {
        console.log(`ℹ️ 设置 ${key} 已存在，跳过初始化`);
        initializedCount++;
        if (initializedCount === defaultSettings.length) {
          completeInitialization();
        }
      }
    });
  });
}

// 完成初始化并启动服务器
function completeInitialization() {
  console.log('=============================================');
  console.log('✅ 所有初始化步骤完成!');
  console.log('=============================================');
  
  // 每小时清理过期令牌
  console.log('🔧 设置定时任务: 每小时清理过期令牌');
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
  
  // 系统设置 API - 新增
  app.get('/api/settings', authenticateJWT, (req, res) => {
    db.all("SELECT * FROM settings", (err, rows) => {
      if (err) {
        return res.status(500).json({ msg: '获取设置失败', error: err.message });
      }
      
      const settings = {};
      rows.forEach(row => {
        settings[row.key] = row.value;
      });
      
      res.json(settings);
    });
  });
  
  // 更新系统设置 API - 新增
  app.put('/api/settings', authenticateJWT, logAction('更新系统设置'), (req, res) => {
    const settings = req.body;
    
    if (!settings || typeof settings !== 'object') {
      return res.status(400).json({ msg: '设置参数必须是对象' });
    }
    
    // 使用事务确保所有设置都更新成功
    db.run("BEGIN TRANSACTION", err => {
      if (err) {
        return res.status(500).json({ msg: '开始事务失败', error: err.message });
      }
      
      const keys = Object.keys(settings);
      let completed = 0;
      let hasError = false;
      
      keys.forEach(key => {
        db.run(
          "UPDATE settings SET value = ?, updated_at = CURRENT_TIMESTAMP WHERE key = ?",
          [settings[key], key],
          function(err) {
            if (err) {
              hasError = true;
              return db.run("ROLLBACK", () => {
                res.status(500).json({ msg: `更新设置 ${key} 失败`, error: err.message });
              });
            }
            
            completed++;
            if (completed === keys.length && !hasError) {
              db.run("COMMIT", err => {
                if (err) {
                  return res.status(500).json({ msg: '提交事务失败', error: err.message });
                }
                res.json({ msg: '系统设置更新成功', updatedCount: keys.length });
              });
            }
          }
        );
      });
    });
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
        uids: row.uids.split(','),
        notification_types: JSON.parse(row.notification_types || '["wxpusher"]')
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
        uids: row.uids.split(','),
        notification_types: JSON.parse(row.notification_types || '["wxpusher"]')
      });
    });
  });
  
  app.post('/api/plates', authenticateJWT, logAction('添加车牌'), (req, res) => {
    try {
      const { plate, uids, remark, notification_types = ['wxpusher'] } = req.body;
      
      console.log('📥 添加车牌请求参数:', {
        plate,
        uids,
        remark,
        notification_types,
        plateLength: plate ? plate.length : 0,
        plateChars: plate ? plate.split('').map(c => `0x${c.charCodeAt(0).toString(16)}(${c})`).join(' ') : 'undefined'
      });
      
      // 基本参数验证
      if (!plate || !uids || !uids.length) {
        return res.status(400).json({ msg: '车牌号和 UID 必填' });
      }
      
      // 验证车牌格式 - 第一位为汉字，总长度7-8位，后续为字母或数字
      const plateRegex = /^[\u4e00-\u9fa5][A-Z0-9]{6,7}$/;
      if (!plateRegex.test(plate)) {
        return res.status(400).json({ 
          msg: '车牌号格式不正确，第一位必须为汉字，总长度7-8位，后续为字母或数字',
          debug: {
            input: plate,
            length: plate.length,
            regex: plateRegex.toString(),
            testResult: plateRegex.test(plate),
            firstChar: plate ? plate[0] : 'undefined',
            firstCharCode: plate ? plate.charCodeAt(0) : 'undefined',
            isChinese: plate ? /^[\u4e00-\u9fa5]$/.test(plate[0]) : false
          }
        });
      }
      
      // 验证通知方式
      const validNotificationTypes = ['wxpusher', 'wechatWork', 'dingtalk', 'bark'];
      const invalidTypes = notification_types.filter(type => !validNotificationTypes.includes(type));
      if (invalidTypes.length > 0) {
        return res.status(400).json({ msg: `无效的通知方式: ${invalidTypes.join(', ')}` });
      }
      
      // 数据库文件权限检查
      const dbPath = path.join(dataDir, 'car_notify.db');
      try {
        fs.accessSync(dbPath, fs.constants.W_OK);
        console.log('✅ 数据库文件可写');
      } catch (err) {
        console.error('❌ 数据库文件不可写:', err.message);
        return res.status(500).json({ 
          msg: '数据库写入权限不足',
          error: err.message,
          solution: '检查容器数据目录挂载权限'
        });
      }
      
      const plateId = uuidv4();
      const uidsStr = Array.isArray(uids) ? uids.join(',') : uids;
      const notificationTypesStr = JSON.stringify(notification_types);
      
      console.log('📥 准备插入数据库:', {
        plateId,
        plate,
        uidsStr,
        notificationTypesStr
      });
      
      db.run(
        "INSERT INTO plates (id, plate, uids, remark, notification_types) VALUES (?, ?, ?, ?, ?)",
        [plateId, plate, uidsStr, remark || '', notificationTypesStr],
        function(err) {
          if (err) {
            console.error('❌ 添加车牌数据库错误:', {
              message: err.message,
              errno: err.errno,
              code: err.code,
              stack: err.stack
            });
            
            if (err.message.includes('UNIQUE constraint failed')) {
              return res.status(400).json({ 
                msg: '该车牌号已存在',
                plate: plate
              });
            } else if (err.message.includes('no such column: notification_types')) {
              return res.status(500).json({ 
                msg: '数据库表结构过时',
                error: err.message,
                solution: '请删除旧数据库文件或执行数据迁移'
              });
            } else if (err.message.includes('permission denied')) {
              return res.status(500).json({ 
                msg: '数据库写入权限不足',
                error: err.message,
                solution: '检查容器数据目录挂载权限'
              });
          
            return res.status(500).json({ 
              msg: '添加车牌失败', 
              error: err.message,
              errno: err.errno,
              code: err.code,
              debug: {
                plate,
                plateId,
                dbPath: path.join(dataDir, 'car_notify.db')
              }
            });
          }
          
          console.log(`✅ 车牌添加成功: ${plate} (ID: ${plateId})`);
          res.status(201).json({ 
            msg: '车牌添加成功', 
            id: plateId,
            plate: plate
          });
        }
      );
    } catch (error) {
      console.error('❌ 添加车牌请求处理错误:', {
        message: error.message,
        stack: error.stack
      });
      res.status(500).json({ 
        msg: '添加车牌请求处理错误', 
        error: error.message,
        stack: error.stack
      });
    }
  });
  
  app.put('/api/plates/:id', authenticateJWT, logAction('更新车牌'), (req, res) => {
    const { plate, uids, remark, notification_types = ['wxpusher'] } = req.body;
    
    if (!plate || !uids || !uids.length) {
      return res.status(400).json({ msg: '车牌号和 UID 必填' });
    }
    
    // 验证车牌格式 - 第一位为汉字，总长度7-8位，后续为字母或数字
    const plateRegex = /^[\u4e00-\u9fa5][A-Z0-9]{6,7}$/;
    if (!plateRegex.test(plate)) {
      return res.status(400).json({ msg: '车牌号格式不正确，第一位必须为汉字，总长度7-8位，后续为字母或数字' });
    }
    
    // 验证通知方式
    const validNotificationTypes = ['wxpusher', 'wechatWork', 'dingtalk', 'bark'];
    const invalidTypes = notification_types.filter(type => !validNotificationTypes.includes(type));
    if (invalidTypes.length > 0) {
      return res.status(400).json({ msg: `无效的通知方式: ${invalidTypes.join(', ')}` });
    }
    
    const uidsStr = Array.isArray(uids) ? uids.join(',') : uids;
    const notificationTypesStr = JSON.stringify(notification_types);
    
    db.run(
      "UPDATE plates SET plate = ?, uids = ?, remark = ?, notification_types = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
      [plate, uidsStr, remark || '', notificationTypesStr, req.params.id],
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
  
  // 通知发送 API - 修改为支持多种通知方式
  app.post('/api/notify', logAction('发送通知'), async (req, res) => {
    try {
      const { plate, phone } = req.body;
      
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
        
        // 查询所有系统设置
        db.all("SELECT * FROM settings", (err, settingsRows) => {
          if (err) {
            return res.status(500).json({ msg: '获取系统设置失败', error: err.message });
          }
          
          // 整理设置
          const settings = {};
          settingsRows.forEach(row => {
            settings[row.key] = row.value;
          });
          
          // 验证通知方式配置
          let notificationTypes;
          try {
            notificationTypes = JSON.parse(plateInfo.notification_types || '["wxpusher"]');
          } catch (e) {
            return res.status(500).json({ msg: '解析通知方式配置失败', error: e.message });
          }
          
          if (!notificationTypes || !notificationTypes.length) {
            return res.status(400).json({ msg: '未配置通知方式' });
          }
          
          // 验证各通知方式的配置
          const config = {
            wxpusherAppToken: settings.app_token,
            wechatWorkWebhook: settings.wechat_work_webhook,
            dingtalkWebhook: settings.dingtalk_webhook,
            barkServer: settings.bark_server || 'https://api.day.app/',
            barkToken: settings.bark_token
          };
          
          // 检查企业微信配置
          if (notificationTypes.includes('wechatWork') && !config.wechatWorkWebhook) {
            return res.status(400).json({ msg: '企业微信Webhook未配置' });
          }
          
          // 检查钉钉配置
          if (notificationTypes.includes('dingtalk') && !config.dingtalkWebhook) {
            return res.status(400).json({ msg: '钉钉Webhook未配置' });
          }
          
          // 检查Bark配置
          if (notificationTypes.includes('bark') && !config.barkToken) {
            return res.status(400).json({ msg: 'Bark设备Token未配置' });
          }
          
          // 构造通知内容
          const { uids, remark } = plateInfo;
          const validUids = uids.split(',').filter(uid => uid.trim() !== '');
          
          // 验证WXPusher UID
          if (notificationTypes.includes('wxpusher') && (!validUids || !validUids.length)) {
            return res.status(400).json({ msg: 'WXPusher需要至少一个用户UID' });
          }
          
          const content = `【挪车通知】车牌 ${plateInfo.plate}（备注：${remark || '无'}）需要挪车，联系电话：${phone}。请及时处理！`;
          
          // 调用通知服务发送通知
          notificationService.sendNotification({
            types: notificationTypes,
            content,
            config,
            uids: validUids
          })
          .then(results => {
            res.json({ 
              msg: '通知发送完成', 
              results 
            });
          })
          .catch(error => {
            res.status(500).json({ 
              msg: '发送通知失败', 
              error: error.message 
            });
          });
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
  
  // 启动服务器并添加错误处理
  try {
    console.log(`🚀 启动服务器，监听端口 ${PORT}...`);
    app.listen(PORT, () => {
      console.log(`✅ 服务已启动：http://localhost:${PORT}`);
      console.log(`🔑 后台登录：http://localhost:${PORT}/admin/login.html`);
      console.log(`📊 数据目录：${dataDir}`);
      console.log(`🔍 故障排查建议：`);
      console.log(`  1. 检查数据目录权限: ls -ld ${dataDir}`);
      console.log(`  2. 检查数据库文件权限: ls -l ${path.join(dataDir, 'car_notify.db')}`);
      console.log(`  3. 表结构过时请删除旧数据库文件: rm ${path.join(dataDir, 'car_notify.db')}`);
      console.log('=============================================');
      console.log('🎉 服务器启动成功!');
      console.log('=============================================');
    });
  } catch (err) {
    console.error('❌ 服务器启动失败:', err.message);
    process.exit(1);
  }
}

// 未捕获异常处理
process.on('uncaughtException', (err) => {
  console.error('❌ 未捕获的异常:', err.message);
  console.error(err.stack);
  
  // 尝试优雅关闭数据库连接
  if (db) {
    db.close((err) => {
      if (err) console.error('❌ 关闭数据库连接失败:', err.message);
      process.exit(1);
    });
  } else {
    process.exit(1);
  }
});

// 未处理的Promise拒绝处理
process.on('unhandledRejection', (reason, promise) => {
  console.error('❌ 未处理的Promise拒绝:', reason);
  console.error('Promise:', promise);
});

// 优雅关闭
process.on('SIGINT', () => {
  console.log('🔄 收到关闭信号，正在优雅关闭...');
  if (db) {
    db.close((err) => {
      if (err) {
        console.error('❌ 关闭数据库连接失败:', err.message);
      } else {
        console.log('✅ 数据库连接已关闭');
      }
      process.exit(0);
    });
  } else {
    process.exit(0);
  }
});