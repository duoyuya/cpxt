const fetch = require('node-fetch');

/**
 * 通知服务类 - 统一管理多种通知方式
 */
class NotificationService {
  constructor() {
    // 初始化通知方式映射表
    this.notificationTypes = {
      wxpusher: this.sendWXPusher.bind(this),
      wechatWork: this.sendWechatWork.bind(this),
      dingtalk: this.sendDingtalk.bind(this),
      bark: this.sendBark.bind(this)
    };
  }

  /**
   * 统一发送通知入口
   * @param {Object} options - 通知选项
   * @param {string[]} options.types - 通知方式数组 ['wxpusher', 'wechatWork', 'dingtalk', 'bark']
   * @param {string} options.content - 通知内容
   * @param {Object} options.config - 各通知方式的配置
   * @param {string[]} [options.uids] - WXPusher用户ID数组
   * @returns {Promise<Object>} 各通知方式的发送结果
   */
  async sendNotification(options) {
    const { types, content, config, uids = [] } = options;
    const results = {};

    if (!types || !types.length) {
      throw new Error('至少需要指定一种通知方式');
    }

    if (!content) {
      throw new Error('通知内容不能为空');
    }

    // 并行发送所有指定的通知
    await Promise.all(types.map(async (type) => {
      try {
        if (this.notificationTypes[type]) {
          results[type] = {
            success: true,
            data: await this.notificationTypes[type](content, config, uids)
          };
        } else {
          results[type] = {
            success: false,
            error: `不支持的通知方式: ${type}`
          };
        }
      } catch (error) {
        results[type] = {
          success: false,
          error: error.message,
          stack: error.stack
        };
      }
    }));

    return results;
  }

  /**
   * 发送WXPusher通知
   * @param {string} content - 通知内容
   * @param {Object} config - WXPusher配置
   * @param {string[]} uids - 用户ID数组
   * @returns {Promise<Object>} 发送结果
   */
  async sendWXPusher(content, config, uids) {
    if (!config.wxpusherAppToken) {
      throw new Error('WXPusher AppToken未配置');
    }

    if (!uids || !uids.length) {
      throw new Error('WXPusher需要至少一个用户UID');
    }

    const response = await fetch("https://wxpusher.zjiecode.com/api/send/message", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        appToken: config.wxpusherAppToken,
        content,
        contentType: 1,
        uids: uids.filter(uid => uid.trim())
      })
    });

    if (!response.ok) {
      throw new Error(`WXPusher请求失败: ${response.status} ${response.statusText}`);
    }

    const result = await response.json();
    
    if (result.code !== 1000) {
      throw new Error(`WXPusher发送失败: ${result.msg || '未知错误'}`);
    }

    return result.data;
  }

  /**
   * 发送企业微信通知
   * @param {string} content - 通知内容
   * @param {Object} config - 企业微信配置
   * @returns {Promise<Object>} 发送结果
   */
  async sendWechatWork(content, config) {
    if (!config.wechatWorkWebhook) {
      throw new Error('企业微信Webhook未配置');
    }

    // 企业微信机器人消息格式
    const message = {
      msgtype: "text",
      text: {
        content: content
      }
    };

    const response = await fetch(config.wechatWorkWebhook, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(message)
    });

    if (!response.ok) {
      throw new Error(`企业微信请求失败: ${response.status} ${response.statusText}`);
    }

    const result = await response.json();
    
    if (result.errcode !== 0) {
      throw new Error(`企业微信发送失败: ${result.errmsg || '未知错误'}`);
    }

    return result;
  }

  /**
   * 发送钉钉通知
   * @param {string} content - 通知内容
   * @param {Object} config - 钉钉配置
   * @returns {Promise<Object>} 发送结果
   */
  async sendDingtalk(content, config) {
    if (!config.dingtalkWebhook) {
      throw new Error('钉钉Webhook未配置');
    }

    // 钉钉机器人消息格式
    const message = {
      msgtype: "text",
      text: {
        content: content
      }
    };

    // 如果钉钉webhook包含签名，则直接使用
    const response = await fetch(config.dingtalkWebhook, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(message)
    });

    if (!response.ok) {
      throw new Error(`钉钉请求失败: ${response.status} ${response.statusText}`);
    }

    const result = await response.json();
    
    if (result.errcode !== 0) {
      throw new Error(`钉钉发送失败: ${result.errmsg || '未知错误'}`);
    }

    return result;
  }

  /**
   * 发送Bark通知
   * @param {string} content - 通知内容
   * @param {Object} config - Bark配置
   * @returns {Promise<Object>} 发送结果
   */
  async sendBark(content, config) {
    if (!config.barkServer || !config.barkToken) {
      throw new Error('Bark服务器地址和设备Token未配置');
    }

    // 处理Bark服务器地址格式
    const serverUrl = config.barkServer.endsWith('/') 
      ? config.barkServer 
      : `${config.barkServer}/`;
      
    const url = `${serverUrl}${config.barkToken}/${encodeURIComponent('挪车通知')}/${encodeURIComponent(content)}`;

    const response = await fetch(url, {
      method: "GET"
    });

    if (!response.ok) {
      throw new Error(`Bark请求失败: ${response.status} ${response.statusText}`);
    }

    const result = await response.json();
    
    if (!result.success) {
      throw new Error(`Bark发送失败: ${JSON.stringify(result)}`);
    }

    return result;
  }
}

module.exports = new NotificationService();
