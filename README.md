# kfc-giftcard-retry-analyzer
Go multithreaded enumerator for KFC Hut gift cards. Identifies valid PINs by analyzing retry-frequency anomalies (non-541 errors) rather than relying solely on success flags.

# 礼品卡 paymentCode 枚举与重试分析工具

## 用途-仅针对必应积分世界杯肯德基礼品卡邮件密码错误问题

当微软肯德基礼品卡卡密后4位因数据错误被置为 `0000` 时，本工具通过遍历 `0000~9999` 并结合**服务器重试行为分析**，精准定位正确的密码。

## 核心原理（区别于传统爆破）

传统枚举只依赖 `errCode=0` 判断成功；本工具额外利用了一个关键现象：

- **错误密码（后4位错误）**：服务器快速返回 `errCode: 541`（卡号或密码错误），几乎不会触发重试。
- **正确密码（后4位正确）**：服务器需要校验金额、状态、风控等，在并发或网络抖动时容易发生超时/限流，进而触发客户端重试逻辑。

因此，在均匀的网络环境下，**正确密码所在的那一个请求，其重试次数会明显高于其他密码（通常 > 7 次）**。  
本工具完整遍历所有后缀，记录每个密码的重试次数，最终输出 **重试次数大于 7 的密码列表**，从而反推出正确密码。

> 这种“通过异常日志反推真实值”的思路，在工程排障中具有通用借鉴意义。

## 工作流程

1. 抓包获取用户 `token`、`cardSequence` 等参数。
2. 配置 `config.json`。
3. 运行程序，并发遍历 0000~9999。
4. 对每个密码：
   - 若返回 `errCode=0` 且有 `data`，标记为“真实密码”（控制台提示，但不直接写入文件）。
   - 若返回 `541`，直接跳过。
   - 若返回其他错误（超时、限流等），重试并记录该密码的重试次数。
5. 遍历结束后生成 `retry_analysis.txt`，包含：
   - **重试次数 > 7 的密码列表**（格式：`密码: 重试次数`）
   - 若找到真实密码，则额外显示卡号和完整密码。

## 使用方法

### 1. 使用Reqable抓包肯德基+小程序信息并选择配置文件config.json

使用Reqable抓包肯德基教程：
1. 环境准备
工具：Reqable（Windows/Mac 版）
环境：PC 端微信

2. 证书安装与配置
启动 Reqable，根据引导安装 Root CA 证书。
确保 Reqable 主界面右上角的 系统代理​ 与 HTTPS 解密（SSL）​ 图标均为绿色激活状态。

3. 进程级抓包（关键步骤）
为了避免微信小程序绕过系统代理，需启用 Reqable 的强制注入模式：
点击 Reqable 顶部菜单的 “调试”​ 按钮。
切换至 “进程代理”​ 选项卡。
在进程列表中勾选 WeChatAppEx.exe（微信小程序独立进程）。
此时 Reqable 将强制接管该进程的所有流量，无需修改微信内部代理设置。

4. 捕获请求与提取参数
在 PC 微信中打开 肯德基+​ 小程序，进入“礼品卡”或“绑定卡”页面。
输入邮件中错误的Card Number以及Activation Code。
在 Reqable 请求列表中，使用搜索功能过滤关键字：queryRealCardInfo。
点击该请求，在右侧 Request（请求）​ 面板中查看详情：
获取 Token：在请求体（Body）的 JSON 或 Form 数据中，找到 token字段。
获取 OpenID：在请求头（Headers）的 Cookie或 Referer中，或在响应体（Response）中查找 openId字段（通常以 o开头的 28 位字符串）。
### 2. 选择配置文件config.json
可参考的config使用案例（只需要输入邮件中给出的cardSequence、16位paymentPrefix（去除最末的0000）、通过reqable抓包获取的token以及openId）

{


    "cardSequence": "", #首掺杂数字和字母的15 位主体​ + 末尾常附 0000
    "paymentPrefix": "210010923555000",#16 位纯数字
    "token": "",#四段.两段的格式，注意单个token有一定的时间限制，若出现报错则需要重新抓包
    "openId": "",#o开头 + A-Z a-z 0-9 _ -（base64url 风格）的28 位"omxHq0xxxxxxxxxxxxxxxxxxxxxxxx"
    
    "secretKey": "kfc",
    "encodeList": ["smsCode"],
    "referer": "https://servicewechat.com/wx08ee7f7d36a2eff8/455/page-frame.html",
    "host": "appcamp.kfc.com.cn",

    "clientKey": "wxaupllQI8zMn8m8",
    "clientSec": "6nVSIvoC16X1kaVl",
    "signPath": "/card/queryRealCardInfo",
    "fullUrl": "https://appcamp.kfc.com.cn/api/card/queryRealCardInfo",

    "threads": 20,
    "maxRetry": 25,
    "retryWait": 3
}
### 3. 编译并执行生成的kfc_enum.exe
在vscode终端中编译：go build -o kfc_enum.exe kfc_enum.go
双击运行 kfc_enum.exe，程序将遍历所有后缀，生成retry_analysis.txt
### 4. retry_analysis.txt结果解读
打开 retry_analysis.txt，内容示例如下：
重试次数大于7的密码:
2100009235556066143: 12

2100009235556060012: 8

2100009235556064891: 9

成功密码:

卡号(cardSequence): D0000IIR0110KTG0000

密码(paymentCode): 2100009235556066143
