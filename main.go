// bb-fuzzer: 高并发目录模糊测试与信息收集脚本（Go）
// 功能概述：
// - 读取 targets.txt（每行一个域名/子域名）与 wordlist.txt（每行一个路径）
// - 优先使用 HTTPS，失败自动回退 HTTP
// - 并发扫描 + 速率限制（令牌桶），可自定义并发与 QPS
// - 智能过滤：仅输出 200/301/302/403，且基于“软 404”内容大小过滤
// - 可自定义 UA 与 Header，支持设置 Cookie 以模拟会话
// - 每个目标域名独立输出 <domain>_fuzz.txt；错误日志单独写入 error.log
// - 进度显示：实时打印全局与单域进度
//
// 构建：
//   go build -o bb-fuzzer main.go
// 运行：
//   ./bb-fuzzer -targets targets.txt -wordlist wordlist.txt -t 80 -r 40 \
//     -ua "Mozilla/5.0 ..." -H "X-Forwarded-For: 127.0.0.1" -cookie "sid=abc; role=user" \
//     -timeout 10
//
// 提示：
// - 软 404 基线：对每个域名随机探测若干不存在路径，统计其常见响应体大小，后续扫描与其相等时将被忽略（无论状态码）。
// - 重定向：不自动跟随重定向，保留 301/302 的首跳响应用于输出。
//
// 作者：lontano

package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	rate "golang.org/x/time/rate"
)

// ===================== 配置与参数 =====================

type Config struct {
    TargetsPath string
    WordlistPath string
    Concurrency int
    RateLimit float64 // 每秒请求数（全局）
    Timeout time.Duration
    UA string
    UAFile string
    Headers multiFlag
    Cookie string
    ErrLog string
    NoColor bool
}

// multiFlag 允许重复 -H 参数
 type multiFlag []string
 func (m *multiFlag) String() string { return strings.Join(*m, ", ") }
 func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

// ===================== 工具函数 =====================

func readLines(path string) ([]string, error) {
    f, err := os.Open(path)
    if err != nil { return nil, err }
    defer f.Close()
    var out []string
    s := bufio.NewScanner(f)
    for s.Scan() {
        line := strings.TrimSpace(s.Text())
        if line == "" || strings.HasPrefix(line, "#") { continue }
        out = append(out, line)
    }
    return out, s.Err()
}

func loadRandomUAs(path string) ([]string, error) {
    if path == "" { return nil, nil }
    return readLines(path)
}

func safeFilename(host string) string {
    re := regexp.MustCompile(`[^a-zA-Z0-9._-]`)
    return re.ReplaceAllString(host, "_")
}

func pickUA(cfg *Config, uas []string) string {
    if cfg.UA != "" { return cfg.UA }
    if len(uas) == 0 { return defaultUA() }
    return uas[rand.Intn(len(uas))]
}

func defaultUA() string {
    return fmt.Sprintf("bb-fuzzer/1.0 (%s; %s) Go/%s", runtime.GOOS, runtime.GOARCH, runtime.Version())
}

// ===================== HTTP 客户端与请求 =====================

func newHTTPClient(timeout time.Duration) *http.Client {
    tr := &http.Transport{
        Proxy: http.ProxyFromEnvironment,
        DialContext: (&net.Dialer{ Timeout: timeout }).DialContext,
        TLSClientConfig: &tls.Config{ InsecureSkipVerify: true }, // 赏金场景下容忍自签证书
        TLSHandshakeTimeout: timeout,
        ResponseHeaderTimeout: timeout,
        ExpectContinueTimeout: 2 * time.Second,
        MaxIdleConns: 200,
        IdleConnTimeout: 90 * time.Second,
        DisableKeepAlives: false,
    }
    // 不自动跟随重定向，保留 30x
    return &http.Client{
        Transport: tr,
        Timeout: timeout,
        CheckRedirect: func(req *http.Request, via []*http.Request) error {
            return http.ErrUseLastResponse
        },
    }
}

type RespInfo struct {
    URL string
    Status int
    Size int
    WordCount int
}

var successCodes = map[int]struct{}{200: {}, 301: {}, 302: {}, 403: {}}

// fetchWithFallback 优先 HTTPS，失败时尝试 HTTP
func fetchWithFallback(ctx context.Context, client *http.Client, host, path string, headers http.Header) (*RespInfo, error) {
    // 确保 path 形如 "/abc"
    if path == "" || path[0] != '/' { path = "/" + path }

    // 先试 HTTPS
    u := url.URL{Scheme: "https", Host: host, Path: path}
    ri, err := doRequest(ctx, client, &u, headers)
    if err == nil { return ri, nil }

    // 如果是 TLS/连接类错误则回退 HTTP
    if isNetOrTLSError(err) {
        u = url.URL{Scheme: "http", Host: host, Path: path}
        return doRequest(ctx, client, &u, headers)
    }
    return nil, err
}

func isNetOrTLSError(err error) bool {
    if err == nil { return false }
    var netErr net.Error
    if errors.As(err, &netErr) { return true }
    // url.Error 包裹
    var urlErr *url.Error
    if errors.As(err, &urlErr) {
        if urlErr.Timeout() { return true }
        if _, ok := urlErr.Err.(net.Error); ok { return true }
        // TLS 握手等
        if strings.Contains(strings.ToLower(urlErr.Error()), "tls") { return true }
    }
    // 其他常见网络消息
    msg := strings.ToLower(err.Error())
    if strings.Contains(msg, "connection refused") || strings.Contains(msg, "no such host") || strings.Contains(msg, "handshake") {
        return true
    }
    return false
}

func doRequest(ctx context.Context, client *http.Client, u *url.URL, headers http.Header) (*RespInfo, error) {
    req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
    if err != nil { return nil, err }
    // 设置头
    for k, vals := range headers {
        for _, v := range vals { req.Header.Add(k, v) }
    }
    resp, err := client.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    // 读取全部以获取大小与词数（谨慎：大文件会慢——字典路径通常较小）
    body, err := io.ReadAll(resp.Body)
    if err != nil { return nil, err }
    wc := 0
    if len(body) > 0 {
        // 粗略词数：按空白分割
        wc = len(strings.Fields(string(body)))
    }
    ri := &RespInfo{
        URL: u.String(),
        Status: resp.StatusCode,
        Size: len(body),
        WordCount: wc,
    }
    return ri, nil
}

// ===================== 软 404 基线探测 =====================

func buildHeaders(cfg *Config, uas []string) http.Header {
    h := http.Header{}
    h.Set("User-Agent", pickUA(cfg, uas))
    // 附加自定义 Header
    for _, line := range cfg.Headers {
        // 形如 "Key: Value"
        sp := strings.SplitN(line, ":", 2)
        if len(sp) != 2 { continue }
        key := strings.TrimSpace(sp[0])
        val := strings.TrimSpace(sp[1])
        if key == "" || val == "" { continue }
        h.Add(key, val)
    }
    if cfg.Cookie != "" {
        h.Add("Cookie", cfg.Cookie)
    }
    return h
}

// probeSoft404Sizes：返回该主机上最常见的"不存在"页面大小集合
func probeSoft404Sizes(ctx context.Context, client *http.Client, host string, headers http.Header) map[int]int {
    // 多次随机探测，记录各大小出现次数
    sizes := make(map[int]int)
    paths := []string{}
    for i := 0; i < 5; i++ {
        r := randString(12)
        // 同时覆盖几种常见变体
        paths = append(paths, "/"+r, "/"+r+"/", "/"+r+".html")
    }
    for _, p := range paths {
        ri, err := fetchWithFallback(ctx, client, host, p, headers)
        if err != nil { continue }
        sizes[ri.Size]++
    }
    return sizes
}

func randString(n int) string {
    letters := []rune("abcdefghijklmnopqrstuvwxyz0123456789")
    b := make([]rune, n)
    for i := range b { b[i] = letters[rand.Intn(len(letters))] }
    return string(b)
}

// shouldReport 根据成功码与软 404 基线决定是否输出
func shouldReport(ri *RespInfo, baseline map[int]int) bool {
    if _, ok := successCodes[ri.Status]; !ok { return false }
    if len(baseline) == 0 { return true }
    // 若 body 大小与最常见的 404/软404 大小相同，则忽略
    // 找出 baseline 中出现次数最多的 size
    maxCnt, commonSize := 0, -1
    for sz, cnt := range baseline {
        if cnt > maxCnt { maxCnt, commonSize = cnt, sz }
    }
    if commonSize >= 0 && ri.Size == commonSize {
        return false
    }
    return true
}

// ===================== 扫描调度 =====================

type task struct {
    host string
    path string
}

type domainProgress struct {
    total int64
    done int64
}

func main() {
    rand.Seed(time.Now().UnixNano())

    cfg := &Config{}
    flag.StringVar(&cfg.TargetsPath, "targets", "targets.txt", "targets 文件路径")
    flag.StringVar(&cfg.WordlistPath, "wordlist", "wordlist.txt", "wordlist 文件路径")
    flag.IntVar(&cfg.Concurrency, "t", 80, "并发工作协程数")
    flag.Float64Var(&cfg.RateLimit, "r", 40, "全局每秒请求数(QPS)")
    flag.DurationVar(&cfg.Timeout, "timeout", 10*time.Second, "请求超时时间")
    flag.StringVar(&cfg.UA, "ua", "", "自定义 User-Agent；留空则随机/默认")
    flag.StringVar(&cfg.UAFile, "ua-file", "", "UA 列表文件（每行一个），随机挑选")
    flag.Var(&cfg.Headers, "H", "附加 Header，格式: 'Key: Value'，可多次传入")
    flag.StringVar(&cfg.Cookie, "cookie", "", "请求 Cookie 串，例如 'sid=xxx; role=user'")
    flag.StringVar(&cfg.ErrLog, "errlog", "error.log", "错误日志文件")
    flag.BoolVar(&cfg.NoColor, "no-color", false, "禁用彩色输出")
    flag.Parse()

    // 读取输入
    targets, err := readLines(cfg.TargetsPath)
    if err != nil { fatalf("读取 targets 失败: %v", err) }
    wordlist, err := readLines(cfg.WordlistPath)
    if err != nil { fatalf("读取 wordlist 失败: %v", err) }

    uaList, err := loadRandomUAs(cfg.UAFile)
    if err != nil { fatalf("读取 UA 列表失败: %v", err) }

    // 错误日志
    errFile, err := os.OpenFile(cfg.ErrLog, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
    if err != nil { fatalf("无法打开错误日志: %v", err) }
    defer errFile.Close()
    logErr := func(format string, a ...any) {
        ts := time.Now().Format("2006-01-02 15:04:05")
        fmt.Fprintf(errFile, "[%s] "+format+"\n", append([]any{ts}, a...)...)
    }

    client := newHTTPClient(cfg.Timeout)
    limiter := rate.NewLimiter(rate.Limit(cfg.RateLimit), int(cfg.RateLimit))

    // 构建任务
    tasks := make(chan task, 1000)
    var globalTotal int64 = int64(len(targets) * len(wordlist))
    var globalDone int64

    // 每域输出文件、基线、进度
    outFiles := sync.Map{}           // host -> *os.File
    soft404Map := sync.Map{}         // host -> map[int]int
    progress := sync.Map{}            // host -> *domainProgress

    openOut := func(host string) *os.File {
        if v, ok := outFiles.Load(host); ok { return v.(*os.File) }
        fn := fmt.Sprintf("%s_fuzz.txt", safeFilename(host))
        f, err := os.OpenFile(fn, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
        if err != nil { fatalf("打开输出文件失败 %s: %v", fn, err) }
        outFiles.Store(host, f)
        return f
    }
    getBaseline := func(host string, headers http.Header) map[int]int {
        if v, ok := soft404Map.Load(host); ok { return v.(map[int]int) }
        ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
        defer cancel()
        bl := probeSoft404Sizes(ctx, client, host, headers)
        soft404Map.Store(host, bl)
        return bl
    }

    // 进度管理
    for _, host := range targets {
        progress.Store(host, &domainProgress{total: int64(len(wordlist))})
    }

    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()

    // 生产者：
    go func() {
        defer close(tasks)
        for _, host := range targets {
            // 为每个域设置其专属 headers（UA 可随机）
            headers := buildHeaders(cfg, uaList)
            _ = headers // 保持作用域；实际由消费者使用
            for _, p := range wordlist {
                tasks <- task{host: host, path: p}
            }
        }
    }()

    // 消费者（工人）
    var wg sync.WaitGroup
    type workerCtx struct {
        headers http.Header
    }

    // 为每个 worker 创建一套（可变 UA）头部，减少锁竞争
    newWorker := func() workerCtx {
        h := buildHeaders(cfg, uaList)
        return workerCtx{headers: h}
    }

    for i := 0; i < cfg.Concurrency; i++ {
        wg.Add(1)
        go func(id int) {
            defer wg.Done()
            w := newWorker()
            for tk := range tasks {
                // 速率限制
                if err := limiter.Wait(ctx); err != nil { return }

                // 获取域名基线（懒加载）
                bl := getBaseline(tk.host, w.headers)

                // 请求
                ri, err := fetchWithFallback(ctx, client, tk.host, tk.path, w.headers)
                if err != nil {
                    logErr("%s %s -> %v", tk.host, tk.path, err)
                } else if shouldReport(ri, bl) {
                    f := openOut(tk.host)
                    line := fmt.Sprintf("URL: %s | Status: %d | Size: %d | WordCount: %d\n", ri.URL, ri.Status, ri.Size, ri.WordCount)
                    f.WriteString(line)
                }

                // 进度
                atomic.AddInt64(&globalDone, 1)
                if v, ok := progress.Load(tk.host); ok {
                    dp := v.(*domainProgress)
                    atomic.AddInt64(&dp.done, 1)
                }
            }
        }(i)
    }

    // 进度显示协程
    doneCh := make(chan struct{})
    go func() {
        ticker := time.NewTicker(1 * time.Second)
        defer ticker.Stop()
        for {
            select {
            case <-ticker.C:
                gDone := atomic.LoadInt64(&globalDone)
                gPct := float64(gDone) / float64(globalTotal) * 100
                fmt.Printf("[进度] 全局: %d/%d (%.1f%%)\n", gDone, globalTotal, gPct)
                // 打印部分域的进度
                cnt := 0
                progress.Range(func(key, val any) bool {
                    if cnt >= 5 { return false } // 避免刷屏，最多显示 5 个域
                    host := key.(string)
                    dp := val.(*domainProgress)
                    d := atomic.LoadInt64(&dp.done)
                    pct := float64(d) / float64(dp.total) * 100
                    fmt.Printf("  正在扫描：%s - 已完成 %.1f%% (%d/%d)\n", host, pct, d, dp.total)
                    cnt++
                    return true
                })
            case <-doneCh:
                return
            }
        }
    }()

    wg.Wait()
    close(doneCh)

    // 关闭所有输出文件
    outFiles.Range(func(_, v any) bool { v.(*os.File).Close(); return true })

    fmt.Println("扫描完成。结果已写入各 *_fuzz.txt 文件，错误日志见:", cfg.ErrLog)
}

func fatalf(format string, a ...any) {
    fmt.Fprintf(os.Stderr, format+"\n", a...)
    os.Exit(1)
}
