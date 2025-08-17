BB-Fuzzer - 高性能目录模糊测试工具
✨ 项目简介

这是一个用 Go 语言编写的高性能目录模糊测试与信息收集脚本。它专为渗透测试和国际 Bug Bounty（漏洞赏金）设计，能够帮助安全研究人员快速有效地发现隐藏的目录和接口。

主要特性:

    高并发: 利用 Go 的协程实现高并发扫描，速度极快。

    智能过滤: 自动过滤软 404 页面，只输出有价值的响应（200, 301, 302, 403）。

    多协议支持: 优先使用 HTTPS，失败时自动回退到 HTTP。

    速率控制: 支持自定义 QPS (每秒请求数)，以避免被目标服务器封锁。

    高度可定制: 可自定义 User-Agent、Header 和 Cookie，支持导入 UA 列表。

    文件化输出: 每个目标的扫描结果都保存在独立文件中，便于后续分析。

🚀 使用指南
1. 构建

首先，请确保你的系统已安装 Go 1.18 或更高版本。在项目根目录下，运行以下命令：

go mod init bb-fuzzer-go
go mod tidy
go build -o bb-fuzzer main.go

2. 准备输入文件

    targets.txt: 包含要扫描的域名列表，每行一个。

    example.com
    dev.example.com

    wordlist.txt: 包含要探测的路径列表，每行一个。

    admin
    api
    login
    .git

3. 运行

可以使用 nohup 命令在后台运行，并将所有日志重定向到文件中：

nohup ./bb-fuzzer -targets targets.txt -wordlist wordlist.txt -t 100 -r 50 > bb-fuzzer.log 2>&1 &

常用参数:

    -targets <path>: 目标文件路径 (默认为 targets.txt)

    -wordlist <path>: 字典文件路径 (默认为 wordlist.txt)

    -t <int>: 并发协程数 (默认为 80)

    -r <float>: 全局每秒请求数 (QPS) (默认为 40)

    -ua <string>: 自定义 User-Agent

    -H <string>: 添加自定义 Header，格式为 'Key: Value' (可多次使用)

    -cookie <string>: 添加 Cookie 串

📜 示例输出
example.com_fuzz.txt

URL: [https://example.com/admin](https://example.com/admin) | Status: 403 | Size: 422 | WordCount: 20
URL: [https://example.com/api](https://example.com/api) | Status: 200 | Size: 50 | WordCount: 15

⚠️ 免责声明

本工具仅用于授权的安全测试和教育目的。使用本工具进行任何非法活动，使用者需自行承担全部法律责任。

<p align="center">Made with ❤️ by [你的 GitHub 用户名]</p>
