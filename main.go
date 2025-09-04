// Filename: main.go
package main

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy"
)

// --- 配置结构体 (已重构) ---
type ProxyInfo struct {
	Address string `json:"address"`
}

type Rule struct {
	Domains   []string `json:"domains"`
	ProxyName string   `json:"proxy_name"`
}

type Config struct {
	HttpListenAddr   string               `json:"http_listen_addr"`
	Socks5ListenAddr string               `json:"socks5_listen_addr"`
	ApiListenAddr    string               `json:"api_listen_addr"`
	Proxies          map[string]ProxyInfo `json:"proxies"`
	DefaultProxyName string               `json:"default_proxy_name"`
	Rules            []Rule               `json:"rules"`
}

// --- 全局变量与线程安全 ---
var (
	config      Config
	configMutex sync.RWMutex // 读写锁，保护配置的并发访问
)

// --- 主逻辑 ---
func main() {
	if err := loadConfig("config.json"); err != nil {
		log.Fatalf("无法加载初始配置文件 'config.json': %v", err)
	}

	var wg sync.WaitGroup

	// 启动 HTTP 代理监听
	if config.HttpListenAddr != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			log.Printf("启动 HTTP 代理，监听地址: %s", config.HttpListenAddr)
			listenAndServeHTTP(config.HttpListenAddr)
		}()
	}

	// 启动 SOCKS5 代理监听
	if config.Socks5ListenAddr != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			log.Printf("启动 SOCKS5 代理，监听地址: %s", config.Socks5ListenAddr)
			listenAndServeSOCKS5(config.Socks5ListenAddr)
		}()
	}

	// 启动 API 服务监听
	if config.ApiListenAddr != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			log.Printf("启动 API 服务，监听地址: %s", config.ApiListenAddr)
			serveAPI(config.ApiListenAddr)
		}()
	}

	wg.Wait()
}

// --- API 实现 ---
func serveAPI(addr string) {
	mux := http.NewServeMux()
	mux.HandleFunc("/config", configHandler)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("API 服务启动失败: %v", err)
	}
}

func configHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		// GET /config: 获取当前配置
		configMutex.RLock() // 加读锁
		defer configMutex.RUnlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(config)

	case http.MethodPut:
		// PUT /config: 更新整个配置
		var newConfig Config
		if err := json.NewDecoder(r.Body).Decode(&newConfig); err != nil {
			http.Error(w, "无效的 JSON: "+err.Error(), http.StatusBadRequest)
			return
		}

		// 验证新配置的有效性
		if err := validateConfig(&newConfig); err != nil {
			http.Error(w, "配置验证失败: "+err.Error(), http.StatusBadRequest)
			return
		}
		
		configMutex.Lock() // 加写锁
		config = newConfig
		configMutex.Unlock()

		log.Println("配置已通过 API 更新")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("配置更新成功"))

	default:
		http.Error(w, "只支持 GET 和 PUT 方法", http.StatusMethodNotAllowed)
	}
}

// --- 配置加载与验证 ---
func loadConfig(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	var newConfig Config
	if err := json.NewDecoder(file).Decode(&newConfig); err != nil {
		return err
	}

	if err := validateConfig(&newConfig); err != nil {
		return err
	}

	// 加载初始配置时不需要锁
	config = newConfig
	return nil
}

func validateConfig(c *Config) error {
	if _, ok := c.Proxies[c.DefaultProxyName]; !ok {
		return fmt.Errorf("默认代理 '%s' 在代理池中未定义", c.DefaultProxyName)
	}
	for _, rule := range c.Rules {
		if _, ok := c.Proxies[rule.ProxyName]; !ok {
			return fmt.Errorf("规则中使用的代理 '%s' 在代理池中未定义", rule.ProxyName)
		}
	}
	return nil
}


// --- 核心路由与转发逻辑 (已更新) ---
func selectBackendProxy(host string) (ProxyInfo, error) {
	configMutex.RLock() // 加读锁
	defer configMutex.RUnlock()

	hostname := strings.Split(host, ":")[0]
	hostname = strings.ToLower(strings.TrimSpace(hostname))
	for _, rule := range config.Rules {
		for _, domain := range rule.Domains {
			d := strings.ToLower(strings.TrimSpace(domain))
			if strings.HasPrefix(d, "*.") {
				d = strings.TrimPrefix(d, "*.")
			}
			d = strings.TrimPrefix(d, ".")
			if strings.HasSuffix(hostname, d) {
				proxyName := rule.ProxyName
				if p, ok := config.Proxies[proxyName]; ok {
					return p, nil
				}
				// 理论上 validateConfig 会阻止这种情况
				return ProxyInfo{}, fmt.Errorf("配置错误: 规则引用的代理 '%s' 未找到", proxyName)
			}
		}
	}
	// 没有规则匹配，使用默认代理
	if p, ok := config.Proxies[config.DefaultProxyName]; ok {
		return p, nil
	}
	return ProxyInfo{}, errors.New("配置错误: 默认代理未找到")
}


func routeAndConnect(targetHost string) (net.Conn, error) {
	backendProxy, err := selectBackendProxy(targetHost)
	if err != nil {
		return nil, err
	}
	
	log.Printf("目标 %s 匹配规则，将转发到代理 '%s'", targetHost, backendProxy.Address)

	backendConn, err := dialBackend(backendProxy, targetHost)
	if err != nil {
		return nil, fmt.Errorf("连接后端代理 %s 失败: %w", backendProxy.Address, err)
	}

	log.Printf("隧道已建立: Client <-> Router <-> %s <-> %s", backendProxy.Address, targetHost)
	return backendConn, nil
}


// dialBackend 连接 SOCKS5 后端
func dialBackend(proxyInfo ProxyInfo, targetAddr string) (net.Conn, error) {
	// 始终通过 SOCKS5 后端转发
	dialer, err := proxy.SOCKS5("tcp", proxyInfo.Address, nil, proxy.Direct)
	if err != nil {
		return nil, fmt.Errorf("创建 SOCKS5 拨号器失败: %w", err)
	}
	return dialer.Dial("tcp", targetAddr)
}

const (
	socks5Version = 0x05
	cmdConnect    = 0x01
	atypIPv4      = 0x01
	atypDomain    = 0x03
	atypIPv6      = 0x04
)

func listenAndServeHTTP(addr string) {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("HTTP 无法监听端口 %s: %v", addr, err)
	}
	defer listener.Close()
	for {
		clientConn, err := listener.Accept()
		if err != nil {
			log.Printf("HTTP 接受连接失败: %v", err)
			continue
		}
		go handleHttpRequest(clientConn)
	}
}

func handleHttpRequest(clientConn net.Conn) {
	defer clientConn.Close()

	reader := bufio.NewReader(clientConn)
	req, err := http.ReadRequest(reader)
	if err != nil {
		if err != io.EOF {
			log.Printf("HTTP 读取请求失败: %v", err)
		}
		return
	}

	targetHost := req.Host
	if !strings.Contains(targetHost, ":") {
		if req.Method == "CONNECT" {
			targetHost = targetHost + ":443"
		} else {
			targetHost = targetHost + ":80"
		}
	}
	backendConn, err := routeAndConnect(targetHost)
	if err != nil {
		log.Printf("路由失败: %v", err)
		clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer backendConn.Close()

	if req.Method == "CONNECT" {
		_, err = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		if err != nil {
			log.Printf("HTTP 发送 '200' 响应失败: %v", err)
			return
		}
	} else {
		err = req.Write(backendConn)
		if err != nil {
			log.Printf("HTTP 转发请求失败: %v", err)
			return
		}
	}
	
	transfer(backendConn, clientConn)
}

func listenAndServeSOCKS5(addr string) {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("SOCKS5 无法监听端口 %s: %v", addr, err)
	}
	defer listener.Close()
	for {
		clientConn, err := listener.Accept()
		if err != nil {
			log.Printf("SOCKS5 接受连接失败: %v", err)
			continue
		}
		go handleSocks5Request(clientConn)
	}
}

func handleSocks5Request(clientConn net.Conn) {
	defer clientConn.Close()

	buf := make([]byte, 262) 
	_, err := io.ReadFull(clientConn, buf[:2])
	if err != nil {
		log.Printf("SOCKS5 握手失败: %v", err)
		return
	}
	if buf[0] != socks5Version { return }
	nmethods := buf[1]
	if _, err = io.ReadFull(clientConn, buf[:nmethods]); err != nil { return }
	if _, err = clientConn.Write([]byte{socks5Version, 0x00}); err != nil { return }

	_, err = io.ReadFull(clientConn, buf[:4])
	if err != nil {
		return
	}
	if buf[1] != cmdConnect {
		log.Printf("SOCKS5 不支持的命令: %d", buf[1])
		return
	}

	var targetHost string
	addrType := buf[3]

	sniffPort := 0
	sniffedHost := ""
	sniffedFirst := []byte(nil)

	switch addrType {
	case atypIPv4:
		_, err = io.ReadFull(clientConn, buf[:net.IPv4len+2])
		if err != nil {
			return
		}
		ip := net.IP(buf[:net.IPv4len])
		port := binary.BigEndian.Uint16(buf[net.IPv4len : net.IPv4len+2])
		targetHost = net.JoinHostPort(ip.String(), strconv.Itoa(int(port)))
		sniffPort = int(port)
	case atypDomain:
		_, err = io.ReadFull(clientConn, buf[:1])
		if err != nil {
			return
		}
		domainLen := int(buf[0])
		_, err = io.ReadFull(clientConn, buf[:domainLen+2])
		if err != nil {
			return
		}
		domain := string(buf[:domainLen])
		port := binary.BigEndian.Uint16(buf[domainLen : domainLen+2])
		targetHost = net.JoinHostPort(domain, strconv.Itoa(int(port)))
		sniffPort = int(port)
	case atypIPv6:
		_, err = io.ReadFull(clientConn, buf[:net.IPv6len+2])
		if err != nil {
			return
		}
		ip := net.IP(buf[:net.IPv6len])
		port := binary.BigEndian.Uint16(buf[net.IPv6len : net.IPv6len+2])
		targetHost = net.JoinHostPort(ip.String(), strconv.Itoa(int(port)))
		sniffPort = int(port)
	default:
		log.Printf("SOCKS5 不支持的地址类型: %d", addrType)
		clientConn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	
	// 先发送 SOCKS5 成功响应
	_, err = clientConn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	if err != nil {
		log.Printf("SOCKS5 发送成功响应失败: %v", err)
		return
	}
	
	// 最小化嗅探：当是 IP 且端口为 443/80 时，窥探首包以尝试恢复域名
	if sniffPort == 443 || sniffPort == 80 {
		log.Printf("嗅探目标主机: %s", targetHost)
		hostOnly, _, err := net.SplitHostPort(targetHost)
		if err == nil {
			ip := net.ParseIP(hostOnly)
			if ip != nil {
				_ = clientConn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
				peek := make([]byte, 512)
				n, _ := clientConn.Read(peek)
				_ = clientConn.SetReadDeadline(time.Time{})
				if n > 0 {
					sniffedFirst = peek[:n]
					if sniffPort == 443 {
						sni := parseTLSClientHelloSNI(sniffedFirst)
						if sni != "" { 
							sniffedHost = net.JoinHostPort(sni, strconv.Itoa(sniffPort))
							log.Printf("TLS SNI 解析成功: %s", sni)
						} else {
							log.Printf("TLS SNI 解析失败，数据长度: %d", len(sniffedFirst))
							// 输出前64字节的十六进制用于调试
							debugLen := 64
							if len(sniffedFirst) < debugLen {
								debugLen = len(sniffedFirst)
							}
							log.Printf("TLS 数据前%d字节: %x", debugLen, sniffedFirst[:debugLen])
						}
					} else if sniffPort == 80 {
						host := parseHTTPHost(sniffedFirst)
						if host != "" { 
							sniffedHost = net.JoinHostPort(host, strconv.Itoa(sniffPort))
						}
					}
				}
			}
		}
	}
	
	backendRoutingKey := targetHost
	if sniffedHost != "" {
		backendRoutingKey = sniffedHost
		log.Printf("嗅探成功，使用域名路由: %s", backendRoutingKey)
	}
	
	backendConn, err := routeAndConnect(backendRoutingKey)
	if err != nil {
		log.Printf("路由失败: %v", err)
		clientConn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer backendConn.Close()
	
	// 回放已窥探的首包到后端
	if len(sniffedFirst) > 0 {
		backendConn.Write(sniffedFirst)
	}
	
	transfer(backendConn, clientConn)
}

func transfer(backend net.Conn, client net.Conn) {
    var wg sync.WaitGroup
    wg.Add(2)
    go func() {
        defer wg.Done()
        io.Copy(backend, client)
		if tcpConn, ok := backend.(*net.TCPConn); ok {
			tcpConn.CloseWrite()
		}
    }()
    go func() {
        defer wg.Done()
        io.Copy(client, backend)
		if tcpConn, ok := client.(*net.TCPConn); ok {
			tcpConn.CloseWrite()
		}
    }()
    wg.Wait()
}

// 预编译正则表达式，提高性能
var domainRegex = regexp.MustCompile(`[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}`)

func parseTLSClientHelloSNI(data []byte) string {
	// 使用正则表达式提取域名
	if len(data) < 5 || data[0] != 0x16 { return "" }
	
	text := string(data)
	matches := domainRegex.FindAllString(text, -1)
	
	// 返回第一个找到的有效域名
	for _, match := range matches {
		if len(match) > 3 && strings.Contains(match, ".") {
			return strings.ToLower(match)
		}
	}
	
	return ""
}

func parseHTTPHost(data []byte) string {
	// Read until first CRLFCRLF or buffer end, find Host header
	text := string(data)
	// quick limit for safety
	idxEnd := strings.Index(text, "\r\n\r\n")
	if idxEnd >= 0 { text = text[:idxEnd] }
	for _, line := range strings.Split(text, "\r\n") {
		if len(line) >= 5 && (strings.HasPrefix(strings.ToLower(line), "host:")) {
			v := strings.TrimSpace(line[5:])
			return strings.ToLower(v)
		}
	}
	return ""
}
