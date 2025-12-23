package main

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http" // Quan trọng
	// "net/url"  // Quan trọng
	"os"
	"strings"
	"time"
)

type Message struct {
	Domain string `json:"domain"`
}

type Response struct {
	Fingerprint string `json:"fingerprint"`
	Error       string `json:"error"`
}

// Hàm ghi log để debug
func logDebug(msg string) {
	f, _ := os.OpenFile("debug_log.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	defer f.Close()
	f.WriteString(fmt.Sprintf("%s: %s\n", time.Now().Format(time.RFC3339), msg))
}

func main() {
	logDebug("Native App Started")
	
	for {
		var length uint32
		err := binary.Read(os.Stdin, binary.LittleEndian, &length)
		if err == io.EOF {
			logDebug("Stdin EOF - Exiting")
			return
		}
		if err != nil {
			logDebug("Read Length Error: " + err.Error())
			return
		}

		msgBuf := make([]byte, length)
		_, err = io.ReadFull(os.Stdin, msgBuf)
		if err != nil {
			logDebug("Read Body Error: " + err.Error())
			return
		}

		var msg Message
		json.Unmarshal(msgBuf, &msg)
		logDebug("Received Request for: " + msg.Domain)

		// Xử lý
		fingerprint, errStr := getSystemCertFingerprint(msg.Domain)
		logDebug(fmt.Sprintf("Result: %s, Error: %s", fingerprint, errStr))

		resp := Response{Fingerprint: fingerprint, Error: errStr}
		sendResponse(resp)
	}
}

func getSystemCertFingerprint(domain string) (string, string) {
	if !strings.Contains(domain, ":") {
		domain += ":443"
	}

	// // 1. CẤU HÌNH PROXY BURP SUITE
	// proxyUrl, err := url.Parse("http://127.0.0.1:8080") //Comment sau khi test xong
	// if err != nil { //Comment sau khi test xong
	// 	return "", "Proxy Config Error: " + err.Error() //Comment sau khi test xong
	// } //Comment sau khi test xong

	// 2. Cấu hình TLS (Bỏ qua verify để chấp nhận Cert của Burp)
	conf := &tls.Config{InsecureSkipVerify: true}

	// 3. Tạo Transport đi qua Proxy
	transport := &http.Transport{
		// Proxy:           http.ProxyURL(proxyUrl), //Comment sau khi test xong
		TLSClientConfig: conf,
	}

	// 4. Tạo Request giả (HEAD) để lấy kết nối TLS
	targetUrl := "https://" + strings.TrimSuffix(domain, ":443")
	req, _ := http.NewRequest("HEAD", targetUrl, nil)
	
	// Client với Timeout
	client := &http.Client{
		Transport: transport,
		Timeout:   5 * time.Second,
	}

	// 5. Gửi Request
	resp, err := client.Do(req)
	
	if err != nil {
		return "", "Connection Error: " + err.Error()
	}
	defer resp.Body.Close()

	// 6. Lấy chứng chỉ từ Response
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		cert := resp.TLS.PeerCertificates[0]
		hash := sha256.Sum256(cert.Raw)
		return hex.EncodeToString(hash[:]), ""
	}

	return "", "No certificates found"
}

func sendResponse(resp Response) {
	bytes, _ := json.Marshal(resp)
	binary.Write(os.Stdout, binary.LittleEndian, uint32(len(bytes)))
	os.Stdout.Write(bytes)
}