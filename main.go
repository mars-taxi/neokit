package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
)

func main() {
	mux := http.NewServeMux()

	// 静态文件服务
	fs := http.FileServer(http.Dir("static"))
	mux.Handle("/static/", http.StripPrefix("/static/", fs))
	mux.HandleFunc("/", serveIndex)

	// API 路由
	mux.HandleFunc("/api/encrypt", handleEncrypt)
	mux.HandleFunc("/api/decrypt", handleDecrypt)
	mux.HandleFunc("/api/hash", handleHash)
	mux.HandleFunc("/api/hmac", handleHMAC)
	mux.HandleFunc("/api/generate-key", handleGenerateKey)
	mux.HandleFunc("/api/generate-salt", handleGenerateSalt)
	mux.HandleFunc("/api/generate-iv", handleGenerateIV)
	mux.HandleFunc("/api/base64-encode", handleBase64Encode)
	mux.HandleFunc("/api/base64-decode", handleBase64Decode)
	mux.HandleFunc("/api/rsa-generate", handleRSAGenerate)
	mux.HandleFunc("/api/rsa-encrypt", handleRSAEncrypt)
	mux.HandleFunc("/api/rsa-decrypt", handleRSADecrypt)

	// CORS 中间件
	handler := corsMiddleware(mux)

	fmt.Println("================================================")
	fmt.Println("  NeoKr - 在线加解密工具站")
	fmt.Println("  网站: https://neokr.com")
	fmt.Println("  服务地址: http://localhost:8080")
	fmt.Println("================================================")

	if err := http.ListenAndServe(":8080", handler); err != nil {
		log.Fatal("服务器启动失败:", err)
	}
}

func serveIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	http.ServeFile(w, r, "static/index.html")
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func writeError(w http.ResponseWriter, errMsg string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": errMsg})
}

func parseJSON(r *http.Request, v interface{}) error {
	defer r.Body.Close()
	return json.NewDecoder(r.Body).Decode(v)
}

func trimSpace(s string) string {
	return strings.TrimSpace(s)
}
