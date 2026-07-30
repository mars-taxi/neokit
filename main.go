package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"neokit/internal/crypto"
)

func main() {
	mux := http.NewServeMux()

	// 静态文件服务
	fs := http.FileServer(http.Dir("public"))
	mux.Handle("/public/", http.StripPrefix("/public/", fs))
	mux.HandleFunc("/", serveIndex)

	// API 路由
	mux.HandleFunc("/api/encrypt", crypto.HandleEncrypt)
	mux.HandleFunc("/api/decrypt", crypto.HandleDecrypt)
	mux.HandleFunc("/api/hash", crypto.HandleHash)
	mux.HandleFunc("/api/hmac", crypto.HandleHMAC)
	mux.HandleFunc("/api/generate-key", crypto.HandleGenerateKey)
	mux.HandleFunc("/api/generate-salt", crypto.HandleGenerateSalt)
	mux.HandleFunc("/api/generate-iv", crypto.HandleGenerateIV)
	mux.HandleFunc("/api/base64-encode", crypto.HandleBase64Encode)
	mux.HandleFunc("/api/base64-decode", crypto.HandleBase64Decode)
	mux.HandleFunc("/api/rsa-generate", crypto.HandleRSAGenerate)
	mux.HandleFunc("/api/rsa-encrypt", crypto.HandleRSAEncrypt)
	mux.HandleFunc("/api/rsa-decrypt", crypto.HandleRSADecrypt)

	// CORS 中间件
	handler := corsMiddleware(mux)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	fmt.Println("================================================")
	fmt.Println("  NeoKr - 在线加解密工具站")
	fmt.Println("  网站: https://neokr.com")
	fmt.Printf("  服务地址: http://0.0.0.0:%s\n", port)
	fmt.Println("================================================")

	if err := http.ListenAndServe(":"+port, handler); err != nil {
		log.Fatal("服务器启动失败:", err)
	}
}

func serveIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	http.ServeFile(w, r, "public/index.html")
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
