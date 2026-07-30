package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
	"net/http"
)

// ========== 请求/响应结构体 ==========

type EncryptRequest struct {
	Algorithm string `json:"algorithm"`
	Mode      string `json:"mode"`
	Plaintext string `json:"plaintext"`
	Key       string `json:"key"`
	IV        string `json:"iv"`
	KeySize   int    `json:"keySize"`
	Encoding  string `json:"encoding"` // base64, hex
}

type DecryptRequest struct {
	Algorithm  string `json:"algorithm"`
	Mode       string `json:"mode"`
	Ciphertext string `json:"ciphertext"`
	Key        string `json:"key"`
	IV         string `json:"iv"`
	KeySize    int    `json:"keySize"`
	Encoding   string `json:"encoding"`
}

type HashRequest struct {
	Algorithm string `json:"algorithm"`
	Data      string `json:"data"`
}

type HMACRequest struct {
	Algorithm string `json:"algorithm"`
	Data      string `json:"data"`
	Key       string `json:"key"`
}

type GenerateRequest struct {
	Length int    `json:"length"`
	Format string `json:"format"`
}

type RSARequest struct {
	PublicKey  string `json:"publicKey"`
	PrivateKey string `json:"privateKey"`
	Data       string `json:"data"`
	KeySize    int    `json:"keySize"`
}

// ========== 对称加密 ==========

func handleEncrypt(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, "仅支持POST请求", http.StatusMethodNotAllowed)
		return
	}
	var req EncryptRequest
	if err := parseJSON(r, &req); err != nil {
		writeError(w, "请求参数解析失败", http.StatusBadRequest)
		return
	}

	req.Plaintext = trimSpace(req.Plaintext)
	req.Key = trimSpace(req.Key)
	req.IV = trimSpace(req.IV)

	if req.Plaintext == "" {
		writeError(w, "明文不能为空", http.StatusBadRequest)
		return
	}
	if req.Key == "" {
		writeError(w, "密钥不能为空", http.StatusBadRequest)
		return
	}
	if req.Encoding != "hex" {
		req.Encoding = "base64"
	}

	var rawBytes []byte
	var err error

	switch req.Algorithm {
	case "aes":
		rawBytes, err = aesEncrypt(req.Plaintext, req.Key, req.IV, req.Mode, req.KeySize)
	case "des":
		rawBytes, err = desEncrypt(req.Plaintext, req.Key, req.IV)
	case "3des":
		rawBytes, err = tripleDESEncrypt(req.Plaintext, req.Key, req.IV)
	default:
		writeError(w, "不支持的加密算法: "+req.Algorithm, http.StatusBadRequest)
		return
	}

	if err != nil {
		writeError(w, "加密失败: "+err.Error(), http.StatusInternalServerError)
		return
	}

	var result string
	if req.Encoding == "hex" {
		result = hex.EncodeToString(rawBytes)
	} else {
		result = base64.StdEncoding.EncodeToString(rawBytes)
	}

	writeJSON(w, map[string]string{"result": result, "encoding": req.Encoding})
}

func handleDecrypt(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, "仅支持POST请求", http.StatusMethodNotAllowed)
		return
	}
	var req DecryptRequest
	if err := parseJSON(r, &req); err != nil {
		writeError(w, "请求参数解析失败", http.StatusBadRequest)
		return
	}

	req.Ciphertext = trimSpace(req.Ciphertext)
	req.Key = trimSpace(req.Key)
	req.IV = trimSpace(req.IV)

	if req.Ciphertext == "" {
		writeError(w, "密文不能为空", http.StatusBadRequest)
		return
	}
	if req.Key == "" {
		writeError(w, "密钥不能为空", http.StatusBadRequest)
		return
	}
	if req.Encoding != "hex" {
		req.Encoding = "base64"
	}

	// 解码密文
	var rawBytes []byte
	var err error
	if req.Encoding == "hex" {
		rawBytes, err = hex.DecodeString(req.Ciphertext)
	} else {
		rawBytes, err = base64.StdEncoding.DecodeString(req.Ciphertext)
	}
	if err != nil {
		writeError(w, "密文解码失败: "+err.Error(), http.StatusBadRequest)
		return
	}

	var result string

	switch req.Algorithm {
	case "aes":
		result, err = aesDecrypt(rawBytes, req.Key, req.IV, req.Mode, req.KeySize)
	case "des":
		result, err = desDecrypt(rawBytes, req.Key, req.IV)
	case "3des":
		result, err = tripleDESDecrypt(rawBytes, req.Key, req.IV)
	default:
		writeError(w, "不支持的解密算法: "+req.Algorithm, http.StatusBadRequest)
		return
	}

	if err != nil {
		writeError(w, "解密失败: "+err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSON(w, map[string]string{"result": result})
}

// ========== AES ==========

func aesEncrypt(plaintext, keyStr, ivStr, mode string, keySize int) ([]byte, error) {
	key := padKey(keyStr, keySize/8)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("创建AES cipher失败: %w", err)
	}

	plainBytes := []byte(plaintext)

	switch mode {
	case "ecb":
		return aesECBEncrypt(block, plainBytes)
	case "cbc":
		iv := getIV(ivStr, aes.BlockSize)
		return aesCBCEncrypt(block, iv, plainBytes)
	case "ctr":
		iv := getIV(ivStr, aes.BlockSize)
		return aesCTREncrypt(block, iv, plainBytes)
	case "gcm":
		nonce := getIV(ivStr, 12)
		return aesGCMEncrypt(block, nonce, plainBytes)
	default:
		return aesCBCEncrypt(block, getIV(ivStr, aes.BlockSize), plainBytes)
	}
}

func aesDecrypt(cipherBytes []byte, keyStr, ivStr, mode string, keySize int) (string, error) {
	key := padKey(keyStr, keySize/8)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("创建AES cipher失败: %w", err)
	}

	switch mode {
	case "ecb":
		return aesECBDecrypt(block, cipherBytes)
	case "cbc":
		iv := getIV(ivStr, aes.BlockSize)
		return aesCBCDecrypt(block, iv, cipherBytes)
	case "ctr":
		iv := getIV(ivStr, aes.BlockSize)
		return aesCTRDecrypt(block, iv, cipherBytes)
	case "gcm":
		nonce := getIV(ivStr, 12)
		return aesGCMDecrypt(block, nonce, cipherBytes)
	default:
		return aesCBCDecrypt(block, getIV(ivStr, aes.BlockSize), cipherBytes)
	}
}

func aesECBEncrypt(block cipher.Block, plaintext []byte) ([]byte, error) {
	plaintext = pkcs7Pad(plaintext, aes.BlockSize)
	ciphertext := make([]byte, len(plaintext))
	for i := 0; i < len(plaintext); i += aes.BlockSize {
		block.Encrypt(ciphertext[i:i+aes.BlockSize], plaintext[i:i+aes.BlockSize])
	}
	return ciphertext, nil
}

func aesECBDecrypt(block cipher.Block, ciphertext []byte) (string, error) {
	if len(ciphertext)%aes.BlockSize != 0 {
		return "", errors.New("密文长度不是块大小的整数倍")
	}
	plaintext := make([]byte, len(ciphertext))
	for i := 0; i < len(ciphertext); i += aes.BlockSize {
		block.Decrypt(plaintext[i:i+aes.BlockSize], ciphertext[i:i+aes.BlockSize])
	}
	result, err := pkcs7Unpad(plaintext)
	if err != nil {
		return "", err
	}
	return string(result), nil
}

func aesCBCEncrypt(block cipher.Block, iv, plaintext []byte) ([]byte, error) {
	plaintext = pkcs7Pad(plaintext, aes.BlockSize)
	ciphertext := make([]byte, len(plaintext))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, plaintext)
	return ciphertext, nil
}

func aesCBCDecrypt(block cipher.Block, iv, ciphertext []byte) (string, error) {
	if len(ciphertext)%aes.BlockSize != 0 {
		return "", errors.New("密文长度不是块大小的整数倍")
	}
	plaintext := make([]byte, len(ciphertext))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, ciphertext)
	result, err := pkcs7Unpad(plaintext)
	if err != nil {
		return "", err
	}
	return string(result), nil
}

func aesCTREncrypt(block cipher.Block, iv, plaintext []byte) ([]byte, error) {
	ciphertext := make([]byte, len(plaintext))
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(ciphertext, plaintext)
	return ciphertext, nil
}

func aesCTRDecrypt(block cipher.Block, iv, ciphertext []byte) (string, error) {
	plaintext := make([]byte, len(ciphertext))
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(plaintext, ciphertext)
	return string(plaintext), nil
}

func aesGCMEncrypt(block cipher.Block, nonce, plaintext []byte) ([]byte, error) {
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return aesgcm.Seal(nil, nonce, plaintext, nil), nil
}

func aesGCMDecrypt(block cipher.Block, nonce, ciphertext []byte) (string, error) {
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

// ========== DES ==========

func desEncrypt(plaintext, keyStr, ivStr string) ([]byte, error) {
	key := padKey(keyStr, 8)
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	plainBytes := pkcs7Pad([]byte(plaintext), des.BlockSize)
	ciphertext := make([]byte, len(plainBytes))

	if ivStr != "" {
		iv := padKey(ivStr, des.BlockSize)
		mode := cipher.NewCBCEncrypter(block, iv)
		mode.CryptBlocks(ciphertext, plainBytes)
	} else {
		for i := 0; i < len(plainBytes); i += des.BlockSize {
			block.Encrypt(ciphertext[i:i+des.BlockSize], plainBytes[i:i+des.BlockSize])
		}
	}
	return ciphertext, nil
}

func desDecrypt(cipherBytes []byte, keyStr, ivStr string) (string, error) {
	key := padKey(keyStr, 8)
	block, err := des.NewCipher(key)
	if err != nil {
		return "", err
	}
	if len(cipherBytes)%des.BlockSize != 0 {
		return "", errors.New("密文长度不是块大小的整数倍")
	}
	plaintext := make([]byte, len(cipherBytes))

	if ivStr != "" {
		iv := padKey(ivStr, des.BlockSize)
		mode := cipher.NewCBCDecrypter(block, iv)
		mode.CryptBlocks(plaintext, cipherBytes)
	} else {
		for i := 0; i < len(cipherBytes); i += des.BlockSize {
			block.Decrypt(plaintext[i:i+des.BlockSize], cipherBytes[i:i+des.BlockSize])
		}
	}
	result, err := pkcs7Unpad(plaintext)
	if err != nil {
		return "", err
	}
	return string(result), nil
}

// ========== 3DES ==========

func tripleDESEncrypt(plaintext, keyStr, ivStr string) ([]byte, error) {
	key := padKey(keyStr, 24)
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}
	plainBytes := pkcs7Pad([]byte(plaintext), des.BlockSize)
	ciphertext := make([]byte, len(plainBytes))

	if ivStr != "" {
		iv := padKey(ivStr, des.BlockSize)
		mode := cipher.NewCBCEncrypter(block, iv)
		mode.CryptBlocks(ciphertext, plainBytes)
	} else {
		for i := 0; i < len(plainBytes); i += des.BlockSize {
			block.Encrypt(ciphertext[i:i+des.BlockSize], plainBytes[i:i+des.BlockSize])
		}
	}
	return ciphertext, nil
}

func tripleDESDecrypt(cipherBytes []byte, keyStr, ivStr string) (string, error) {
	key := padKey(keyStr, 24)
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return "", err
	}
	if len(cipherBytes)%des.BlockSize != 0 {
		return "", errors.New("密文长度不是块大小的整数倍")
	}
	plaintext := make([]byte, len(cipherBytes))

	if ivStr != "" {
		iv := padKey(ivStr, des.BlockSize)
		mode := cipher.NewCBCDecrypter(block, iv)
		mode.CryptBlocks(plaintext, cipherBytes)
	} else {
		for i := 0; i < len(cipherBytes); i += des.BlockSize {
			block.Decrypt(plaintext[i:i+des.BlockSize], cipherBytes[i:i+des.BlockSize])
		}
	}
	result, err := pkcs7Unpad(plaintext)
	if err != nil {
		return "", err
	}
	return string(result), nil
}

// ========== 哈希 ==========

func handleHash(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, "仅支持POST请求", http.StatusMethodNotAllowed)
		return
	}
	var req HashRequest
	if err := parseJSON(r, &req); err != nil {
		writeError(w, "请求参数解析失败", http.StatusBadRequest)
		return
	}

	if req.Data == "" {
		writeError(w, "数据不能为空", http.StatusBadRequest)
		return
	}

	var h hash.Hash
	switch req.Algorithm {
	case "md5":
		h = md5.New()
	case "sha1":
		h = sha1.New()
	case "sha256":
		h = sha256.New()
	case "sha512":
		h = sha512.New()
	default:
		writeError(w, "不支持的哈希算法: "+req.Algorithm, http.StatusBadRequest)
		return
	}

	h.Write([]byte(req.Data))
	result := hex.EncodeToString(h.Sum(nil))

	writeJSON(w, map[string]string{
		"result":    result,
		"algorithm": req.Algorithm,
	})
}

// ========== HMAC ==========

func handleHMAC(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, "仅支持POST请求", http.StatusMethodNotAllowed)
		return
	}
	var req HMACRequest
	if err := parseJSON(r, &req); err != nil {
		writeError(w, "请求参数解析失败", http.StatusBadRequest)
		return
	}

	if req.Data == "" {
		writeError(w, "数据不能为空", http.StatusBadRequest)
		return
	}
	if req.Key == "" {
		writeError(w, "密钥不能为空", http.StatusBadRequest)
		return
	}

	var mac hash.Hash
	switch req.Algorithm {
	case "hmac-sha256":
		mac = hmac.New(sha256.New, []byte(req.Key))
	case "hmac-sha512":
		mac = hmac.New(sha512.New, []byte(req.Key))
	default:
		writeError(w, "不支持的HMAC算法: "+req.Algorithm, http.StatusBadRequest)
		return
	}

	mac.Write([]byte(req.Data))
	result := hex.EncodeToString(mac.Sum(nil))

	writeJSON(w, map[string]string{
		"result":    result,
		"algorithm": req.Algorithm,
	})
}

// ========== 密钥/盐/IV 生成 ==========

func handleGenerateKey(w http.ResponseWriter, r *http.Request) {
	handleGenerate(w, r, "key")
}

func handleGenerateSalt(w http.ResponseWriter, r *http.Request) {
	handleGenerate(w, r, "salt")
}

func handleGenerateIV(w http.ResponseWriter, r *http.Request) {
	handleGenerate(w, r, "iv")
}

func handleGenerate(w http.ResponseWriter, r *http.Request, genType string) {
	if r.Method != http.MethodPost {
		writeError(w, "仅支持POST请求", http.StatusMethodNotAllowed)
		return
	}
	var req GenerateRequest
	if err := parseJSON(r, &req); err != nil {
		writeError(w, "请求参数解析失败", http.StatusBadRequest)
		return
	}

	defaultLengths := map[string]int{"key": 32, "salt": 16, "iv": 16}
	if req.Length <= 0 || req.Length > 1024 {
		req.Length = defaultLengths[genType]
	}
	if req.Format != "base64" {
		req.Format = "hex"
	}

	bytes := make([]byte, req.Length)
	if _, err := rand.Read(bytes); err != nil {
		writeError(w, "生成"+genType+"失败", http.StatusInternalServerError)
		return
	}

	var result string
	switch req.Format {
	case "base64":
		result = base64.StdEncoding.EncodeToString(bytes)
	default:
		result = hex.EncodeToString(bytes)
	}

	writeJSON(w, map[string]string{
		"result": result,
		"format": req.Format,
		"length": fmt.Sprintf("%d bytes", req.Length),
		"type":   genType,
	})
}

// ========== Base64 ==========

func handleBase64Encode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, "仅支持POST请求", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Data string `json:"data"`
	}
	if err := parseJSON(r, &req); err != nil {
		writeError(w, "请求参数解析失败", http.StatusBadRequest)
		return
	}

	result := base64.StdEncoding.EncodeToString([]byte(req.Data))
	writeJSON(w, map[string]string{"result": result})
}

func handleBase64Decode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, "仅支持POST请求", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Data string `json:"data"`
	}
	if err := parseJSON(r, &req); err != nil {
		writeError(w, "请求参数解析失败", http.StatusBadRequest)
		return
	}

	decoded, err := base64.StdEncoding.DecodeString(req.Data)
	if err != nil {
		writeError(w, "Base64解码失败: "+err.Error(), http.StatusBadRequest)
		return
	}

	writeJSON(w, map[string]string{"result": string(decoded)})
}

// ========== RSA ==========

func handleRSAGenerate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, "仅支持POST请求", http.StatusMethodNotAllowed)
		return
	}
	var req RSARequest
	if err := parseJSON(r, &req); err != nil {
		writeError(w, "请求参数解析失败", http.StatusBadRequest)
		return
	}

	if req.KeySize == 0 {
		req.KeySize = 2048
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, req.KeySize)
	if err != nil {
		writeError(w, "RSA密钥对生成失败", http.StatusInternalServerError)
		return
	}

	privBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes})

	pubBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		writeError(w, "公钥序列化失败", http.StatusInternalServerError)
		return
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: pubBytes})

	writeJSON(w, map[string]string{
		"publicKey":  string(pubPEM),
		"privateKey": string(privPEM),
		"keySize":    fmt.Sprintf("%d bits", req.KeySize),
	})
}

func handleRSAEncrypt(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, "仅支持POST请求", http.StatusMethodNotAllowed)
		return
	}
	var req RSARequest
	if err := parseJSON(r, &req); err != nil {
		writeError(w, "请求参数解析失败", http.StatusBadRequest)
		return
	}

	if req.PublicKey == "" || req.Data == "" {
		writeError(w, "公钥和数据不能为空", http.StatusBadRequest)
		return
	}

	block, _ := pem.Decode([]byte(req.PublicKey))
	if block == nil {
		writeError(w, "公钥PEM解析失败", http.StatusBadRequest)
		return
	}

	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		writeError(w, "公钥解析失败: "+err.Error(), http.StatusBadRequest)
		return
	}

	pubKey, ok := pubInterface.(*rsa.PublicKey)
	if !ok {
		writeError(w, "不是有效的RSA公钥", http.StatusBadRequest)
		return
	}

	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, pubKey, []byte(req.Data))
	if err != nil {
		writeError(w, "RSA加密失败: "+err.Error(), http.StatusInternalServerError)
		return
	}

	result := base64.StdEncoding.EncodeToString(ciphertext)
	writeJSON(w, map[string]string{"result": result})
}

func handleRSADecrypt(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, "仅支持POST请求", http.StatusMethodNotAllowed)
		return
	}
	var req RSARequest
	if err := parseJSON(r, &req); err != nil {
		writeError(w, "请求参数解析失败", http.StatusBadRequest)
		return
	}

	if req.PrivateKey == "" || req.Data == "" {
		writeError(w, "私钥和数据不能为空", http.StatusBadRequest)
		return
	}

	block, _ := pem.Decode([]byte(req.PrivateKey))
	if block == nil {
		writeError(w, "私钥PEM解析失败", http.StatusBadRequest)
		return
	}

	privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		writeError(w, "私钥解析失败: "+err.Error(), http.StatusBadRequest)
		return
	}

	ciphertext, err := base64.StdEncoding.DecodeString(req.Data)
	if err != nil {
		writeError(w, "密文Base64解码失败: "+err.Error(), http.StatusBadRequest)
		return
	}

	plaintext, err := rsa.DecryptPKCS1v15(rand.Reader, privKey, ciphertext)
	if err != nil {
		writeError(w, "RSA解密失败: "+err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSON(w, map[string]string{"result": string(plaintext)})
}

// ========== 工具函数 ==========

func padKey(keyStr string, size int) []byte {
	keyBytes := []byte(keyStr)
	if len(keyBytes) >= size {
		return keyBytes[:size]
	}
	padded := make([]byte, size)
	copy(padded, keyBytes)
	return padded
}

func getIV(ivStr string, size int) []byte {
	if ivStr == "" {
		iv := make([]byte, size)
		for i := range iv {
			iv[i] = 0x00
		}
		return iv
	}
	ivBytes := []byte(ivStr)
	if len(ivBytes) >= size {
		return ivBytes[:size]
	}
	padded := make([]byte, size)
	copy(padded, ivBytes)
	return padded
}

func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padText := make([]byte, padding)
	for i := range padText {
		padText[i] = byte(padding)
	}
	return append(data, padText...)
}

func pkcs7Unpad(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("数据为空")
	}
	padding := int(data[len(data)-1])
	if padding > len(data) || padding == 0 || padding > aes.BlockSize {
		return nil, errors.New("无效的填充")
	}
	for i := len(data) - padding; i < len(data); i++ {
		if data[i] != byte(padding) {
			return nil, errors.New("填充验证失败，请检查密钥和IV是否正确")
		}
	}
	return data[:len(data)-padding], nil
}

