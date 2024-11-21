package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// 生成消息认证码（MAC）
func generateMAC(message, key []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	return hex.EncodeToString(mac.Sum(nil))
}

// 验证 MAC
func verifyMAC(message, receivedMAC, key []byte) bool {
	expectedMAC := generateMAC(message, key)
	return hmac.Equal([]byte(expectedMAC), receivedMAC)
}

func main() {
	// 定义密钥和消息
	key := []byte("xxxxxxxxx")
	message := []byte("This is a secure message")

	// 生成 MAC
	mac := generateMAC(message, key)
	fmt.Println("Generated MAC:", mac)

	// 模拟接收的 MAC，用于验证
	receivedMAC, _ := hex.DecodeString(mac)
	fmt.Println("receivedMAC:", receivedMAC)

	// 验证接收到的 MAC 是否正确
	if verifyMAC(message, receivedMAC, key) {
		fmt.Println("MAC is valid")
	} else {
		fmt.Println("MAC is invalid")
	}
}
