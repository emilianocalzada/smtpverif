package main

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

// EmailVerifier contains the configuration for email verification
type EmailVerifier struct {
	DialTimeout time.Duration
	ProxyAddr   string
	ProxyUser   string
	ProxyPass   string
}

// VerifyResult represents the result of email verification
type VerifyResult struct {
	Email     string
	IsValid   bool
	ErrorMsg  string
	FullTrace []string
}

func NewEmailVerifier(proxyAddr, proxyUser, proxyPass string) *EmailVerifier {
	return &EmailVerifier{
		DialTimeout: 30 * time.Second, // Increased timeout
		ProxyAddr:   proxyAddr,
		ProxyUser:   proxyUser,
		ProxyPass:   proxyPass,
	}
}

func (v *EmailVerifier) Verify(email string) (*VerifyResult, error) {
	result := &VerifyResult{
		Email:     email,
		IsValid:   false,
		FullTrace: make([]string, 0),
	}

	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		result.ErrorMsg = "Invalid email format"
		return result, fmt.Errorf("invalid email format")
	}

	domain := parts[1]

	// Get MX records
	mxRecords, err := net.LookupMX(domain)
	if err != nil {
		result.ErrorMsg = "MX lookup failed"
		return result, fmt.Errorf("mx lookup failed: %v", err)
	}

	if len(mxRecords) == 0 {
		result.ErrorMsg = "No MX records found"
		return result, fmt.Errorf("no MX records found")
	}

	// Create proxy dialer
	var conn net.Conn
	if v.ProxyAddr != "" {
		var auth *proxy.Auth
		if v.ProxyUser != "" || v.ProxyPass != "" {
			auth = &proxy.Auth{
				User:     v.ProxyUser,
				Password: v.ProxyPass,
			}
		}

		dialer, err := proxy.SOCKS5("tcp", v.ProxyAddr, auth, proxy.Direct)
		if err != nil {
			return result, fmt.Errorf("proxy dialer creation failed: %v", err)
		}

		conn, err = dialer.Dial("tcp", fmt.Sprintf("%s:25", strings.TrimSuffix(mxRecords[0].Host, ".")))
	} else {
		conn, err = net.DialTimeout("tcp", fmt.Sprintf("%s:25", strings.TrimSuffix(mxRecords[0].Host, ".")), v.DialTimeout)
	}

	if err != nil {
		result.ErrorMsg = "Connection failed"
		return result, fmt.Errorf("connection failed: %v", err)
	}
	defer conn.Close()

	// Create buffered reader for better response handling
	reader := bufio.NewReader(conn)

	// Helper function to send command and get response
	sendCommand := func(cmd string) (string, error) {
		if cmd != "" {
			_, err := fmt.Fprintf(conn, "%s\r\n", cmd)
			if err != nil {
				return "", fmt.Errorf("failed to send command: %v", err)
			}
			result.FullTrace = append(result.FullTrace, fmt.Sprintf("> %s", cmd))
		}

		resp, err := reader.ReadString('\n')
		if err != nil {
			return "", fmt.Errorf("failed to read response: %v", err)
		}
		result.FullTrace = append(result.FullTrace, fmt.Sprintf("< %s", resp))
		return resp, nil
	}

	// Read initial greeting
	resp, err := sendCommand("")
	if err != nil {
		result.ErrorMsg = "Failed to read initial greeting"
		return result, err
	}

	// Use EHLO instead of HELO for ESMTP
	ehloCmd := fmt.Sprintf("EHLO %s", domain)
	resp, err = sendCommand(ehloCmd)
	if err != nil {
		result.ErrorMsg = "EHLO failed"
		return result, err
	}

	// Use a real-looking email address for MAIL FROM with ESMTP parameters
	fromCmd := fmt.Sprintf("MAIL FROM:<%s> SIZE=0", fmt.Sprintf("verify@%s", domain))
	resp, err = sendCommand(fromCmd)
	if err != nil {
		result.ErrorMsg = "MAIL FROM failed"
		return result, err
	}

	// RCPT TO command
	rcptCmd := fmt.Sprintf("RCPT TO:<%s>", email)
	resp, err = sendCommand(rcptCmd)
	if err != nil {
		result.ErrorMsg = "RCPT TO failed"
		return result, err
	}

	// Send QUIT
	sendCommand("QUIT")

	// Check response code
	if strings.HasPrefix(resp, "250") {
		result.IsValid = true
	} else {
		result.IsValid = false
		result.ErrorMsg = "Email address does not exist"
	}

	return result, nil
}

func main() {
	// Example usage with SOCKS5 proxy
	proxyAddr := "host:port" // Replace with your SOCKS5 proxy address
	proxyUser := "user"         // Optional: proxy username
	proxyPass := "pass"         // Optional: proxy password

	verifier := NewEmailVerifier(proxyAddr, proxyUser, proxyPass)

	result, err := verifier.Verify("user@example.com")

	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("Email: %s\n", result.Email)
	fmt.Printf("Is Valid: %v\n", result.IsValid)
	if result.ErrorMsg != "" {
		fmt.Printf("Error Message: %s\n", result.ErrorMsg)
	}

	fmt.Println("\nFull SMTP Trace:")
	for _, trace := range result.FullTrace {
		fmt.Println(trace)
	}
}
