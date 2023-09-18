package google_authenticator

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Google Authenticator 接口
type GoogleAuthenticator interface{
    CreateSecret(length int) string
    GetCode(secret string, val int64) (int32, error)
    VerifyCode(secret, code string) bool
    ProvisionURI(user, issuer, secret string) string
    QRCodeURL(uri string, size int, level string) string
}

var (
   GA GoogleAuthenticator
   once sync.Once
)

type authenticator struct {}


func init() {
    once.Do(func() {
        GA = &authenticator{}
    })
}

// CreateSecret
func (*authenticator)CreateSecret(length int) string {
    const base32LookupTable = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567="
    
    var (
        err error
        secret string
    )

    randBytes, err := makeRandomBytes(length)
    if err == nil {
        for i := 0; i < length; i++ {
            secret += string(base32LookupTable[randBytes[i]&31])
        }
    }

    return secret
}

// GetCode
func (*authenticator)GetCode(secret string, val int64) (int32, error) {
    h, err := hmacSha1(secret, val)
    if err != nil {
        return -1, fmt.Errorf("hmacSha1 error: %w", err)
    }

	offset := h[19] & 0x0F
	truncated := binary.BigEndian.Uint32(h[offset : offset+4])
	truncated &= 0x7FFFFFFF
	digits := truncated % 1000000

	return int32(digits), nil
}

// VerifyCode
func (ga *authenticator)VerifyCode(secret, code string) bool {
    const discrepancy = 1

    ts := math.Floor(float64(time.Now().Unix() / 30))

    for i := 0-discrepancy; i <= discrepancy; i += discrepancy {
        c, err := ga.GetCode(secret, int64(ts)+int64(i))
        if err != nil {
            return false
        }
        if strconv.FormatInt(int64(c), 10) == code {
            return true
        }
    }

    return false
}

// ProvisionURI
func (*authenticator)ProvisionURI(user, issuer, secret string) string {
    // Sample: otpauth://totp/Company:joe_example@gmail.com?secret=[...]&issuer=Company
    const schema = "otpauth://"
    
    auth := "totp/"
    q := url.Values{}
    q.Add("secret", secret)
    
    if issuer != "" {
        auth += issuer + ":"
        q.Add("issuer", issuer)
    }
    return schema + auth + user + "?" + q.Encode()
}

// QRCodeURL
func (*authenticator)QRCodeURL(uri string, size int, level string) string {
    const QRCodeBaseURL = `https://api.qrserver.com/v1/create-qr-code`

    q := url.Values{}
    q.Add("data", uri)

    if size <= 0 {
        size = 200
    }
    q.Add("size", fmt.Sprintf("%dx%d", size, size))

    // L|M|Q|H
    if level == "" || strings.Contains(`L|M|Q|H`, level) {
        level = "M"
    }
    q.Add("ecc", level)

    return QRCodeBaseURL + "?" + q.Encode()
}

// makeRandBytes
func makeRandomBytes(length int) ([]byte, error) {
    var (
        err error
        bytes []byte
    )

    if length < 1 {
        bytes = []byte{}
    } else {
        bytes = make([]byte, length)
    }

    _, err = io.ReadFull(rand.Reader, bytes)
    if err != nil {
        return nil, fmt.Errorf("make rand bytes error: %w", err)
    }

    return bytes, nil
}

// hmacSha1
func hmacSha1(key string, t int64) ([]byte, error) {
    var (
        err error
    )

	decodeKey, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(key)
	if err != nil {
		return nil, fmt.Errorf("secret base32.Decode error: %w", err)
	}

	hmacSha1 := hmac.New(sha1.New, decodeKey)
    err = binary.Write(hmacSha1, binary.BigEndian, t)
	if err != nil {
		return nil, fmt.Errorf("hash error: %w", err)
	}

    return hmacSha1.Sum(nil), nil
}