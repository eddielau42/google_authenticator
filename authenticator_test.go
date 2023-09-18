package google_authenticator

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func setup(t *testing.T) func(t *testing.T) {
    // Setup : ...

    return func(t *testing.T) {
        // Teardown...
    }
}

func TestCreateSecret(t *testing.T) {
    teardown := setup(t)
    defer teardown(t)

    const (
        secretLen = 16
        makeTimes = 3
    )
    
    for i := 0; i < makeTimes; i++ {
        secretStr := GA.CreateSecret(secretLen)
        t.Logf("secret: %s\n", secretStr)
        assert.NotEmpty(t, secretStr)
    }
}

func TestProvisionURI(t *testing.T) {
    teardown := setup(t)
    defer teardown(t)

    testCases := []struct {
        user, issuer, secret, uri string
    }{
        {"foo", "company", "xxx", "otpauth://totp/company:test?issuer=company&secret=x"},
        {"bar", "", "xxx", "otpauth://totp/test?secret=x"},
    }
    for _, testCase := range testCases {
        uri := GA.ProvisionURI(testCase.user, testCase.issuer, testCase.secret)
        t.Logf("user: %s, issuer: %s, secret: %s, URI: %s\n", testCase.user, testCase.issuer, testCase.secret, uri)
        assert.Equal(t, uri, testCase.uri)
    }
    
}

func TestQRCode(t *testing.T) {
    teardown := setup(t)
    defer teardown(t)

    testCases := []struct{
        user, issuer string
        size int
        level string
    }{
        {"foo", "local", 100, "M"},
        {"bar", "testing", 150, "Q"},
        {"baz", "", 0, "H"},
    }

    for _, testCase := range testCases {
        secret := GA.CreateSecret(16)
        uri := GA.ProvisionURI(testCase.user, testCase.issuer, secret)
        qrcodeURL := GA.QRCodeURL(uri, testCase.size, testCase.level)
        t.Logf("URI: %s | QRcode-URL: %s\n", uri, qrcodeURL)
    }
}

func TestGetCode(t *testing.T) {
    teardown := setup(t)
    defer teardown(t)

    const secret = "WH7ZSQXSVLGJEYBM"
    ts := time.Now().Unix()

    code, err := GA.GetCode(secret, ts)
    t.Logf("get_code: %v | err: %v\n", code, err)
}

func TestVerifyCode(t *testing.T) {
    teardown := setup(t)
    defer teardown(t)

    testCases := []struct{
        secret string
        code string
    }{
        // {"FVN4LPN3LP7B33YL", "838738"},
        // {"WH7ZSQXSVLGJEYBM", "730240"},
        {"UGRXTRRJN5NDGR3E", "719224"},
    }
    
    for _, testCase := range testCases {
        passed := GA.VerifyCode(testCase.secret, testCase.code)
        t.Logf("verify_code (secret: %v, code: %v) ---> passed: %v\n", testCase.secret, testCase.code, passed)
        assert.True(t, passed, "verified: %", passed)
    }

}
