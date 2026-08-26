package backup

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

var s3HTTP = &http.Client{Timeout: 10 * time.Minute}

type s3Client struct {
	endpoint  string
	bucket    string
	accessKey string
	secretKey string
	region    string
	pathStyle bool
}

func newS3Client(endpoint, bucket, accessKey, secretKey, region string, pathStyle bool) *s3Client {
	if region == "" {
		region = "us-east-1"
	}
	return &s3Client{
		endpoint:  strings.TrimRight(endpoint, "/"),
		bucket:    bucket,
		accessKey: accessKey,
		secretKey: secretKey,
		region:    region,
		pathStyle: pathStyle,
	}
}

func (c *s3Client) objectURL(key string) string {
	if c.pathStyle {
		return fmt.Sprintf("%s/%s/%s", c.endpoint, c.bucket, key)
	}
	u, _ := url.Parse(c.endpoint)
	return fmt.Sprintf("%s://%s.%s/%s", u.Scheme, c.bucket, u.Host, key)
}

func (c *s3Client) bucketURL(query string) string {
	base := c.objectURL("")
	base = strings.TrimSuffix(base, "/")
	if query != "" {
		return base + "?" + query
	}
	return base
}

func (c *s3Client) Put(ctx context.Context, key string, body []byte) error {
	rawURL := c.objectURL(key)
	now := time.Now().UTC()
	payloadHash := hexSHA256(body)

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, rawURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("x-amz-content-sha256", payloadHash)
	req.Header.Set("x-amz-date", now.Format("20060102T150405Z"))
	req.ContentLength = int64(len(body))

	c.sign(req, now, payloadHash)

	resp, err := s3HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("s3 put %d: %s", resp.StatusCode, b)
	}
	return nil
}

func (c *s3Client) Get(ctx context.Context, key string) ([]byte, error) {
	rawURL := c.objectURL(key)
	now := time.Now().UTC()
	payloadHash := hexSHA256(nil)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("x-amz-content-sha256", payloadHash)
	req.Header.Set("x-amz-date", now.Format("20060102T150405Z"))

	c.sign(req, now, payloadHash)

	resp, err := s3HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("s3 get %d: %s", resp.StatusCode, b)
	}
	return io.ReadAll(resp.Body)
}

func (c *s3Client) Delete(ctx context.Context, key string) error {
	rawURL := c.objectURL(key)
	now := time.Now().UTC()
	payloadHash := hexSHA256(nil)

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, rawURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("x-amz-content-sha256", payloadHash)
	req.Header.Set("x-amz-date", now.Format("20060102T150405Z"))

	c.sign(req, now, payloadHash)

	resp, err := s3HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 && resp.StatusCode != 404 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("s3 delete %d: %s", resp.StatusCode, b)
	}
	return nil
}

type s3Object struct {
	Key          string `xml:"Key"`
	Size         int64  `xml:"Size"`
	LastModified string `xml:"LastModified"`
}

type s3ListResult struct {
	Contents []s3Object `xml:"Contents"`
}

func (c *s3Client) List(ctx context.Context, prefix string) ([]s3Object, error) {
	query := "list-type=2"
	if prefix != "" {
		query += "&prefix=" + url.QueryEscape(prefix)
	}
	rawURL := c.bucketURL(query)
	now := time.Now().UTC()
	payloadHash := hexSHA256(nil)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("x-amz-content-sha256", payloadHash)
	req.Header.Set("x-amz-date", now.Format("20060102T150405Z"))

	c.sign(req, now, payloadHash)

	resp, err := s3HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("s3 list %d: %s", resp.StatusCode, body)
	}
	var result s3ListResult
	if err := xml.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("s3 list parse: %w", err)
	}
	return result.Contents, nil
}

func (c *s3Client) sign(req *http.Request, now time.Time, payloadHash string) {
	date := now.Format("20060102")
	datetime := now.Format("20060102T150405Z")

	parsedURL, _ := url.Parse(req.URL.String())
	host := parsedURL.Host

	req.Header.Set("Host", host)

	var headerNames []string
	headerMap := map[string]string{}
	for k := range req.Header {
		lk := strings.ToLower(k)
		headerNames = append(headerNames, lk)
		headerMap[lk] = strings.TrimSpace(req.Header.Get(k))
	}
	sort.Strings(headerNames)

	var canonicalHeaders strings.Builder
	for _, k := range headerNames {
		canonicalHeaders.WriteString(k)
		canonicalHeaders.WriteByte(':')
		canonicalHeaders.WriteString(headerMap[k])
		canonicalHeaders.WriteByte('\n')
	}
	signedHeaders := strings.Join(headerNames, ";")

	canonicalQueryString := parsedURL.RawQuery
	if parts := strings.Split(canonicalQueryString, "&"); len(parts) > 1 {
		sort.Strings(parts)
		canonicalQueryString = strings.Join(parts, "&")
	}

	canonicalRequest := strings.Join([]string{
		req.Method,
		parsedURL.EscapedPath(),
		canonicalQueryString,
		canonicalHeaders.String(),
		signedHeaders,
		payloadHash,
	}, "\n")

	credentialScope := strings.Join([]string{date, c.region, "s3", "aws4_request"}, "/")
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		datetime,
		credentialScope,
		hexSHA256([]byte(canonicalRequest)),
	}, "\n")

	signingKey := hmacSHA256(
		hmacSHA256(
			hmacSHA256(
				hmacSHA256([]byte("AWS4"+c.secretKey), []byte(date)),
				[]byte(c.region),
			),
			[]byte("s3"),
		),
		[]byte("aws4_request"),
	)
	signature := hex.EncodeToString(hmacSHA256(signingKey, []byte(stringToSign)))

	auth := fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		c.accessKey, credentialScope, signedHeaders, signature,
	)
	req.Header.Set("Authorization", auth)
}

func hexSHA256(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}
