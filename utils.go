package main

import (
	"crypto/tls"
	"regexp"
	"strings"
	"time"

	"github.com/valyala/fasthttp"
)

var (
	timeout       int
	maxConcurrent int
	userAgent     string
	urlFile       string
	cmdExec       string
	outFile       string
	rexMatch      string

	allTargets []string

	baseRex    = regexp.MustCompile(`uid=\d+?\(\w+?\)\s*?gid=\d+?\(\w+?\)\s*groups=\d+?\(\w+?\)`)
	versRex1   = regexp.MustCompile(`(?i)<meta\sname="ajs-version-number"\scontent="([^"]+)">`)
	versRex2   = regexp.MustCompile(`(?i)<span\s*id='footer-build-information'>([\d\.]+)</span>`)
	versRex3   = regexp.MustCompile(`(?i)<li.class="print-only">printed.by.atlassian.confluence.([\d\.]+)<\/li>`)
	httpClient = fasthttp.Client{
		MaxIdemponentCallAttempts: 512,
		WriteTimeout:              3 * time.Second,
		MaxConnDuration:           3 * time.Second,
		MaxIdleConnDuration:       2 * time.Second,
		MaxConnWaitTimeout:        5 * time.Second,
		// less emphasis on read because at almost all times
		// we're bound to not get a response and timeout
		ReadTimeout: 3 * time.Second,
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	lackofart = `
  +-------------------------------+
  |    C O N F L U E N T P W N    |
  +-------------------------------+

[+] ConfluentPwn by RedHunt Labs - A Modern Attack Surface (ASM) Management Company
[+] Author: Pinaki Mondal (RHL Research Team)
[+] Continuously Track Your Attack Surface using https://redhuntlabs.com/nvadr.
`
)

func cookHTTPRequest(requri string) *fasthttp.Request {
	req := fasthttp.AcquireRequest()
	req.SetRequestURI(requri)
	req.Header.SetConnectionClose()
	req.Header.SetMethod("GET")
	// set a custom user agent if supplied
	if len(userAgent) > 0 {
		req.Header.SetUserAgent(userAgent)
	}
	return req
}

func checkScheme(host string) string {
	if !strings.Contains(host, "://") {
		return "http://" + host
	}
	return host
}
