# 🔍 Panduan Mengurangi False Positives (AI & Manual Verification)

Dokumen ini berisi panduan praktis untuk meminimalkan *false positives* saat menggunakan kecerdasan buatan (AI) dalam analisis kerentanan serta alur verifikasi manual sebelum melaporkan temuan.

---

## 1. Minta Bukti Eksekusi Konkret (PoC), Bukan Sekadar Analisis Kode
Saat berinteraksi dengan AI untuk menganalisis suatu kerentanan, hindari pertanyaan umum seperti *"Apakah kode ini rentan?"*. Ajukan perintah/prompt yang mewajibkan AI membuktikannya secara konkret.

* **Payload & Request Lengkap**: Minta AI menuliskan command `curl` lengkap, HTTP raw request, atau script exploit (Python/bash) yang dapat langsung dieksekusi.
* **Penjelasan Langkah demi Langkah**: AI harus menjelaskan dengan detail alur eksekusi dari input yang dikirimkan hingga respons yang diterima oleh server backend.
* **Testing Environment**: Jika memungkinkan, minta AI memandu proses setup lingkungan pengujian lokal (staging/docker container) untuk mereproduksi temuan tersebut secara langsung.

> [!TIP]
> **Contoh Prompt yang Baik:**
> *"Analisis fungsi/endpoint berikut untuk celah keamanan SQL Injection. Jika Anda menemukan kerentanan, buatlah payload PoC berupa HTTP raw request dan perintah curl lengkap untuk membuktikannya. Jelaskan langkah demi langkah bagaimana payload tersebut mengeksploitasi logika backend."*

---

## 2. Verifikasi Manual Sebelum Pelaporan
Jangan pernah mengirimkan laporan (bug bounty/pentest) secara langsung dari output AI tanpa verifikasi langsung pada target (yang berada dalam scope RoE).

1. **Hipotesis AI**: Terima temuan AI hanya sebagai hipotesis awal atau indikasi potensi kerentanan.
2. **Reproduksi Manual**: Lakukan pengujian langsung di lingkungan target asli atau staging menggunakan payload yang telah disesuaikan.
3. **Konfirmasi Dampak Nyata**: Pastikan kerentanan menghasilkan dampak nyata (seperti kebocoran data, eksekusi perintah/RCE, atau pengalihan otorisasi), bukan sekadar respons error teoritis yang tidak dapat dieksploitasi lebih jauh.

---

## 3. Lakukan Cross-Check dengan Tool Statis dan Dinamis
Gunakan AI sebagai akselerator, bukan satu-satunya penentu. Kombinasikan analisis AI dengan perkakas pengujian keamanan standar industri:

* **Dynamic Application Security Testing (DAST)**: Gunakan **Burp Suite** atau **OWASP ZAP** untuk memantau request dan response secara langsung, serta memodifikasi parameter secara interaktif.
* **Static Application Security Testing (SAST)**: Jalankan static analyzer seperti **Semgrep** atau **CodeQL** untuk melakukan cross-reference terhadap temuan struktural pada kode sumber.
* **Tingkat Keyakinan (Confidence)**: Apabila AI, SAST, dan pengujian manual DAST semuanya menunjukkan hasil yang konsisten, tingkat keyakinan terhadap kerentanan tersebut sangat tinggi.

---

## 4. Berikan Konteks Lengkap kepada AI
AI sering kali berasumsi skenario terburuk (*worst-case scenario*) yang menghasilkan false positive tinggi apabila tidak diberikan informasi kontekstual yang cukup. Pastikan Anda menyertakan detail berikut dalam prompt:

* **Versi Framework & Library**: Sebutkan versi bahasa pemrograman dan framework yang digunakan (misalnya: *PHP 8.2, Laravel 10.x*).
* **Mekanisme Keamanan yang Ada**: Informasikan jika sudah ada WAF (Web Application Firewall), fungsi sanitasi (`htmlspecialchars`, dll), atau middleware otentikasi.
* **Alur Autentikasi/Otorisasi**: Jelaskan bagaimana session ditangani dan hak akses setiap user diatur pada endpoint tersebut.

---

## 5. Minta AI Menyertakan Tingkat Keyakinan dan Argumen Mitigasi
Perintahkan AI untuk tidak langsung menyatakan kode tersebut vulnerable tanpa menganalisis faktor mitigasi yang mungkin sudah diterapkan secara implisit.

> [!TIP]
> **Contoh Prompt Penyeimbang:**
> *"Evaluasi potongan kode ini untuk celah SSRF. Berikan penilaian tingkat keyakinan Anda (Low/Medium/High). Jika Anda ragu atau melihat adanya filter/mitigasi yang membuat eksploitasi tidak berjalan, jelaskan secara mendalam mengapa skenario ini kemungkinan besar merupakan false positive."*

---

## 6. Lakukan Uji Ulang dengan Teknik "Devil's Advocate"
Setelah AI memberikan temuan kerentanan, tantang balik hasil tersebut untuk memastikan kekuatannya secara logika.

* Tanyakan kepada AI: *"Mengapa potongan kode ini TIDAK rentan terhadap kerentanan tersebut?"* atau *"Skenario apa yang dapat mencegah payload ini berjalan?"*.
* Jika argumen AI yang menyatakan kode tersebut aman terasa lebih logis dan didukung oleh arsitektur aplikasi, maka temuan awal kemungkinan besar merupakan *false positive*.
