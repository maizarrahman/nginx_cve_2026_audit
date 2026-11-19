# Audit Konfigurasi Nginx
Audit konfigurasi Nginx untuk kerentanan keamanan berikut ini:

**CVE-2026-123007**: Kerentanan pada pemrosesan HTTP/2 yang dapat menyebabkan heap memory corruption (penulisan memori di luar batas). Dapat dimanfaatkan penyerang untuk merusak memori worker NGINX dan berpotensi menjalankan kode berbahaya.

**CVE-2026-123633**: Kerentanan _use-after-free_ pada HTTP/2 saat koneksi sedang ditutup (_connection draining_) sementara koneksi ke upstream masih berlangsung. Dapat menyebabkan crash worker atau berpotensi eksekusi kode.

**CVE-2026-121810**: Kerentanan _use-after-free_ pada HTTP/3/QUIC ketika terjadi proses penutupan koneksi (_connection draining_) bersamaan dengan pembuatan stream dan komunikasi ke upstream.

**CVE-2026-123634**: Kerentanan _use-after-free_ pada mekanisme DNS _resolver_ NGINX ketika memproses respons DNS. Kondisi tertentu, seperti penggunaan _resolver_ dengan `proxy_pass` dinamis atau konfigurasi _mirror_, dapat memicu kerentanan.

**CVE-2026-113425**: Kerentanan _use-after-free_ pada _Mail Proxy Module_ ketika klien memutus koneksi selama proses autentikasi melalui `auth_http`. Dapat menyebabkan _crash_ atau potensi eksekusi kode.


## Cara Menjalankan
Simpan script di server NGINX, lalu:
```bash
chmod +x nginx_cve_audit.sh
sudo ./nginx_cve_audit.sh
```
Kalau NGINX menggunakan lokasi binary khusus:
```bash
sudo NGINX_BIN=/usr/sbin/nginx ./nginx_cve_audit.sh
```
Simpan hasil audit ke file:
```bash
sudo ./nginx_cve_audit.sh 2>&1 | tee nginx_cve_audit_$(date +%F).log
```


## Cara membaca hasil audit
[RISK] = Fitur terdeteksi aktif dan versi belum diperbarui; indikasi risiko tinggi.
[WARN] = Ada konfigurasi yang perlu ditinjau manual.
[OK] = Pola exposure tidak ditemukan, atau versi sudah diperbarui.
