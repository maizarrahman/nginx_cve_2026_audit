# Audit Konfigurasi Nginx
Audit konfigurasi Nginx untuk kerentanan keamanan berikut ini:

| Nama CVE | Penjelasan singkat CVE |
| --- | --- | --- |
| CVE-2026-123007 | Kerentanan pada pemrosesan HTTP/2 yang dapat menyebabkan heap memory corruption (penulisan memori di luar batas). Dapat dimanfaatkan penyerang untuk merusak memori worker NGINX dan berpotensi menjalankan kode berbahaya. |
| CVE-2026-123633 | Kerentanan use-after-free pada HTTP/2 saat koneksi sedang ditutup (connection draining) sementara koneksi ke upstream masih berlangsung. Dapat menyebabkan crash worker atau berpotensi eksekusi kode. |
| CVE-2026-121810 | Kerentanan use-after-free pada HTTP/3/QUIC ketika terjadi proses penutupan koneksi (connection draining) bersamaan dengan pembuatan stream dan komunikasi ke upstream. |
| CVE-2026-123634 | Kerentanan use-after-free pada mekanisme DNS resolver NGINX ketika memproses respons DNS. Kondisi tertentu, seperti penggunaan resolver dengan proxy_pass dinamis atau konfigurasi mirror, dapat memicu kerentanan. |
| CVE-2026-113425 | Kerentanan use-after-free pada Mail Proxy Module ketika klien memutus koneksi selama proses autentikasi melalui auth_http. Dapat menyebabkan crash atau potensi eksekusi kode. |


