# Demo hardening patch

File yang sudah dibuat:
- `demo-security-fix.js`
- `demo-ops-fix.js`

Tambahkan ke file `index.html` sebelum tag penutup `</body>`:

```html
<script src="./demo-security-fix.js"></script>
<script src="./demo-ops-fix.js"></script>
```

Fungsi patch berikut:
- session aman + timeout logout otomatis
- hash password PBKDF2
- DB tidak crash saat korup
- backup & restore JSON
- validasi tanggal absensi tidak boleh masa depan
- konfirmasi saat simpan absensi
- tombol export/import tersedia di UI
- session login otomatis pulih saat refresh
