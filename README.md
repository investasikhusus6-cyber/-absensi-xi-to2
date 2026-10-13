# Absensi Apel XI TO 2 — deploy di Vercel

Vercel tidak punya database MySQL sendiri. Pakai MySQL gratis dari luar, mis. TiDB Cloud Serverless (gratis), Aiven, atau Railway.

## 1. Siapkan database
Buat cluster/DB MySQL, catat host, port, user, password, nama database. Tabel, 33 siswa, dan admin dibuat otomatis oleh aplikasi saat pertama diakses (`schema.sql` hanya referensi).

## 2. Unggah ke Vercel
- Push folder ini ke GitHub, lalu Vercel -> Add New Project -> pilih repo. Framework: Other. Tanpa build command.
- Atau: `npm i -g vercel` lalu `vercel` di folder ini.

## 3. Environment Variables (Project Settings)
DB_HOST, DB_PORT, DB_USER, DB_PASS, DB_NAME,
SESSION_SECRET (teks acak min. 16 karakter, wajib),
ADMIN_USER, ADMIN_PASS (akun admin pertama; ganti setelah masuk).
Lalu Redeploy.

## Uji lokal
`DB_SSL=false SESSION_SECRET=teksrahasiapanjang123 ADMIN_PASS=xxx DB_USER=root DB_NAME=absensi npm start`

## Pencadangan
`mysqldump -h HOST -u USER -p NAMA_DB > cadangan_$(date +%F).sql` (atau fitur backup dari penyedia database).

## Daftar uji manual
- 33 nama tampil tanpa ganda; klik status -> "Tersimpan ✓"; muat ulang -> tetap ada.
- Tanggal/sesi berbeda -> data terpisah.
- Ekspor rentang tanggal -> 3 sheet; Hadir tidak ada di REKAP KETERANGAN; belum diabsen = kosong.
