CREATE DATABASE IF NOT EXISTS absensi CHARACTER SET utf8mb4;
USE absensi;

CREATE TABLE IF NOT EXISTS admins (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(50) NOT NULL UNIQUE,
  password_hash VARCHAR(100) NOT NULL
);

CREATE TABLE IF NOT EXISTS students (
  id INT PRIMARY KEY,               -- nomor urut kelas 1..33
  name VARCHAR(100) NOT NULL UNIQUE
);

-- Satu siswa = satu status per tanggal & sesi (dijamin oleh PRIMARY KEY)
CREATE TABLE IF NOT EXISTS attendance (
  student_id INT NOT NULL,
  att_date DATE NOT NULL,
  session ENUM('Pagi','Sore') NOT NULL,
  status ENUM('Hadir','Sakit','Izin','Alpa','Bolos') NOT NULL,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (student_id, att_date, session),
  FOREIGN KEY (student_id) REFERENCES students(id)
);
-- 33 siswa dan akun admin pertama diisi otomatis oleh server.js saat pertama dijalankan.
