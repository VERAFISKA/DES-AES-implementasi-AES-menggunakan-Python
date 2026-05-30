import os
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad

def generate_key(password: str) -> bytes:
    """Mengubah password teks menjadi key 256-bit menggunakan SHA-256."""
    hasher = SHA256.new(password.encode('utf-8'))
    return hasher.digest()

def encrypt_file(file_path: str, password: str):
    """Mengenkripsi file menggunakan AES-256 CBC."""
    if not os.path.exists(file_path):
        print(f"Error: File '{file_path}' tidak ditemukan!")
        return

    key = generate_key(password)
    
    # Membaca file asli
    with open(file_path, 'rb') as f:
        plaintext = f.read()
    
    # AES CBC membutuhkan data kelipatan 16 bytes (padding)
    padded_data = pad(plaintext, AES.block_size)
    
    # Membuat cipher dengan IV (Initialization Vector) acak
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(padded_data)
    
    # Simpan IV dan ciphertext ke file baru (.enc)
    output_path = file_path + ".enc"
    with open(output_path, 'wb') as f:
        f.write(cipher.iv)
        f.write(ciphertext)
        
    print(f"File berhasil dienkripsi! Disimpan sebagai: {output_path}")

def decrypt_file(encrypted_file_path: str, password: str):
    """Mendekripsi file hasil enkripsi AES-256 CBC."""
    if not os.path.exists(encrypted_file_path):
        print(f"Error: File '{encrypted_file_path}' tidak ditemukan!")
        return

    key = generate_key(password)
    
    # Membaca file terenkripsi
    with open(encrypted_file_path, 'rb') as f:
        iv = f.read(16)  # 16 byte pertama adalah IV
        ciphertext = f.read() # Sisanya adalah data terenkripsi
        
    try:
        # Membuat cipher untuk dekripsi
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        decrypted_padded_data = cipher.decrypt(ciphertext)
        
        # Menghapus padding untuk mengembalikan data asli
        original_data = unpad(decrypted_padded_data, AES.block_size)
        
        # Simpan hasil dekripsi ke file baru
        output_path = encrypted_file_path.replace(".enc", "_decrypted.txt")
        with open(output_path, 'wb') as f:
            f.write(original_data)
            
        print(f"File berhasil didekripsi! Disimpan sebagai: {output_path}")
        
    except (ValueError, KeyError):
        print("Gagal mendekripsi! Password salah atau file rusak.")

# --- CONTOH PENGGUNAAN DENGAN INPUT PASSWORD ---
if __name__ == "__main__":
    nama_file = "rahasia.txt"

    # 1. Membuat file uji coba (.txt) terlebih dahulu dengan data identitas lengkap
    with open(nama_file, "w", encoding="utf-8") as f:
        f.write("==================================================\n"
                "           DOKUMEN IDENTITAS MAHASISWA            \n"
                "==================================================\n"
                "Nama      : Vera Fiska\n"
                "NIM       : 105841112124\n"
                "Kelas     : 4D\n"
                "Prodi     : Informatika\n"
                "Fakultas  : Teknik\n"
                "TTL       : Pellengnge, 09 April 2026\n"
                "Alamat    : Desa Lapasa, Kec. Mare, Kab. Bone\n"
                "Pekerjaan : Mahasiswa\n"
                "--------------------------------------------------\n"
                "Status    : Terproteksi Algoritma AES-256 CBC\n"
                "==================================================")
        
    print(f"File asli '{nama_file}' telah dibuat otomatis.")
    print("--------------------------------------------------")

    # 2. Proses Enkripsi (Meminta Input Password dari User)
    print("[PROSES ENKRIPSI]")
    password_enkripsi = input("Masukkan password untuk mengunci file: ")
    encrypt_file(nama_file, password_enkripsi)
    print("--------------------------------------------------")

    # 3. Proses Dekripsi (Meminta Input Password Kembali untuk Membuka)
    print("[PROSES DEKRIPSI]")
    file_terenkripsi = nama_file + ".enc"
    password_dekripsi = input("Masukkan password untuk membuka file .enc: ")
    decrypt_file(file_terenkripsi, password_dekripsi)