import os
import time
import tkinter as tk
from tkinter import filedialog, ttk, messagebox
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from PIL import Image

# --------------------------
# НАЛАШТУВАННЯ ДЛЯ ГЕНЕРАЦІЇ КЛЮЧА
# --------------------------
# Використовуємо персональні дані для генерації ключа: Петрікіна Владислава Сергіївна, 22.07.2005
BASE_PASSWORD = "Vlada2005Петрікіна2207" 
SALT = os.urandom(16) # Сіль для PBKDF2

class TwoStepProtectorApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Двоетапний захист з аналітикою (ЛР №7)")
        self.geometry("800x600")
        
        # ВИПРАВЛЕННЯ: Спочатку визначте self.password
        self.password = BASE_PASSWORD 
        self.key = self._generate_key()
        
        self.original_file_path = ""
        self.cover_image_path = ""
        self.temp_dir = "temp_lab7"
        
        self._setup_ui()

    def _generate_key(self):
        """Генерація ключа AES-256 (32 байти) з пароля за допомогою PBKDF2."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=SALT,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(self.password.encode() if isinstance(self.password, str) else self.password)

    def _setup_ui(self):
        # Фрейм для вибору файлів
        file_frame = ttk.LabelFrame(self, text="📁 Вибір файлів")
        file_frame.pack(padx=10, pady=10, fill="x")

        # Вибір оригінального файлу
        ttk.Label(file_frame, text="Вихідний файл:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.file_entry = ttk.Entry(file_frame, width=80)
        self.file_entry.grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(file_frame, text="Огляд", command=self._select_file).grid(row=0, column=2, padx=5, pady=5)

        # Вибір зображення-носія
        ttk.Label(file_frame, text="Зображення-носій (PNG/BMP):").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.image_entry = ttk.Entry(file_frame, width=80)
        self.image_entry.grid(row=1, column=1, padx=5, pady=5)
        ttk.Button(file_frame, text="Огляд", command=self._select_image).grid(row=1, column=2, padx=5, pady=5)

        # Кнопки операцій
        op_frame = ttk.Frame(self)
        op_frame.pack(padx=10, pady=5, fill="x")
        ttk.Button(op_frame, text="🛡️ Захист (Шифр + Стеганографія)", command=self._run_protection).pack(side=tk.LEFT, padx=5, pady=5, fill="x", expand=True)
        ttk.Button(op_frame, text="🔓 Відновлення", command=self._run_recovery).pack(side=tk.LEFT, padx=5, pady=5, fill="x", expand=True)
        
        # Область для виводу аналітики
        self.analysis_label = ttk.Label(self, text="📊 АНАЛІТИЧНИЙ МОДУЛЬ:\nОчікування операції...", justify=tk.LEFT)
        self.analysis_label.pack(padx=10, pady=10, fill="both")
        
        # Область для логування
        self.log_text = tk.Text(self, height=12, state='disabled', wrap='word')
        self.log_text.pack(padx=10, pady=5, fill="both", expand=True)
        
        self.log("Ключ AES-256 згенеровано на основі персональних даних. Ключ: " + self.key.hex()[:16] + "...")
    
    # --- UI Хелпери ---
    def log(self, message):
        """Додає повідомлення до логу."""
        self.log_text.config(state='normal')
        self.log_text.insert(tk.END, f"[{time.strftime('%H:%M:%S')}] {message}\n")
        self.log_text.see(tk.END)
        self.log_text.config(state='disabled')

    def _select_file(self):
        path = filedialog.askopenfilename(title="Виберіть файл для захисту")
        if path:
            self.original_file_path = path
            self.file_entry.delete(0, tk.END)
            self.file_entry.insert(0, path)

    def _select_image(self):
        path = filedialog.askopenfilename(title="Виберіть зображення-носій (PNG/BMP)", filetypes=[("Image files", "*.png *.bmp")])
        if path:
            self.cover_image_path = path
            self.image_entry.delete(0, tk.END)
            self.image_entry.insert(0, path)

    # --- ЛОГІКА ЗАХИСТУ ---

    def _run_protection(self):
        """Запускає повний цикл захисту."""
        if not self.original_file_path or not self.cover_image_path:
            messagebox.showerror("Помилка", "Будь ласка, оберіть вихідний файл та зображення-носій.")
            return

        if not os.path.exists(self.temp_dir):
            os.makedirs(self.temp_dir)
            
        encrypted_file = os.path.join(self.temp_dir, "encrypted.bin")
        stego_file = os.path.join(self.temp_dir, "stego_result.png")
        
        self.log("\n--- ЗАПУСК ДВОЕТАПНОГО ЗАХИСТУ ---")
        try:
            # 1. Етап 1: Шифрування
            original_size = os.path.getsize(self.original_file_path)
            self.log(f"1. Етап 1 (Шифрування AES). Оригінальний розмір: {original_size} байт")
            t_enc = self._encrypt_file(self.original_file_path, encrypted_file)
            encrypted_size = os.path.getsize(encrypted_file)
            self.log(f"   -> Створено: {os.path.basename(encrypted_file)}. Розмір: {encrypted_size} байт. Час: {t_enc:.4f} с")

            # 2. Етап 2: Стеганографія
            self.log("2. Етап 2 (LSB-стеганографія). Приховування зашифрованих даних.")
            t_steg = self._hide_data(self.cover_image_path, encrypted_file, stego_file)
            stego_size = os.path.getsize(stego_file)
            self.log(f"   -> Створено: {os.path.basename(stego_file)}. Розмір: {stego_size} байт. Час: {t_steg:.4f} с")

            self._update_analysis(original_size, encrypted_size, stego_size, t_enc, t_steg, 0, integrity=None)
            self.log("✅ Захист успішно завершено! Файл-результат у temp_lab7/stego_result.png")

        except Exception as e:
            messagebox.showerror("Помилка захисту", str(e))
            self.log(f"❌ ПОМИЛКА: {e}")

    def _run_recovery(self):
        """Запускає цикл повного відновлення."""
        stego_file = os.path.join(self.temp_dir, "stego_result.png")
        if not os.path.exists(stego_file):
            messagebox.showerror("Помилка", "Файл stego_result.png не знайдено. Спочатку виконайте захист.")
            return

        extracted_file = os.path.join(self.temp_dir, "extracted.bin")
        decrypted_file = filedialog.asksaveasfilename(defaultextension=os.path.splitext(self.original_file_path)[1] if self.original_file_path else ".txt", title="Зберегти відновлений файл як")
        
        if not decrypted_file:
            return

        self.log("\n--- ЗАПУСК ПОВНОГО ВІДНОВЛЕННЯ ---")
        try:
            # 1. Зворотний Етап 2: Вилучення
            self.log("1. Вилучення даних (LSB-декодування)...")
            self._extract_data(stego_file, extracted_file)
            self.log("   -> Дані успішно вилучено.")
            
            # 2. Зворотний Етап 1: Розшифрування
            self.log("2. Розшифрування AES...")
            t_dec = self._decrypt_file(extracted_file, decrypted_file)
            self.log(f"   -> Файл відновлено: {os.path.basename(decrypted_file)}. Час: {t_dec:.4f} с")

            # 3. Перевірка цілісності
            integrity = self._check_integrity(self.original_file_path, decrypted_file)
            self.log(f"   -> Перевірка цілісності: {'УСПІШНО' if integrity else 'ПРОВАЛ'}")

            # Використовуємо розміри з тимчасових файлів для звіту
            self._update_analysis(
                os.path.getsize(self.original_file_path) if self.original_file_path and os.path.exists(self.original_file_path) else 0, 
                os.path.getsize(extracted_file) if os.path.exists(extracted_file) else 0, 
                os.path.getsize(stego_file) if os.path.exists(stego_file) else 0, 
                0, 0, t_dec, integrity
            )
            messagebox.showinfo("Успіх", f"Файл успішно відновлено та збережено як:\n{decrypted_file}")

        except Exception as e:
            messagebox.showerror("Помилка відновлення", f"Помилка. Можливо, невірний ключ або пошкодження даних.\nДеталі: {e}")
            self.log(f"❌ ПОМИЛКА: {e}")

    def _update_analysis(self, orig_size, enc_size, steg_size, t_enc, t_steg, t_dec, integrity):
        """Оновлення аналітичного модуля."""
        report = "📊 АНАЛІТИЧНИЙ МОДУЛЬ:\n\n"
        
        report += f"**[Розміри файлів]**\n"
        report += f"  - Оригінал: {orig_size / 1024:.2f} КБ\n"
        report += f"  - Зашифрований (прихований): {enc_size / 1024:.2f} КБ\n"
        report += f"  - Стегоконтейнер: {steg_size / 1024:.2f} КБ\n\n"
        
        report += f"**[Час обробки]**\n"
        if t_enc > 0:
             report += f"  - Час Шифрування (Етап 1): {t_enc:.4f} с\n"
        if t_steg > 0:
             report += f"  - Час Стеганографії (Етап 2): {t_steg:.4f} с\n"
        if t_enc > 0 or t_steg > 0:
            report += f"  - Загальний час захисту: {t_enc + t_steg:.4f} с\n"
        if t_dec > 0:
             report += f"  - Час Розшифрування: {t_dec:.4f} с\n\n"
        
        if integrity is not None:
            report += f"**[Тестування цілісності]**\n"
            report += f"  - Цілісність відновленого файлу: {'✅ УСПІШНО' if integrity else '❌ ПРОВАЛ'}"
        
        self.analysis_label.config(text=report)

    # --- ФУНКЦІОНАЛ КРИПТОГРАФІЇ ТА СТЕГАНОГРАФІЇ ---

    def _encrypt_file(self, input_path, output_path):
        """Шифрує файл (Етап 1)."""
        start_time = time.time()
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), default_backend())
        encryptor = cipher.encryptor()
        
        with open(input_path, 'rb') as f_in:
            plaintext = f_in.read()
            # Додавання відступів (Padding)
            padding_len = 16 - (len(plaintext) % 16)
            plaintext += bytes([padding_len]) * padding_len
            ciphertext = encryptor.update(plaintext) + encryptor.finalize()

        with open(output_path, 'wb') as f_out:
            f_out.write(iv + ciphertext)
            
        return time.time() - start_time

    def _decrypt_file(self, input_path, output_path):
        """Розшифровує файл (Зворотний Етап 1)."""
        start_time = time.time()
        
        with open(input_path, 'rb') as f_in:
            data = f_in.read()
        
        iv = data[:16]
        ciphertext = data[16:]

        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), default_backend())
        decryptor = cipher.decryptor()
        
        decrypted_padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Видалення відступів (Unpadding)
        padding_len = decrypted_padded_data[-1]
        plaintext = decrypted_padded_data[:-padding_len]
        
        with open(output_path, 'wb') as f_out:
            f_out.write(plaintext)
        
        return time.time() - start_time

    def _to_bin(self, data):
        """Перетворює байти на рядок бінарних даних."""
        return ''.join([format(i, '08b') for i in data])

    def _hide_data(self, image_path, data_path, output_image_path):
        """Приховує бінарний файл у зображенні за допомогою LSB (Етап 2)."""
        start_time = time.time()
        with open(data_path, 'rb') as f:
            data_to_hide = f.read()

        # Додаємо маркер кінця
        data_to_hide_bin = self._to_bin(data_to_hide) + '1111111111111110'
        
        try:
            img = Image.open(image_path).convert("RGB")
        except:
            raise ValueError("Невірний формат зображення. Використовуйте PNG або BMP.")
            
        data_index = 0
        pixels = img.getdata()
        
        if len(data_to_hide_bin) > len(pixels) * 3:
             raise ValueError("Зображення занадто мале для приховування даних. Потрібно більше зображення.")

        new_pixels = []
        for pixel in pixels:
            new_pixel = list(pixel)
            for i in range(3):
                if data_index < len(data_to_hide_bin):
                    # Змінюємо найменш значущий біт (LSB)
                    new_pixel[i] = new_pixel[i] & ~1 | int(data_to_hide_bin[data_index])
                    data_index += 1
            new_pixels.append(tuple(new_pixel))

        img.putdata(new_pixels)
        img.save(output_image_path, "PNG") 
        
        return time.time() - start_time

    def _extract_data(self, image_path, output_data_path):
        """
        Витягує прихований файл із зображення LSB (Зворотний Етап 2).
        ВИПРАВЛЕННЯ: Додана перевірка кратності 8 бітам.
        """
        img = Image.open(image_path).convert("RGB")
        binary_data = ""
        
        for pixel in img.getdata():
            for value in pixel:
                binary_data += str(value & 1)

        delimiter = '1111111111111110'
        data_end_index = binary_data.find(delimiter)
        
        if data_end_index == -1:
            raise ValueError("Маркер кінця даних не знайдено. Дані пошкоджені або приховані не цим методом.")

        # Обрізаємо бінарний рядок до маркера кінця
        binary_data = binary_data[:data_end_index]
        
        # ВИПРАВЛЕННЯ: Обрізаємо бінарний рядок, щоб його довжина була кратна 8 (для повних байтів)
        if len(binary_data) % 8 != 0:
             binary_data = binary_data[:-(len(binary_data) % 8)]

        byte_data = bytearray()
        for i in range(0, len(binary_data), 8):
            byte_data.append(int(binary_data[i:i+8], 2))
        
        with open(output_data_path, 'wb') as f:
            f.write(byte_data)

    def _check_integrity(self, original_path, restored_path):
        """Перевіряє цілісність шляхом порівняння хешів."""
        if not os.path.exists(original_path) or not os.path.exists(restored_path):
            return False
            
        original_hash = self._get_file_hash(original_path)
        restored_hash = self._get_file_hash(restored_path)
        return original_hash == restored_hash

    def _get_file_hash(self, file_path):
        """Обчислює SHA256 хеш файлу."""
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        with open(file_path, 'rb') as f:
            while True:
                chunk = f.read(4096)
                if not chunk:
                    break
                digest.update(chunk)
        return digest.finalize()

if __name__ == "__main__":
    app = TwoStepProtectorApp()
    app.mainloop()