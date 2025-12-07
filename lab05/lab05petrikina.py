import hashlib
import base64
import tkinter as tk
from tkinter import scrolledtext, messagebox
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# --- Дефолтні дані для демонстрації (на основі ваших даних) ---
DEFAULT_NAME = "Петрікіна Владислава Сергіївна"
DEFAULT_DOB = "22072005"
DEFAULT_SECRET = "Lab5Secure" 

# --- Утилітарні та Криптографічні Функції ---

def derive_fernet_key(password: str, salt: bytes) -> bytes:
    """
    Генерує 32-байтовий ключ Fernet (Base64-encoded) з пароля (персональних даних).
    Використовує PBKDF2HMAC для безпечного перетворення пароля на ключ.
    """
    # 1. Створення функції отримання ключа (Key Derivation Function - KDF)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32, # Fernet вимагає 32 байти
        salt=salt,
        iterations=480000, # Рекомендована кількість ітерацій
    )
    # 2. Отримання 32-байтного ключа
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

def encrypt_message(key: bytes, message: str) -> str:
    """Шифрує повідомлення за допомогою симетричного ключа Fernet."""
    f = Fernet(key)
    # Шифрування повідомлення (перетворюємо рядок на байти)
    encrypted_bytes = f.encrypt(message.encode())
    # Повертаємо зашифровані дані як рядок (Base64)
    return encrypted_bytes.decode()

def decrypt_message(key: bytes, encrypted_data: str) -> str:
    """Розшифровує повідомлення за допомогою симетричного ключа Fernet."""
    f = Fernet(key)
    try:
        # Розшифрування (перетворюємо рядок Base64 на байти)
        decrypted_bytes = f.decrypt(encrypted_data.encode())
        return decrypted_bytes.decode()
    except Exception as e:
        # Обробка помилок (наприклад, невірний ключ або пошкоджені дані)
        return f"Помилка розшифрування: Невірний ключ або дані. ({e})"


# --- GUI Функціональність ---

class SymmetricEncryptorApp:
    def __init__(self, master):
        self.master = master
        master.title("Симетричний Шифратор Повідомлень (Fernet/AES-128)")

        # Зберігання ключів та солі
        self.key = None
        # Соль (salt) для PBKDF2HMAC має бути випадковою, але для демонстрації 
        # її фіксуємо, щоб ключ був однаковий. У реальному житті її треба передавати!
        self.salt = b'vl_secret_lab5' 

        # --- 1. Генерація Ключа ---
        self.key_frame = tk.LabelFrame(master, text="1. Генерація Симетричного Ключа (Секрет)")
        self.key_frame.pack(padx=10, pady=5, fill="x")

        self._add_input_field(self.key_frame, "Повне Ім'я:", DEFAULT_NAME, 'name_entry')
        self._add_input_field(self.key_frame, "Дата народження:", DEFAULT_DOB, 'dob_entry')
        self._add_input_field(self.key_frame, "Секретне слово:", DEFAULT_SECRET, 'secret_entry')

        tk.Button(self.key_frame, text="Згенерувати Спільний Ключ", command=self.generate_key_gui, bg='lightblue').pack(pady=5)

        self.key_label = tk.Label(self.key_frame, text="Спільний Ключ (K): очікування...", wraplength=450, justify=tk.LEFT)
        self.key_label.pack(anchor="w")

        # --- 2. Шифрування ---
        self.encrypt_frame = tk.LabelFrame(master, text="2. Шифрування Повідомлення (Відправник)")
        self.encrypt_frame.pack(padx=10, pady=5, fill="x")

        tk.Label(self.encrypt_frame, text="Текст повідомлення:").pack(anchor="w")
        self.message_text = scrolledtext.ScrolledText(self.encrypt_frame, height=3, width=60)
        self.message_text.insert(tk.INSERT, "Зустрічаємося завтра о 15:00. Це секрет!")
        self.message_text.pack(pady=5)

        tk.Button(self.encrypt_frame, text="Шифрувати", command=self.encrypt_gui, bg='lightgreen').pack(pady=5)
        self.encrypted_output = scrolledtext.ScrolledText(self.encrypt_frame, height=3, width=60, state='disabled')
        self.encrypted_output.pack(pady=5)

        # --- 3. Розшифрування ---
        self.decrypt_frame = tk.LabelFrame(master, text="3. Розшифрування Повідомлення (Отримувач)")
        self.decrypt_frame.pack(padx=10, pady=5, fill="x")
        
        tk.Label(self.decrypt_frame, text="Зашифрований текст (Вставити сюди):").pack(anchor="w")
        self.encrypted_input = scrolledtext.ScrolledText(self.decrypt_frame, height=3, width=60)
        self.encrypted_input.pack(pady=5)

        tk.Button(self.decrypt_frame, text="Розшифрувати", command=self.decrypt_gui, bg='salmon').pack(pady=5)
        self.decrypted_output = tk.Label(self.decrypt_frame, text="Розшифрований Результат: Очікування...", font=('Arial', 10, 'bold'))
        self.decrypted_output.pack(pady=5)

    def _add_input_field(self, parent_frame, label_text, default_value, attribute_name):
        """Допоміжна функція для створення поля вводу з міткою."""
        row_frame = tk.Frame(parent_frame)
        row_frame.pack(fill="x", padx=5, pady=2)
        
        tk.Label(row_frame, text=label_text, width=15, anchor="w").pack(side=tk.LEFT)
        entry = tk.Entry(row_frame, width=50)
        entry.insert(tk.END, default_value)
        entry.pack(side=tk.LEFT, fill="x", expand=True)
        setattr(self, attribute_name, entry)

    # --- Методи обробки подій GUI ---
    
    def generate_key_gui(self):
        """Генерує ключ на основі введених користувачем даних."""
        
        full_name = self.name_entry.get().strip()
        dob = self.dob_entry.get().strip()
        secret = self.secret_entry.get().strip()
        
        if not full_name or not dob or not secret:
            messagebox.showerror("Помилка Вводу", "Будь ласка, заповніть усі поля для генерації ключа.")
            return

        # Створення "пароля" для ключа
        password = full_name + dob + secret
        
        self.key = derive_fernet_key(password, self.salt)
        
        # Відображення ключа
        key_display = self.key.decode()
        self.key_label.config(text=f"Спільний Ключ (K): {key_display[:10]}... (повний: {key_display})")
        messagebox.showinfo("Крок 1 Готово", "Ключ успішно згенеровано. Цей ключ необхідно безпечно передати отримувачу.")

    def encrypt_gui(self):
        """Шифрує повідомлення."""
        if self.key is None:
            messagebox.showerror("Помилка", "Спочатку згенеруйте ключ (Крок 1).")
            return

        message_content = self.message_text.get("1.0", tk.END).strip()
        if not message_content:
            messagebox.showerror("Помилка", "Вміст повідомлення не може бути порожнім.")
            return

        # Викликаємо функцію шифрування
        encrypted_data = encrypt_message(self.key, message_content)
        
        # Відображення результату
        self.encrypted_output.config(state='normal')
        self.encrypted_output.delete("1.0", tk.END)
        self.encrypted_output.insert(tk.INSERT, encrypted_data)
        self.encrypted_output.config(state='disabled')
        
        # Автоматично вставляємо для тестування розшифрування
        self.encrypted_input.delete("1.0", tk.END)
        self.encrypted_input.insert(tk.INSERT, encrypted_data)

    def decrypt_gui(self):
        """Розшифровує повідомлення."""
        if self.key is None:
            messagebox.showerror("Помилка", "Спочатку згенеруйте ключ (Крок 1).")
            return

        encrypted_data = self.encrypted_input.get("1.0", tk.END).strip()

        if not encrypted_data:
             messagebox.showerror("Помилка", "Зашифрований текст не може бути порожнім.")
             return

        # Викликаємо функцію розшифрування
        decrypted_text = decrypt_message(self.key, encrypted_data)

        # Виведення результату
        if decrypted_text.startswith("Помилка розшифрування"):
            self.decrypted_output.config(text=f"❌ {decrypted_text}", fg='red')
            messagebox.showerror("Помилка", "Розшифрування не вдалося. Перевірте ключ або зашифровані дані.")
        else:
            self.decrypted_output.config(text=f"✅ Розшифрований Текст: {decrypted_text}", fg='darkgreen')
            messagebox.showinfo("Готово", f"Повідомлення успішно розшифровано.")


# --- Запуск програми ---
if __name__ == '__main__':
    root = tk.Tk()
    app = SymmetricEncryptorApp(root)
    root.mainloop()