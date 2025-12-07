import hashlib
import tkinter as tk
from tkinter import scrolledtext, messagebox

# --- Утилітарні та Криптографічні Функції (залишаються без змін) ---

def sha256_hash(data):
    """Обчислює SHA-256 хеш від вхідних даних."""
    return hashlib.sha256(data.encode('utf-8')).hexdigest()

def hex_to_int(h):
    """Перетворює 64-символьний HEX-хеш на ціле число."""
    return int(h, 16)

def int_to_hex(i):
    """Перетворює ціле число на 64-символьний HEX-рядок."""
    return format(i, '064x')

def generate_keys(seed_value):
    """Генерує Приватний та Публічний ключі (за спрощеною схемою)."""
    # 1. Приватний ключ (PR)
    private_key_hex = sha256_hash(seed_value)
    pr_int = hex_to_int(private_key_hex)
    
    # 2. Публічний ключ (PU) - Спрощена залежність
    MODULUS = 1000007 
    public_key_int = (pr_int * 7) % MODULUS 
    public_key_demo_hex = sha256_hash(str(public_key_int)) 
    
    return private_key_hex, public_key_demo_hex

def create_signature(document_content, private_key_hex):
    """Створює цифровий підпис (H XOR PR)."""
    document_hash = sha256_hash(document_content)
    
    h_int = hex_to_int(document_hash)
    pr_int = hex_to_int(private_key_hex)
    
    signature_int = h_int ^ pr_int
    signature_hex = int_to_hex(signature_int)
    
    return document_hash, signature_hex

def verify_signature(document_content, signature_hex, private_key_hex):
    """Перевіряє підпис (S XOR PR == H_new)."""
    new_document_hash = sha256_hash(document_content)
    
    try:
        signature_int = hex_to_int(signature_hex)
        pr_int = hex_to_int(private_key_hex)
        decrypted_hash_int = signature_int ^ pr_int 
        decrypted_hash_hex = int_to_hex(decrypted_hash_int)
    except ValueError:
        return False, new_document_hash, "Невалідний формат підпису"
    
    is_valid = decrypted_hash_hex == new_document_hash
    
    return is_valid, new_document_hash, decrypted_hash_hex


# --- GUI Функціональність ---

class DigitalSignatureApp:
    def __init__(self, master):
        self.master = master
        master.title("Спрощена Система Цифрових Підписів (Інтерактивна)")

        # Зберігання ключів та підпису
        self.private_key = ""
        self.public_key = ""
        self.current_signature = ""
        self.current_doc_hash = ""

        # --- 1. Генерація Ключів (Інтерактивний ввід) ---
        self.key_frame = tk.LabelFrame(master, text="1. Генерація Ключів (Введіть дані)")
        self.key_frame.pack(padx=10, pady=5, fill="x")

        # Поля для введення даних
        self._add_input_field(self.key_frame, "Повне Ім'я:", "Петрікіна Владислава Сергіївна", 'name_entry')
        self._add_input_field(self.key_frame, "Дата народження:", "22072005", 'dob_entry')
        self._add_input_field(self.key_frame, "Секретне слово:", "Lab4", 'secret_entry')

        tk.Button(self.key_frame, text="Згенерувати Ключі", command=self.generate_keys_gui, bg='lightblue').pack(pady=5)

        self.pr_label = tk.Label(self.key_frame, text="Приватний Ключ (PR): очікування...", wraplength=450, justify=tk.LEFT)
        self.pr_label.pack(anchor="w")
        self.pu_label = tk.Label(self.key_frame, text="Публічний Ключ (PU): очікування...", wraplength=450, justify=tk.LEFT)
        self.pu_label.pack(anchor="w")

        # --- Крок 2 & 3: Документ, Підписання та Перевірка (як було) ---
        self._setup_sign_verify_sections()

    def _add_input_field(self, parent_frame, label_text, default_value, attribute_name):
        """Допоміжна функція для створення поля вводу з міткою."""
        row_frame = tk.Frame(parent_frame)
        row_frame.pack(fill="x", padx=5, pady=2)
        
        tk.Label(row_frame, text=label_text, width=15, anchor="w").pack(side=tk.LEFT)
        entry = tk.Entry(row_frame, width=50)
        entry.insert(tk.END, default_value)
        entry.pack(side=tk.LEFT, fill="x", expand=True)
        setattr(self, attribute_name, entry)

    def _setup_sign_verify_sections(self):
        """Створення секцій для підписання та перевірки."""
        # --- Секція Підписання ---
        self.sign_frame = tk.LabelFrame(self.master, text="2. Документ та Створення Підпису")
        self.sign_frame.pack(padx=10, pady=5, fill="x")

        tk.Label(self.sign_frame, text="Вміст Документа:").pack(anchor="w")
        self.doc_text = scrolledtext.ScrolledText(self.sign_frame, height=5, width=60)
        self.doc_text.insert(tk.INSERT, "Резюме Петрікіної В.С. від 2025 року. Це оригінальний документ.")
        self.doc_text.pack(pady=5)

        tk.Button(self.sign_frame, text="Створити Цифровий Підпис", command=self.sign_document_gui, bg='lightgreen').pack(pady=5)
        self.hash_label = tk.Label(self.sign_frame, text="Хеш Документа (H):", wraplength=450, justify=tk.LEFT)
        self.hash_label.pack(anchor="w")
        self.signature_label = tk.Label(self.sign_frame, text="Цифровий Підпис (S):", wraplength=450, justify=tk.LEFT)
        self.signature_label.pack(anchor="w")


        # --- Секція Перевірки ---
        self.verify_frame = tk.LabelFrame(self.master, text="3. Перевірка Підпису та Демонстрація Підробки")
        self.verify_frame.pack(padx=10, pady=5, fill="x")
        
        tk.Label(self.verify_frame, text="Підпис для перевірки (S):").pack(anchor="w")
        self.signature_entry = tk.Entry(self.verify_frame, width=70)
        self.signature_entry.pack(pady=5)

        tk.Button(self.verify_frame, text="Перевірити Підпис", command=self.verify_signature_gui, bg='salmon').pack(pady=5)
        self.result_label = tk.Label(self.verify_frame, text="Результат Перевірки: Очікування...", font=('Arial', 10, 'bold'))
        self.result_label.pack(pady=5)


    # --- Методи обробки подій GUI ---
    
    def generate_keys_gui(self):
        """Обробник для кнопки генерації ключів, що читає дані з полів."""
        
        # Отримання даних з полів введення
        full_name = self.name_entry.get().strip()
        dob = self.dob_entry.get().strip()
        secret = self.secret_entry.get().strip()
        
        if not full_name or not dob or not secret:
            messagebox.showerror("Помилка Вводу", "Будь ласка, заповніть усі поля для генерації ключів.")
            return

        # Створення SEED_VALUE
        seed_value = full_name + dob + secret
        
        self.private_key, self.public_key = generate_keys(seed_value)
        
        self.pr_label.config(text=f"Приватний Ключ (PR): {self.private_key[:8]}... (повний: {self.private_key})")
        self.pu_label.config(text=f"Публічний Ключ (PU): {self.public_key[:8]}... (повний: {self.public_key})")
        messagebox.showinfo("Крок 1 Готово", "Ключі успішно згенеровано на основі введених даних.")

    def sign_document_gui(self):
        """Обробник для кнопки підписання документа."""
        if not self.private_key:
            messagebox.showerror("Помилка", "Спочатку згенеруйте ключі (Крок 1).")
            return

        doc_content = self.doc_text.get("1.0", tk.END).strip()
        if not doc_content:
            messagebox.showerror("Помилка", "Вміст документа не може бути порожнім.")
            return

        self.current_doc_hash, self.current_signature = create_signature(doc_content, self.private_key)
        
        self.hash_label.config(text=f"Хеш Документа (H): {self.current_doc_hash}")
        self.signature_label.config(text=f"Цифровий Підпис (S): {self.current_signature}")
        
        # Автоматично вставляємо підпис для перевірки
        self.signature_entry.delete(0, tk.END)
        self.signature_entry.insert(0, self.current_signature)
        messagebox.showinfo("Крок 2 Готово", "Документ успішно підписано.")

    def verify_signature_gui(self):
        """Обробник для кнопки перевірки підпису."""
        if not self.private_key:
            messagebox.showerror("Помилка", "Спочатку згенеруйте ключі (Крок 1).")
            return
            
        doc_content = self.doc_text.get("1.0", tk.END).strip()
        signature_to_verify = self.signature_entry.get().strip()

        if not doc_content or not signature_to_verify:
             messagebox.showerror("Помилка", "Вміст документа та підпис не можуть бути порожніми.")
             return

        # Перевірка
        is_valid, new_hash, expected_hash = verify_signature(doc_content, signature_to_verify, self.private_key)

        # Виведення результату
        if is_valid:
            self.result_label.config(text="✅ Підпис ДІЙСНИЙ. Цілісність та Автентичність ПІДТВЕРДЖЕНО.", fg='green')
            messagebox.showinfo("Результат", "Перевірка пройдена успішно! Документ оригінальний.")
        else:
            self.result_label.config(text="❌ Підпис ПІДРОБЛЕНИЙ/Недійсний! Зміни виявлено.", fg='red')
            messagebox.showwarning("Результат", f"Перевірка не пройдена! Хеші не збігаються.\nОчікувався (з підпису): {expected_hash[:10]}...\nОтримано (з документа): {new_hash[:10]}...")


# --- Запуск програми ---
if __name__ == '__main__':
    root = tk.Tk()
    app = DigitalSignatureApp(root)
    root.mainloop()