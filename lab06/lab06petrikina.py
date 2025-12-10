import sqlite3
import tkinter as tk
from tkinter import ttk, messagebox

# --- 1. Налаштування та Ініціалізація БД ---
DB_NAME = 'student_search_db.db'

def setup_database():
    """Створює таблицю студентів та додає тестові записи."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS students (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            student_group TEXT NOT NULL,
            secret_id TEXT 
        )
    """)
    conn.commit()

    try:
        # Дані згідно з персоналізацією (Петрікіна В.С.)
        cursor.execute("INSERT INTO students (name, student_group, secret_id) VALUES (?, ?, ?)", 
                       ('Петрікіна Владислава Сергіївна', '6.04.121.010.22.2', 'ID: 14108723')) # [cite: 20, 22]
        cursor.execute("INSERT INTO students (name, student_group, secret_id) VALUES (?, ?, ?)", 
                       ('Іван Петренко', 'Група А', 'ID: 99876543'))
        cursor.execute("INSERT INTO students (name, student_group, secret_id) VALUES (?, ?, ?)", 
                       ('Олег Шевченко', 'Група Б', 'ID: 10000001'))
        cursor.execute("INSERT INTO students (name, student_group, secret_id) VALUES (?, ?, ?)", 
                       ('Софія Коваленко', 'Група Б', 'ID: 80000008'))
        conn.commit()
    except sqlite3.IntegrityError:
        pass 
    finally:
        conn.close()

# --- 2. Функціонал Пошуку ---

def execute_search(search_term, is_vulnerable=True):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    results = []
    sql_executed = ""
    status_text = ""
    
    try:
        if is_vulnerable:
            # ВРАЗЛИВИЙ ЗАПИТ: Пряма конкатенація (склеювання) [cite: 92, 98]
            # Демонструємо витік secret_id
            sql_executed = f"SELECT name, student_group, secret_id FROM students WHERE name LIKE '%{search_term}%'"
            cursor.execute(sql_executed)
        else:
            # ЗАХИЩЕНИЙ ЗАПИТ: Параметризований запит (Prepared Statement) [cite: 104, 109]
            sql_executed = "SELECT name, student_group, secret_id FROM students WHERE name LIKE ?"
            like_term = f"%{search_term}%"
            cursor.execute(sql_executed, (like_term,))
            sql_executed += f"\n\n[БЕЗПЕКА]: Дані передані окремо від команди.\nЗначення параметра: '{like_term}'"

        fetched_rows = cursor.fetchall()
        
        if fetched_rows:
            status_text = "✅ Пошук завершено"
            # Перевірка на успішну атаку (якщо повернуто більше ніж 1 запис при спробі зламу)
            if is_vulnerable and ("'" in search_term or "--" in search_term):
                status_text = "⚠️ АТАКА УСПІШНА: ВИТІК ВСІХ ДАНИХ!"
            
            for row in fetched_rows:
                results.append(f"{row[0]} | {row[1]} | {row[2]}") # Вивід ПІБ, Групи та Секретного ID
        else:
            status_text = "❌ Нічого не знайдено"

    except sqlite3.Error as e:
        status_text = "❌ СИНТАКСИЧНА ПОМИЛКА SQL"
        results = [f"Помилка: {e}"]
        
    finally:
        conn.close()
        return status_text, results, sql_executed

# --- 3. Графічний Інтерфейс ---

class SQLSearchApp:
    def __init__(self, master):
        self.master = master
        master.title("Демонстрація SQL-ін'єкцій (Петрікіна В.С.)")
        master.geometry("900x750")

        ttk.Label(master, text="Технічне завдання: Демонстрація вразливості та захисту", font=('Arial', 11, 'bold')).pack(pady=10)
        
        # Блок вводу
        input_frame = ttk.LabelFrame(master, text="Ввід даних", padding="10")
        input_frame.pack(padx=20, pady=5, fill="x")

        ttk.Label(input_frame, text="Введіть ім'я для пошуку:").pack(side="left", padx=5)
        self.search_entry = ttk.Entry(input_frame, width=40)
        self.search_entry.pack(side="left", padx=5)
        self.search_entry.insert(0, "' OR '1'='1' --") 

        # Основна область результатів
        res_container = ttk.Frame(master, padding="10")
        res_container.pack(fill="both", expand=True)

        # Вразлива версія
        self.create_column(res_container, 0, "ВРАЗЛИВА ВЕРСІЯ (Конкатенація)", True)
        # Захищена версія
        self.create_column(res_container, 1, "ЗАХИЩЕНА ВЕРСІЯ (Prepared Statements)", False)

        res_container.columnconfigure(0, weight=1)
        res_container.columnconfigure(1, weight=1)

    def create_column(self, parent, col, title, is_v):
        frame = ttk.LabelFrame(parent, text=title, padding="10")
        frame.grid(row=0, column=col, sticky="nsew", padx=5)

        btn_text = "❌ Тест на вразливість" if is_v else "✅ Безпечний пошук"
        ttk.Button(frame, text=btn_text, command=lambda: self.run_search(is_v)).pack(fill="x", pady=5)

        status_lbl = ttk.Label(frame, text="Очікування...", font=('Arial', 9, 'bold'))
        status_lbl.pack(anchor="w")

        ttk.Label(frame, text="SQL запит, що виконується:").pack(anchor="w", pady=(10,0))
        q_text = tk.Text(frame, height=6, width=40, font=('Consolas', 9), bg="#f8f9fa")
        q_text.pack(fill="x", pady=5)

        ttk.Label(frame, text="Результати (включаючи секретні ID):").pack(anchor="w")
        r_list = tk.Listbox(frame, height=10, font=('Arial', 9))
        r_list.pack(fill="both", expand=True, pady=5)

        if is_v:
            self.v_ui = (status_lbl, q_text, r_list)
        else:
            self.s_ui = (status_lbl, q_text, r_list)

    def run_search(self, is_v):
        ui = self.v_ui if is_v else self.s_ui
        status, results, query = execute_search(self.search_entry.get(), is_v)
        
        ui[0].config(text=status, foreground="red" if "⚠️" in status or "❌" in status else "green")
        ui[1].delete('1.0', tk.END)
        ui[1].insert(tk.END, query)
        ui[2].delete(0, tk.END)
        for res in results:
            ui[2].insert(tk.END, res)

if __name__ == "__main__":
    setup_database()
    root = tk.Tk()
    app = SQLSearchApp(root)
    root.mainloop()