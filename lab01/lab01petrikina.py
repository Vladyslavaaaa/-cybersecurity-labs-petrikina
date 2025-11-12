import re

# Словник поширених слів для перевірки на словниковість
COMMON_WORDS = ["password", "qwerty", "admin", "123456", "test", "user", "login"]

def get_user_data():
    """Збирає ім'я, дату народження та пароль від користувача, з можливістю виходу."""
    
    print("\n" + "="*50)
    
    name_input = input("Введіть ім'я:")
    if name_input.lower() == 'exit':
        return None
    
    date_of_birth = input("Дата народження (формат ДД.ММ.РРРР): ")
    password = input("Введіть пароль для аналізу: ")

    # Обробка даних
    name = name_input.strip()
    year = date_of_birth.split('.')[-1] if date_of_birth.count('.') == 2 else ""
    month_day = "".join(date_of_birth.split('.')[:2]) if date_of_birth.count('.') == 2 else ""
    
    return {
        "password": password,
        "name": name,
        "date_of_birth": date_of_birth,
        "year": year,
        "month_day": month_day,
    }

def analyze_password_security(password: str, personal_data: dict):
    """
    Аналізує безпеку пароля. Повертає оцінку, рекомендації та
    список *конкретних виявлених проблем* (для секції "Виявлені проблеми").
    """
    score = 0
    recommendations = []
    detected_problems = [] # <-- Новий список для виявлених проблем
    
    analysis_results = {
        "date_part_found": False,
        "name_found": False
    }
    
    password_lower = password.lower()

    # --- 1. Оцінка складності (Бали) ---
    
    # Довжина пароля
    if len(password) >= 12:
        score += 3
    elif len(password) >= 8:
        score += 2
    else:
        recommendations.append("Збільште довжину пароля.")
        detected_problems.append("Пароль занадто короткий (менше 8 символів).")

    # Різноманітність символів
    has_upper = bool(re.search(r'[A-Z]', password))
    has_lower = bool(re.search(r'[a-z]', password))
    has_digit = bool(re.search(r'\d', password))
    has_special = bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))

    char_types_count = sum([has_upper, has_lower, has_digit, has_special])
    
    if char_types_count >= 4:
        score += 4
    elif char_types_count == 3:
        score += 3
    
    if not has_upper:
        recommendations.append("Додайте великі літери.")
    if not has_special:
        recommendations.append("Додайте спеціальні символи.")
    
    if char_types_count < 3:
        detected_problems.append(f"Недостатня різноманітність символів ({char_types_count} типів).")
    
    # Словникові слова (Зниження балу)
    for word in COMMON_WORDS:
        if word in password_lower:
            score = max(0, score - 2)
            detected_problems.append(f"Містить словникове слово чи його частину ('{word}').")
            break

    # --- 2. Аналіз зв'язку з особистими даними ---
    
    name_lower = personal_data['name'].lower()
    year = personal_data['year']
    month_day = personal_data['month_day']

    # 1. Перевірка на ім'я
    if len(name_lower) > 2 and name_lower in password_lower:
        score = max(0, score - 3)
        analysis_results["name_found"] = True
        recommendations.append("Не використовуйте ім'я у паролі.")
        detected_problems.append(f"Містить ім'я користувача ('{name_lower}').")


    # 2. Перевірка на частини дати народження
    if (len(year) > 2 and year in password_lower) or \
       (len(month_day) > 2 and month_day in password_lower):
        score = max(0, score - 3)
        analysis_results["date_part_found"] = True
        recommendations.append("Не використовуйте частини дати народження у паролі.")
        detected_problems.append("Містить рік або дату народження.")


    # ----------------------------------------------------
    # Фінальна оцінка (Масштабування до 10 балів)
    # ----------------------------------------------------
    
    final_score = round(min(score, 7) / 7 * 10)
    
    return final_score, recommendations, analysis_results, detected_problems

# --- Основний блок виконання програми ---

if __name__ == "__main__":
    
    while True:
        data = get_user_data()
        
        if data is None:
            print("\nПрограма завершена.")
            break
            
        password_to_analyze = data['password']
        
        if not password_to_analyze:
            continue
        
        # Виклик функції аналізу
        final_score, recommendations_raw, analysis_results, detected_problems = analyze_password_security(
            password_to_analyze, 
            data
        )
        
        # ------------------------------------------------
        # Виведення результатів
        # ------------------------------------------------
        
        print("\nАналіз:")
        print(f"- Частини дати народження у паролі: {'так' if analysis_results['date_part_found'] else 'ні'}")
        print(f"- Ім'я у паролі: {'так' if analysis_results['name_found'] else 'ні'}")
        
        # --- Секція Виявлені проблеми ---
        print("\nВиявлені проблеми:")
        if detected_problems:
            # Видаляємо дублікати та виводимо
            unique_problems = sorted(list(set(detected_problems)))
            for problem in unique_problems:
                print(f"- {problem}")
        else:
            print("- Проблем зі структурою та словниковістю не виявлено.")
        
        # --- Оцінка ---
        print(f"\nОцінка пароля: {final_score}/10")
        
        # --- Рекомендації ---
        print("\nРекомендації:")
        
        # Створюємо фінальний набір рекомендацій
        final_recommendations = set()
        
        # 1. Загальна рекомендація щодо особистих даних
        if analysis_results['date_part_found'] or analysis_results['name_found']:
             final_recommendations.add("Не використовуйте особисті дані (ім'я, дата народження) у паролі.")
        
        # 2. Рекомендації щодо складності
        for rec in recommendations_raw:
            if "Додайте" in rec or "Збільште" in rec:
                 final_recommendations.add(rec.replace("Довжина: ", ""))
                 
        if final_recommendations:
            for rec in sorted(list(final_recommendations)):
                print(f"- {rec}")
        else:
            print("- Пароль відповідає високим стандартам безпеки.")
        
        print("\n" + "="*50)
