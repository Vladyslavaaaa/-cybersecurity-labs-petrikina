import string

# Український алфавіт
UKRAINIAN_ALPHABET = "АБВГҐДЕЄЖЗИІЇЙКЛМНОПРСТУФХЦЧШЩЬЮЯ"
UKR_ALPHABET_SIZE = len(UKRAINIAN_ALPHABET) # 33

# Англійський алфавіт
ENGLISH_ALPHABET = string.ascii_uppercase
ENGLISH_ALPHABET_SIZE = len(ENGLISH_ALPHABET) # 26

# --- Утиліти для роботи з алфавітами та текстом ---

def get_alphabet_and_size(char):
    """Повертає відповідний алфавіт і його розмір для даного символу."""
    if char in UKRAINIAN_ALPHABET:
        return UKRAINIAN_ALPHABET, UKR_ALPHABET_SIZE
    elif char in ENGLISH_ALPHABET:
        return ENGLISH_ALPHABET, ENGLISH_ALPHABET_SIZE
    return None, 0

def clean_text(text):
    """Приведення тексту до верхнього регістру, залишаючи УКР та АНГЛ літери."""
    text = text.upper()
    cleaned = ""
    for char in text:
        if char in UKRAINIAN_ALPHABET or char in ENGLISH_ALPHABET:
            cleaned += char
        else:
            cleaned += char
    return cleaned

# --- Реалізація Шифрів ---

def caesar_process(text, shift, encrypt=True):
    result = ""
    effective_shift = shift if encrypt else -shift
    for char in text:
        alphabet, size = get_alphabet_and_size(char)
        if alphabet:
            index = alphabet.find(char)
            new_index = (index + effective_shift) % size
            result += alphabet[new_index]
        else:
            result += char
    return result

def caesar_encrypt(plaintext, shift):
    return caesar_process(plaintext, shift, encrypt=True)

def caesar_decrypt(ciphertext, shift):
    return caesar_process(ciphertext, shift, encrypt=False)

def vigenere_process(text, key, encrypt=True):
    key = clean_text(key).replace(" ", "")
    key_len = len(key)
    if not key_len: return text
    
    result = ""
    key_index = 0
    
    for char in text:
        text_alphabet, text_size = get_alphabet_and_size(char)
        
        if text_alphabet:
            key_char = key[key_index % key_len]
            key_alphabet, key_size = get_alphabet_and_size(key_char)
            
            if not key_alphabet: 
                result += char
                continue
            
            shift = key_alphabet.find(key_char)
            index = text_alphabet.find(char)
            effective_shift = shift if encrypt else -shift
            
            new_index = (index + effective_shift) % text_size
            result += text_alphabet[new_index]
            
            key_index += 1
        else:
            result += char
    return result

def vigenere_encrypt(plaintext, key):
    return vigenere_process(plaintext, key, encrypt=True)

def vigenere_decrypt(ciphertext, key):
    return vigenere_process(ciphertext, key, encrypt=False)

# --- Функції Генерації Ключів ---

def generate_caesar_shift(date_str):
    digit_sum = 0
    for char in date_str:
        if char.isdigit():
            digit_sum += int(char)
    return digit_sum

def generate_vigenere_key(surname):
    key = clean_text(surname.split()[0])
    return key

# --- Основна Програма ---

def main():
    print("## Програма «Порівняльний Аналіз Шифрів»")
    print("=" * 70)
    
    # 1. Збір даних
    surname = input("Введіть ваше прізвище: ")
    date_of_birth = input("Введіть дату народження (у форматі ДД.ММ.РРРР): ")
    raw_text = input("Введіть текст для шифрування: ")

    # 2. Генерація ключів
    caesar_shift = generate_caesar_shift(date_of_birth)
    vigenere_key = generate_vigenere_key(surname)
    clean_message = clean_text(raw_text)
    
    print("\n" + "=" * 70)
    
    # 3. Шифр Цезаря
    print("### 1. Шифр Цезаря (Моноалфавітна підстановка)")
    print(f"Ключ (сума цифр {date_of_birth}): {caesar_shift}")
    print(f"(Розмір алфавіту УКР: {UKR_ALPHABET_SIZE}, АНГЛ: {ENGLISH_ALPHABET_SIZE})")
    
    caesar_ciphertext = caesar_encrypt(clean_message, caesar_shift)
    caesar_decrypted = caesar_decrypt(caesar_ciphertext, caesar_shift)
    
    print(f"\n   Зашифровано: **{caesar_ciphertext}**")
    print(f"   Розшифровано: **{caesar_decrypted}**")
    
    print("-" * 70)

    # 4. Шифр Віженера
    print("### 2. Шифр Віженера (Поліалфавітна підстановка)")
    print(f"Ключ (з прізвища {surname.split()[0]}): \"{vigenere_key}\"")

    vigenere_ciphertext = vigenere_encrypt(clean_message, vigenere_key)
    vigenere_decrypted = vigenere_decrypt(vigenere_ciphertext, vigenere_key)
    
    print(f"\n   Зашифровано: **{vigenere_ciphertext}**")
    print(f"   Розшифровано: **{vigenere_decrypted}**")
    
    print("\n" + "=" * 70)

    # 5. Порівняння (Новий формат: списки)
    
    print("### 3. Порівняльний Аналіз Алгоритмів")
    print("-" * 70)
    
    print("#### Шифр Цезаря:")
    print(f" - **Тип шифру:** Моноалфавітний (одна заміна для всього тексту).")
    print(f" - **Формат ключа:** Числовий зсув.")
    print(f" - **Значення ключа:** {caesar_shift} (Зсув).")
    print(f" - **Складність ключа:** Низька (лише {UKR_ALPHABET_SIZE} або {ENGLISH_ALPHABET_SIZE} варіантів).")
    print(f" - **Стійкість (Аналіз):** Дуже низька, вразливий до Brute Force та частотного аналізу.")

    print("\n#### Шифр Віженера:")
    print(f" - **Тип шифру:** Поліалфавітний (використовує багато зсувів).")
    print(f" - **Формат ключа:** Ключове слово.")
    print(f" - **Значення ключа:** \"{vigenere_key}\".")
    print(f" - **Складність ключа:** Середня (залежить від довжини та випадковості ключа).")
    print(f" - **Стійкість (Аналіз):** Середня, вразливий до методу Касіскі (для визначення довжини ключа).")
    
    print("\n" + "=" * 70)
    
    # 6. Висновки
    print("### 4. Висновки про Стійкість")
    print("-" * 70)
    print("1. **Шифр Цезаря** не забезпечує криптографічної стійкості. Його моноалфавітна заміна зберігає частотні характеристики мови, що робить його вразливим до простого перебору ключів (Brute Force) або частотного аналізу.")
    print("2. **Шифр Віженера** значно стійкіший, оскільки поліалфавітна заміна 'розмиває' частоту літер. Проте, при короткому ключі, він все ще може бути зламаний за допомогою **методу Касіскі** для визначення довжини ключа.")


if __name__ == "__main__":
    main()