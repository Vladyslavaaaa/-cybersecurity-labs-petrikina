from PIL import Image
import struct
import os

# --- КОНСТАНТИ ---
LENGTH_PREFIX_BYTES = 4 

# --- ФУНКЦІЇ LSB ЛОГІКИ (Без змін) ---

def text_to_bits(text):
    """Конвертує текст у бітову послідовність."""
    return ''.join(format(ord(char), '08b') for char in text)

def encode_message_length(length):
    """Конвертує довжину повідомлення (int) у 32-бітове двійкове представлення."""
    try:
        length_bytes = struct.pack('>I', length)
        return text_to_bits(length_bytes.decode('latin-1'))
    except struct.error as e:
        print(f"Помилка пакування довжини: {e}")
        raise

def get_image_size(image):
    """Повертає загальну кількість бітів, які можна приховати."""
    return image.width * image.height * 3

# (Функції encode та decode залишаються без змін)
def encode(image_path, message, output_path):
    """Приховує повідомлення в зображенні."""
    try:
        img = Image.open(image_path).convert("RGB")
    except FileNotFoundError:
        print(f"❌ Помилка: Файл контейнера '{image_path}' не знайдено.")
        return
    except Exception as e:
        print(f"❌ Помилка відкриття зображення: {e}")
        return

    message_bits = text_to_bits(message)
    length_prefix = encode_message_length(len(message_bits))
    data_to_hide = length_prefix + message_bits
    data_len_bits = len(data_to_hide)

    max_bits = get_image_size(img)
    if data_len_bits > max_bits:
        print(f"❌ Повідомлення занадто велике. Потрібно {data_len_bits} біт, доступно {max_bits} біт.")
        return

    pixel_map = img.load()
    data_index = 0

    for r in range(img.height):
        for c in range(img.width):
            if data_index >= data_len_bits:
                img.save(output_path)
                print(f"✅ Повідомлення успішно закодовано та збережено як '{output_path}'")
                return

            r_val, g_val, b_val = pixel_map[c, r]

            for i, channel_val in enumerate([r_val, g_val, b_val]):
                if data_index < data_len_bits:
                    bit_to_hide = int(data_to_hide[data_index])
                    new_val = (channel_val & ~1) | bit_to_hide

                    if i == 0: r_val = new_val
                    elif i == 1: g_val = new_val
                    else: b_val = new_val

                    data_index += 1

            pixel_map[c, r] = (r_val, g_val, b_val)

    img.save(output_path)
    print(f"Повідомлення успішно закодовано та збережено як '{output_path}'")


def decode(image_path):
    """Витягує повідомлення із зображення-стегоконтейнера."""
    try:
        img = Image.open(image_path).convert("RGB")
    except FileNotFoundError:
        return f"Помилка: Файл стегоконтейнера '{image_path}' не знайдено."
    except Exception as e:
        return f"Помилка відкриття зображення: {e}"

    pixel_map = img.load()

    hidden_bits = ""
    total_bits = 0
    message_length_bits = LENGTH_PREFIX_BYTES * 8
    message_bits_count = 0

    for r in range(img.height):
        for c in range(img.width):
            r_val, g_val, b_val = pixel_map[c, r]

            for channel_val in [r_val, g_val, b_val]:
                hidden_bits += str(channel_val & 1)
                total_bits += 1

                if total_bits == message_length_bits:
                    try:
                        length_bytes = int(hidden_bits, 2).to_bytes(LENGTH_PREFIX_BYTES, byteorder='big')
                        message_bits_count = struct.unpack('>I', length_bytes)[0]
                    except ValueError:
                        return "Помилка: Некоректний префікс довжини. Можливо, це не LSB-стегоконтейнер."

                if message_bits_count > 0 and total_bits == (message_length_bits + message_bits_count):
                    message_bits_only = hidden_bits[message_length_bits:]
                    chars = [chr(int(message_bits_only[i:i+8], 2)) for i in range(0, len(message_bits_only), 8)]
                    return "\n✅ Повідомлення успішно витягнуто:\n" + "".join(chars)

    return "Повідомлення не знайдено. Дані для декодування виявилися неповними."

# --- ІНТЕРАКТИВНЕ МЕНЮ (Без змін) ---

def main_menu():
    """Головне меню програми."""
    while True:
        print("\n" + "="*40)
        print(" LSB-Стеганографія (Власна реалізація)")
        print("="*40)
        print("1. 🔐 Приховати повідомлення (Кодування)")
        print("2. 🔓 Витягти повідомлення (Декодування)")
        print("3. ✖️ Вийти")

        choice = input("Ваш вибір (1-3): ")

        if choice == '1':
            handle_encode()
        elif choice == '2':
            handle_decode_menu()
        elif choice == '3':
            print("Дякую за використання. До побачення!")
            break
        else:
            print("Некоректний вибір. Спробуйте ще раз.")

def handle_encode():
    """Обробник для кодування, включаючи розрахунок обсягу бітів."""
    print("\n--- Режим Кодування ---")
    image_path = input("Введіть шлях до зображення-контейнера (наприклад, image.png): ").strip()

    if not image_path:
        print("❌ Шлях до файлу не може бути порожнім.")
        return

    # --- АНАЛІЗ МІСТКОСТІ ЗОБРАЖЕННЯ ---
    try:
        img = Image.open(image_path).convert("RGB")
        max_bits = get_image_size(img)
        print(f"\nМаксимальна місткість зображення '{os.path.basename(image_path)}': {max_bits} біт")
        
    except FileNotFoundError:
        print(f"❌ Помилка: Файл контейнера '{image_path}' не знайдено. Повторіть спробу.")
        return
    except Exception as e:
        print(f"❌ Помилка аналізу зображення: {e}")
        return
    
    message = input("Введіть секретне повідомлення: ").strip()
    
    if not message:
        print("❌ Повідомлення не може бути порожнім.")
        return
        
    message_bits = text_to_bits(message)
    message_size_bits = len(message_bits)
    data_len_bits = (LENGTH_PREFIX_BYTES * 8) + message_size_bits
    
    print("\n--- Аналіз Обсягу ---")
    print(f"Довжина повідомлення (без префікса): {message_size_bits} біт ({len(message)} байт)")
    print(f"Загальна кількість бітів для запису (з префіксом): {data_len_bits} біт")
    
    if data_len_bits > max_bits:
        print(f"⚠️ **ПОПЕРЕДЖЕННЯ:** Повідомлення завелике для цього контейнера! ({data_len_bits} біт > {max_bits} біт)")
        return
    print("Місця достатньо.")

    output_path = input("Введіть назву для стегоконтейнера (наприклад, stego.png): ").strip()

    if not output_path.lower().endswith(('.png', '.bmp')):
        output_path = os.path.splitext(output_path)[0] + ".png"
        print(f"Зображення буде збережено у форматі PNG для збереження LSB: '{output_path}'")
        
    encode(image_path, message, output_path)

def handle_decode_menu():
    """Обробник для декодування."""
    print("\n--- Режим Декодування ---")
    image_path = input("Введіть шлях до стегоконтейнера: ").strip()
    
    if not image_path:
        print("❌ Шлях до файлу не може бути порожнім.")
        return
        
    result = decode(image_path)
    print(result)

# --- ПРИКЛАД ВИКОРИСТАННЯ (Демонстрація) ---

# Винесено в окрему функцію для чистоти, але викликається, якщо немає інтерактивного режиму
def run_demonstration():
    print("\n" + "="*40)
    print("ДЕМОНСТРАЦІЙНИЙ РЕЖИМ (Виведення обсягів бітів)")
    print("="*40)
    
    IMAGE_FILE = "test_image_100x100.png"
    STEGO_FILE = "stego_demo.png"
    SECRET_MESSAGE = "Тестове повідомлення для демонстрації обсягів."

    # 1. Створення тестового зображення (100x100 пікселів)
    try:
        img = Image.new('RGB', (100, 100), color = 'red')
        img.save(IMAGE_FILE)
        
        # 2. Розрахунок та виведення обсягів
        max_bits = get_image_size(img)
        message_bits = text_to_bits(SECRET_MESSAGE)
        message_size_bits = len(message_bits)
        data_len_bits = (LENGTH_PREFIX_BYTES * 8) + message_size_bits

        print(f"🖼️ Тестове зображення: {IMAGE_FILE} (100x100 px)")
        print(f"📦 Секретне повідомлення: '{SECRET_MESSAGE}'")
        print("--- Розрахунок ---")
        print(f" Довжина повідомлення (без префікса): {message_size_bits} біт")
        print(f"📦 Загальна кількість бітів для запису (з префіксом): {data_len_bits} біт")
        print(f"Максимальна місткість зображення: {max_bits} біт")
        
        if data_len_bits > max_bits:
            print("⚠️ ПОВІДОМЛЕННЯ НЕ БУДЕ ЗАКОДОВАНЕ (завелике)!")
            return
        
        # 3. Кодування
        print("\n--- Кодування ---")
        encode(IMAGE_FILE, SECRET_MESSAGE, STEGO_FILE)

        # 4. Декодування
        print("\n--- Декодування ---")
        extracted_message = decode(STEGO_FILE)
        print("Витягнуте повідомлення:")
        print(extracted_message)

    except Exception as e:
        print(f"❌ Помилка в демонстраційному режимі: {e}")
    finally:
        # Прибирання за собою
        if os.path.exists(IMAGE_FILE):
            os.remove(IMAGE_FILE)
        if os.path.exists(STEGO_FILE):
            os.remove(STEGO_FILE)
        
    print("\nДемонстраційний режим завершено.")
    print("="*40)

# Запуск програми
if __name__ == '__main__':
    # run_demonstration() # Розкоментуйте цю строку для запуску демонстрації бітів
    main_menu()