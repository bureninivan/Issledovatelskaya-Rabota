import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import hashlib

class AESEncryption:
    def __init__(self, key=None):
        if key is None:
            # Генерация ключа по умолчанию (AES-256)
            key = os.urandom(32)
        
        self.key = key
        self.key_size = len(key) * 8  # Размер ключа в битах
    
    def _validate_key(self):
        valid_sizes = [128, 192, 256]
        if self.key_size not in valid_sizes:
            raise ValueError(f"Некорректный размер ключа. Допустимые размеры: {valid_sizes}")
    
    def encrypt_ecb(self, plaintext):
        self._validate_key()
        
        # Добавление padding для выравнивания размера блока
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext) + padder.finalize()
        
        # Создание шифра
        cipher = Cipher(algorithms.AES(self.key), modes.ECB(), backend=default_backend())
        encryptor = cipher.encryptor()
        
        # Шифрование
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return ciphertext
    
    def decrypt_ecb(self, ciphertext):
        self._validate_key()
        
        # Создание шифра
        cipher = Cipher(algorithms.AES(self.key), modes.ECB(), backend=default_backend())
        decryptor = cipher.decryptor()
        
        # Дешифрование
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Удаление padding
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        
        return plaintext
    
    def encrypt_cbc(self, plaintext, iv=None):
        self._validate_key()
        
        if iv is None:
            iv = os.urandom(16)
        elif len(iv) != 16:
            raise ValueError("IV должен быть длиной 16 байт")
        
        # Добавление padding
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext) + padder.finalize()
        
        # Создание шифра
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        # Шифрование
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return iv + ciphertext  # Возвращаем IV вместе с шифротекстом
    
    def decrypt_cbc(self, ciphertext_with_iv):
        self._validate_key()
        
        # Извлечение IV и шифротекста
        iv = ciphertext_with_iv[:16]
        ciphertext = ciphertext_with_iv[16:]
        
        # Создание шифра
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        
        # Дешифрование
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Удаление padding
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        
        return plaintext
    
    def encrypt_cfb(self, plaintext, iv=None):
        self._validate_key()
        
        if iv is None:
            iv = os.urandom(16)
        elif len(iv) != 16:
            raise ValueError("IV должен быть длиной 16 байт")
        
        # Создание шифра
        cipher = Cipher(algorithms.AES(self.key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        # Шифрование
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return iv + ciphertext
    
    def decrypt_cfb(self, ciphertext_with_iv):
        self._validate_key()
        
        # Извлечение IV и шифротекста
        iv = ciphertext_with_iv[:16]
        ciphertext = ciphertext_with_iv[16:]
        
        # Создание шифра
        cipher = Cipher(algorithms.AES(self.key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        
        # Дешифрование
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext
    
    def encrypt_ofb(self, plaintext, iv=None):
        self._validate_key()
        
        if iv is None:
            iv = os.urandom(16)
        elif len(iv) != 16:
            raise ValueError("IV должен быть длиной 16 байт")
        
        # Создание шифра
        cipher = Cipher(algorithms.AES(self.key), modes.OFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        # Шифрование
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return iv + ciphertext
    
    def decrypt_ofb(self, ciphertext_with_iv):
        self._validate_key()
        
        # Извлечение IV и шифротекста
        iv = ciphertext_with_iv[:16]
        ciphertext = ciphertext_with_iv[16:]
        
        # Создание шифра
        cipher = Cipher(algorithms.AES(self.key), modes.OFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        
        # Дешифрование
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext

def demonstrate_aes_modes():
    
    print("=" * 60)
    print("ПРАКТИЧЕСКАЯ РАБОТА: АЛГОРИТМЫ СИММЕТРИЧНОГО ШИФРОВАНИЯ")
    print("AES с различными режимами работы")
    print("=" * 60)
    
    # Исходные данные
    plaintext = b"Hello World! This is a secret message for AES encryption demonstration."
    password = "my_secret_password"
    
    # Генерация ключа из пароля
    key = hashlib.sha256(password.encode()).digest()
    
    # Создание экземпляра шифровальщика
    aes = AESEncryption(key)
    
    print(f"Исходный текст: {plaintext.decode()}")
    print(f"Размер исходного текста: {len(plaintext)} байт")
    print(f"Используемый ключ (SHA-256 от пароля): {base64.b64encode(key).decode()}")
    print(f"Размер ключа: {aes.key_size} бит")
    print()
    
    # Режим ECB
    print("1. РЕЖИМ ECB (Electronic Codebook):")
    ecb_cipher = aes.encrypt_ecb(plaintext)
    ecb_decrypted = aes.decrypt_ecb(ecb_cipher)
    print(f"   Зашифрованный текст: {base64.b64encode(ecb_cipher).decode()}")
    print(f"   Расшифрованный текст: {ecb_decrypted.decode()}")
    print(f"   Совпадение: {plaintext == ecb_decrypted}")
    print()
    
    # Режим CBC
    print("2. РЕЖИМ CBC (Cipher Block Chaining):")
    cbc_cipher = aes.encrypt_cbc(plaintext)
    cbc_decrypted = aes.decrypt_cbc(cbc_cipher)
    print(f"   Зашифрованный текст (с IV): {base64.b64encode(cbc_cipher).decode()}")
    print(f"   Расшифрованный текст: {cbc_decrypted.decode()}")
    print(f"   Совпадение: {plaintext == cbc_decrypted}")
    print()
    
    # Режим CFB
    print("3. РЕЖИМ CFB (Cipher Feedback):")
    cfb_cipher = aes.encrypt_cfb(plaintext)
    cfb_decrypted = aes.decrypt_cfb(cfb_cipher)
    print(f"   Зашифрованный текст (с IV): {base64.b64encode(cfb_cipher).decode()}")
    print(f"   Расшифрованный текст: {cfb_decrypted.decode()}")
    print(f"   Совпадение: {plaintext == cfb_decrypted}")
    print()
    
    # Режим OFB
    print("4. РЕЖИМ OFB (Output Feedback):")
    ofb_cipher = aes.encrypt_ofb(plaintext)
    ofb_decrypted = aes.decrypt_ofb(ofb_cipher)
    print(f"   Зашифрованный текст (с IV): {base64.b64encode(ofb_cipher).decode()}")
    print(f"   Расшифрованный текст: {ofb_decrypted.decode()}")
    print(f"   Совпадение: {plaintext == ofb_decrypted}")
    print()
    
    # Демонстрация с разными ключами
    print("5. ДЕМОНСТРАЦИЯ С РАЗНЫМИ РАЗМЕРАМИ КЛЮЧЕЙ:")
    key_sizes = {
        "AES-128": os.urandom(16),
        "AES-192": os.urandom(24),
        "AES-256": os.urandom(32)
    }
    
    for name, key in key_sizes.items():
        aes_test = AESEncryption(key)
        test_cipher = aes_test.encrypt_cbc(plaintext)
        test_decrypted = aes_test.decrypt_cbc(test_cipher)
        print(f"   {name}: Совпадение после шифрования/дешифрования: {plaintext == test_decrypted}")

def compare_modes_performance():
    import time
    
    print("\n" + "=" * 60)
    print("СРАВНЕНИЕ ПРОИЗВОДИТЕЛЬНОСТИ РЕЖИМОВ")
    print("=" * 60)
    
    # Большой объем данных для тестирования
    large_data = os.urandom(1024 * 1024)  # 1 MB данных
    key = os.urandom(32)
    aes = AESEncryption(key)
    
    modes_functions = [
        ("ECB", aes.encrypt_ecb, aes.decrypt_ecb),
        ("CBC", aes.encrypt_cbc, aes.decrypt_cbc),
        ("CFB", aes.encrypt_cfb, aes.decrypt_cfb),
        ("OFB", aes.encrypt_ofb, aes.decrypt_ofb),
    ]
    
    for mode_name, encrypt_func, decrypt_func in modes_functions:
        start_time = time.time()
        
        # Шифрование
        ciphertext = encrypt_func(large_data)
        
        # Дешифрование
        if mode_name == "ECB":
            decrypted = decrypt_func(ciphertext)
        else:
            decrypted = decrypt_func(ciphertext)
        
        end_time = time.time()
        
        print(f"{mode_name}:")
        print(f"  Время выполнения: {end_time - start_time:.4f} секунд")
        print(f"  Корректность: {large_data == decrypted}")
        print(f"  Размер данных: {len(large_data)} байт")
        print(f"  Размер шифротекста: {len(ciphertext)} байт")
        print()

if __name__ == "__main__":
    # Установка необходимой библиотеки
    # pip install cryptography
    
    demonstrate_aes_modes()
    compare_modes_performance()
    
    print("=" * 60)
    print("ВЫВОДЫ:")
    print("- ECB: Простой режим, но небезопасен для повторяющихся данных")
    print("- CBC: Более безопасный, требует IV, подвержен ошибкам padding")
    print("- CFB: Поточный режим, не требует padding")
    print("- OFB: Поточный режим, устойчив к ошибкам передачи")
    print("=" * 60)
