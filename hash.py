import hashlib
import time
import os
import base64
import hmac
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
from cryptography.hazmat.backends import default_backend

class HashFunctions:
    def __init__(self):
        """Инициализация класса для работы с хеш-функциями"""
        self.supported_hashes = {
            'MD5': hashlib.md5,
            'SHA1': hashlib.sha1,
            'SHA224': hashlib.sha224,
            'SHA256': hashlib.sha256,
            'SHA384': hashlib.sha384,
            'SHA512': hashlib.sha512,
            'SHA3_224': hashlib.sha3_224,
            'SHA3_256': hashlib.sha3_256,
            'SHA3_384': hashlib.sha3_384,
            'SHA3_512': hashlib.sha3_512,
            'BLAKE2b': hashlib.blake2b,
            'BLAKE2s': hashlib.blake2s
        }
    
    def calculate_hash(self, data, algorithm='SHA256'):
        """
        Вычисление хеша для данных
        data: строковые или байтовые данные
        algorithm: алгоритм хеширования
        """
        if algorithm not in self.supported_hashes:
            raise ValueError(f"Неподдерживаемый алгоритм: {algorithm}")
        
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        hash_func = self.supported_hashes[algorithm]()
        hash_func.update(data)
        return hash_func.hexdigest()
    
    def calculate_hash_bytes(self, data, algorithm='SHA256'):
        """Вычисление хеша в байтовом формате"""
        if algorithm not in self.supported_hashes:
            raise ValueError(f"Неподдерживаемый алгоритм: {algorithm}")
        
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        hash_func = self.supported_hashes[algorithm]()
        hash_func.update(data)
        return hash_func.digest()
    
    def hmac_hash(self, data, key, algorithm='SHA256'):
        """
        Вычисление HMAC (Hash-based Message Authentication Code)
        """
        if isinstance(data, str):
            data = data.encode('utf-8')
        if isinstance(key, str):
            key = key.encode('utf-8')
        
        hmac_obj = hmac.new(key, data, getattr(hashlib, algorithm.lower()))
        return hmac_obj.hexdigest()
    
    def pbkdf2_derive(self, password, salt, iterations=100000, key_length=32, algorithm='SHA256'):
        """
        Генерация ключа из пароля с помощью PBKDF2
        """
        if isinstance(password, str):
            password = password.encode('utf-8')
        if isinstance(salt, str):
            salt = salt.encode('utf-8')
        
        kdf = PBKDF2(
            algorithm=getattr(hashes, algorithm.upper())(),
            length=key_length,
            salt=salt,
            iterations=iterations,
            backend=default_backend()
        )
        return kdf.derive(password)
    
    def compare_hashes(self, hash1, hash2):
        """Безопасное сравнение хешей (защита от timing attacks)"""
        return hmac.compare_digest(hash1, hash2)
    
    def measure_collision_resistance(self, algorithm, num_samples=1000):
        """
        Тестирование сопротивления коллизиям
        """
        hashes_set = set()
        collisions = 0
        
        for i in range(num_samples):
            random_data = os.urandom(32)
            hash_value = self.calculate_hash(random_data, algorithm)
            
            if hash_value in hashes_set:
                collisions += 1
            else:
                hashes_set.add(hash_value)
        
        return collisions, len(hashes_set)
    
    def avalanche_test(self, data, algorithm='SHA256'):
        """
        Тест лавинного эффекта - небольшое изменение данных должно сильно менять хеш
        """
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        original_hash = self.calculate_hash(data, algorithm)
        
        # Меняем один бит
        modified_data = bytearray(data)
        if len(modified_data) > 0:
            modified_data[0] ^= 1  # Инвертируем первый бит
        
        modified_hash = self.calculate_hash(bytes(modified_data), algorithm)
        
        # Считаем количество отличающихся битов
        diff_bits = self._count_different_bits(original_hash, modified_hash)
        total_bits = len(original_hash) * 4  # hex digits to bits
        
        return diff_bits, total_bits, (diff_bits / total_bits) * 100

    def _count_different_bits(self, hex1, hex2):
        """Подсчет количества отличающихся битов между двумя hex строками"""
        bytes1 = bytes.fromhex(hex1)
        bytes2 = bytes.fromhex(hex2)
        
        diff_count = 0
        for b1, b2 in zip(bytes1, bytes2):
            diff = b1 ^ b2
            diff_count += bin(diff).count('1')
        
        return diff_count

def demonstrate_hash_functions():
    """Демонстрация работы хеш-функций"""
    
    print("=" * 70)
    print("ПРАКТИЧЕСКАЯ РАБОТА: ХЕШ-ФУНКЦИИ")
    print("SHA семейство и алгоритмы хеширования")
    print("=" * 70)
    
    hash_obj = HashFunctions()
    
    # Тестовые данные
    test_data = "Hello World! This is a test message for hash functions."
    test_password = "my_secret_password"
    salt = os.urandom(16)
    
    print(f"Тестовые данные: {test_data}")
    print(f"Длина данных: {len(test_data)} байт")
    print()
    
    # Сравнение разных алгоритмов хеширования
    algorithms = ['MD5', 'SHA1', 'SHA256', 'SHA512', 'SHA3_256', 'BLAKE2b']
    
    print("1. СРАВНЕНИЕ АЛГОРИТМОВ ХЕШИРОВАНИЯ:")
    print("-" * 50)
    
    results = {}
    for algo in algorithms:
        start_time = time.time()
        hash_value = hash_obj.calculate_hash(test_data, algo)
        end_time = time.time()
        
        results[algo] = {
            'hash': hash_value,
            'time': end_time - start_time,
            'length': len(hash_value)  # в hex символах
        }
        
        print(f"{algo:10} | Время: {results[algo]['time']:8f} сек | "
              f"Длина: {results[algo]['length']:3} симв | "
              f"Хеш: {hash_value[:20]}...")
    
    print()
    
    # Лавинный эффект
    print("2. ТЕСТ ЛАВИННОГО ЭФФЕКТА (SHA256):")
    diff_bits, total_bits, percentage = hash_obj.avalanche_test(test_data, 'SHA256')
    print(f"   Измененных битов: {diff_bits}/{total_bits} ({percentage:.2f}%)")
    print("   (небольшое изменение данных значительно меняет хеш)")
    print()
    
    # HMAC демонстрация
    print("3. HMAC (Hash-based Message Authentication Code):")
    hmac_key = "secret_key"
    hmac_result = hash_obj.hmac_hash(test_data, hmac_key, 'SHA256')
    print(f"   Ключ: {hmac_key}")
    print(f"   HMAC-SHA256: {hmac_result}")
    print()
    
    # PBKDF2 демонстрация
    print("4. PBKDF2 (Password-Based Key Derivation Function):")
    derived_key = hash_obj.pbkdf2_derive(test_password, salt, iterations=1000, key_length=32)
    print(f"   Пароль: {test_password}")
    print(f"   Соль: {base64.b64encode(salt).decode()}")
    print(f"   Производный ключ: {base64.b64encode(derived_key).decode()}")
    print()
    
    # Сравнение производительности на разных размерах данных
    print("5. ПРОИЗВОДИТЕЛЬНОСТЬ НА РАЗНЫХ РАЗМЕРАХ ДАННЫХ (SHA256):")
    sizes = [10, 100, 1000, 10000, 100000]  # байты
    
    for size in sizes:
        test_data_large = os.urandom(size)
        start_time = time.time()
        hash_obj.calculate_hash(test_data_large, 'SHA256')
        end_time = time.time()
        
        print(f"   {size:6} байт: {end_time - start_time:.6f} сек")

def compare_hash_algorithms():
    """Сравнительный анализ алгоритмов хеширования"""
    
    print("\n" + "=" * 70)
    print("СРАВНИТЕЛЬНЫЙ АНАЛИЗ АЛГОРИТМОВ ХЕШИРОВАНИЯ")
    print("=" * 70)
    
    hash_obj = HashFunctions()
    test_data = "Test message for algorithm comparison"
    
    algorithms = [
        'MD5', 'SHA1', 'SHA224', 'SHA256', 
        'SHA384', 'SHA512', 'SHA3_224', 'SHA3_256',
        'SHA3_384', 'SHA3_512', 'BLAKE2b', 'BLAKE2s'
    ]
    
    print("Алгоритм      | Размер | Время (сек) | Безопасность | Рекомендация")
    print("-" * 70)
    
    security_levels = {
        'MD5': 'Сломан',
        'SHA1': 'Ненадежный', 
        'SHA224': 'Приемлемый',
        'SHA256': 'Надежный',
        'SHA384': 'Очень надежный',
        'SHA512': 'Очень надежный',
        'SHA3_224': 'Надежный',
        'SHA3_256': 'Очень надежный',
        'SHA3_384': 'Очень надежный',
        'SHA3_512': 'Максимальный',
        'BLAKE2b': 'Очень надежный',
        'BLAKE2s': 'Очень надежный'
    }
    
    recommendations = {
        'MD5': 'Не использовать',
        'SHA1': 'Не использовать',
        'SHA224': 'Для некритичных задач',
        'SHA256': 'Стандарт, рекомендуется',
        'SHA384': 'Для высокой безопасности',
        'SHA512': 'Для максимальной безопасности',
        'SHA3_224': 'Альтернатива SHA256',
        'SHA3_256': 'Рекомендуется',
        'SHA3_384': 'Для высокой безопасности',
        'SHA3_512': 'Для максимальной безопасности',
        'BLAKE2b': 'Высокая производительность',
        'BLAKE2s': 'Для встроенных систем'
    }
    
    for algo in algorithms:
        start_time = time.time()
        hash_value = hash_obj.calculate_hash(test_data, algo)
        end_time = time.time()
        
        hash_size = len(hash_value)  # hex characters
        execution_time = end_time - start_time
        
        print(f"{algo:12} | {hash_size:6} | {execution_time:11.8f} | "
              f"{security_levels[algo]:12} | {recommendations[algo]}")

def demonstrate_collision_resistance():
    """Демонстрация сопротивления коллизиям"""
    
    print("\n" + "=" * 70)
    print("ТЕСТИРОВАНИЕ СОПРОТИВЛЕНИЯ КОЛЛИЗИЯМ")
    print("=" * 70)
    
    hash_obj = HashFunctions()
    test_algorithms = ['MD5', 'SHA1', 'SHA256']
    
    print("Тест на 10,000 случайных образцов:")
    print("Алгоритм  | Коллизии | Уникальных хешей | Вероятность")
    print("-" * 55)
    
    for algo in test_algorithms:
        collisions, unique_hashes = hash_obj.measure_collision_resistance(algo, 10000)
        collision_prob = (collisions / 10000) * 100
        
        print(f"{algo:8} | {collisions:8} | {unique_hashes:15} | {collision_prob:8.6f}%")

def practical_applications():
    """Практические применения хеш-функций"""
    
    print("\n" + "=" * 70)
    print("ПРАКТИЧЕСКИЕ ПРИМЕНЕНИЯ ХЕШ-ФУНКЦИЙ")
    print("=" * 70)
    
    hash_obj = HashFunctions()
    
    # 1. Проверка целостности файлов
    print("1. ПРОВЕРКА ЦЕЛОСТНОСТИ ФАЙЛОВ:")
    file_data = b"This is simulated file content for integrity check"
    file_hash = hash_obj.calculate_hash(file_data, 'SHA256')
    print(f"   Хеш файла: {file_hash}")
    print(f"   Проверка: {hash_obj.compare_hashes(file_hash, file_hash)}")
    
    # 2. Хранение паролей
    print("\n2. ХРАНЕНИЕ ПАРОЛЕЙ:")
    password = "user_password_123"
    salt = os.urandom(16)
    password_hash = hash_obj.pbkdf2_derive(password, salt, iterations=100000)
    print(f"   Пароль: {password}")
    print(f"   Хеш пароля: {base64.b64encode(password_hash).decode()}")
    
    # 3. Цифровые подписи
    print("\n3. ЦИФРОВЫЕ ПОДПИСИ:")
    document = "Important contract document"
    document_hash = hash_obj.calculate_hash_bytes(document, 'SHA256')
    print(f"   Документ: {document}")
    print(f"   Хеш для подписи: {base64.b64encode(document_hash).decode()}")
    
    # 4. HMAC для аутентификации сообщений
    print("\n4. HMAC ДЛЯ АУТЕНТИФИКАЦИИ:")
    message = "API request data"
    secret = "api_secret_key"
    hmac_signature = hash_obj.hmac_hash(message, secret, 'SHA256')
    print(f"   Сообщение: {message}")
    print(f"   HMAC подпись: {hmac_signature}")

if __name__ == "__main__":
    demonstrate_hash_functions()
    compare_hash_algorithms()
    demonstrate_collision_resistance()
    practical_applications()
    
    print("\n" + "=" * 70)
    print("ВЫВОДЫ:")
    print("- SHA256: Текущий стандарт для большинства применений")
    print("- SHA3: Перспективный стандарт с другой архитектурой")
    print("- BLAKE2: Высокая производительность при хорошей безопасности")
    print("- MD5/SHA1: Не должны использоваться для безопасности")
    print("- HMAC: Для аутентификации сообщений с ключом")
    print("- PBKDF2: Для безопасного преобразования паролей в ключи")
    print("=" * 70)
