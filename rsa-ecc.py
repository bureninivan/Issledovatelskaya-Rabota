import os
import base64
import time
import hashlib
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

class AsymmetricEncryption:
    def __init__(self):
        """Инициализация классов для RSA и ECC шифрования"""
        self.rsa_private_key = None
        self.rsa_public_key = None
        self.ec_private_key = None
        self.ec_public_key = None
    
    def generate_rsa_keys(self, key_size=2048):
        """
        Генерация RSA ключевой пары
        key_size: 1024, 2048, 3072, 4096 бит
        """
        print(f"Генерация RSA ключей ({key_size} бит)...")
        
        self.rsa_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        self.rsa_public_key = self.rsa_private_key.public_key()
        
        return self.rsa_private_key, self.rsa_public_key
    
    def generate_ecc_keys(self, curve=ec.SECP256R1):
        """
        Генерация ECC ключевой пары
        curve: SECP256R1, SECP384R1, SECP521R1, etc.
        """
        print(f"Генерация ECC ключей ({curve.name})...")
        
        self.ec_private_key = ec.generate_private_key(
            curve=curve,
            backend=default_backend()
        )
        self.ec_public_key = self.ec_private_key.public_key()
        
        return self.ec_private_key, self.ec_public_key
    
    def rsa_encrypt(self, plaintext, public_key=None):
        """
        Шифрование с помощью RSA
        RSA может шифровать только небольшие сообщения
        """
        if public_key is None:
            public_key = self.rsa_public_key
        
        # RSA может шифровать только данные меньше размера ключа
        max_size = (public_key.key_size // 8) - 42  # Для OAEP padding
        
        if len(plaintext) > max_size:
            raise ValueError(f"Сообщение слишком большое для RSA. Максимум: {max_size} байт")
        
        ciphertext = public_key.encrypt(
            plaintext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return ciphertext
    
    def rsa_decrypt(self, ciphertext, private_key=None):
        """Дешифрование с помощью RSA"""
        if private_key is None:
            private_key = self.rsa_private_key
        
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext
    
    def ecc_encrypt_hybrid(self, plaintext, public_key=None):
        """
        Гибридное шифрование с ECC
        ECDH для обмена ключами + симметричное шифрование
        """
        if public_key is None:
            public_key = self.ec_public_key
        
        # Генерация временной ключевой пары для ECDH
        ephemeral_private_key = ec.generate_private_key(
            curve=public_key.curve,
            backend=default_backend()
        )
        ephemeral_public_key = ephemeral_private_key.public_key()
        
        # Вычисление общего секрета
        shared_secret = ephemeral_private_key.exchange(ec.ECDH(), public_key)
        
        # Производный ключ для шифрования
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'hybrid-encryption',
            backend=default_backend()
        ).derive(shared_secret)
        
        # Простое XOR шифрование (в реальности использовать AES)
        ciphertext = bytes([p ^ k for p, k in zip(plaintext, derived_key[:len(plaintext)])])
        
        # Возвращаем временный публичный ключ и шифротекст
        return ephemeral_public_key, ciphertext
    
    def ecc_decrypt_hybrid(self, ephemeral_public_key, ciphertext, private_key=None):
        """Дешифрование гибридного ECC шифрования"""
        if private_key is None:
            private_key = self.ec_private_key
        
        # Вычисление общего секрета
        shared_secret = private_key.exchange(ec.ECDH(), ephemeral_public_key)
        
        # Производный ключ для дешифрования
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'hybrid-encryption',
            backend=default_backend()
        ).derive(shared_secret)
        
        # Дешифрование
        plaintext = bytes([c ^ k for c, k in zip(ciphertext, derived_key[:len(ciphertext)])])
        
        return plaintext
    
    def rsa_sign(self, message, private_key=None):
        """Создание цифровой подписи с RSA"""
        if private_key is None:
            private_key = self.rsa_private_key
        
        signature = private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature
    
    def rsa_verify(self, message, signature, public_key=None):
        """Проверка цифровой подписи с RSA"""
        if public_key is None:
            public_key = self.rsa_public_key
        
        try:
            public_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False
    
    def ecc_sign(self, message, private_key=None):
        """Создание цифровой подписи с ECC"""
        if private_key is None:
            private_key = self.ec_private_key
        
        signature = private_key.sign(
            message,
            ec.ECDSA(hashes.SHA256())
        )
        return signature
    
    def ecc_verify(self, message, signature, public_key=None):
        """Проверка цифровой подписи с ECC"""
        if public_key is None:
            public_key = self.ec_public_key
        
        try:
            public_key.verify(
                signature,
                message,
                ec.ECDSA(hashes.SHA256())
            )
            return True
        except InvalidSignature:
            return False
    
    def save_rsa_private_key(self, filename, password=None):
        """Сохранение RSA приватного ключа"""
        if self.rsa_private_key is None:
            raise ValueError("RSA приватный ключ не сгенерирован")
        
        encryption_algorithm = serialization.NoEncryption()
        if password:
            encryption_algorithm = serialization.BestAvailableEncryption(password.encode())
        
        with open(filename, 'wb') as f:
            f.write(self.rsa_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=encryption_algorithm
            ))
    
    def save_rsa_public_key(self, filename):
        """Сохранение RSA публичного ключа"""
        if self.rsa_public_key is None:
            raise ValueError("RSA публичный ключ не сгенерирован")
        
        with open(filename, 'wb') as f:
            f.write(self.rsa_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

def demonstrate_rsa_ecc():
    """Демонстрация работы RSA и ECC"""
    
    print("=" * 70)
    print("ПРАКТИЧЕСКАЯ РАБОТА: АСИММЕТРИЧНОЕ ШИФРОВАНИЕ")
    print("RSA и ECC (Elliptic-Curve Cryptography)")
    print("=" * 70)
    
    # Создание экземпляра шифровальщика
    crypto = AsymmetricEncryption()
    
    # Исходные данные
    message = b"Hello World! This is a test message for asymmetric encryption."
    short_message = b"Short secret"  # Для прямого RSA шифрования
    
    print(f"Исходное сообщение: {message.decode()}")
    print(f"Размер сообщения: {len(message)} байт")
    print(f"Короткое сообщение для RSA: {short_message.decode()}")
    print()
    
    # Генерация ключей RSA
    start_time = time.time()
    rsa_private, rsa_public = crypto.generate_rsa_keys(2048)
    rsa_key_gen_time = time.time() - start_time
    
    print(f"1. RSA КЛЮЧЕВАЯ ПАРА (2048 бит):")
    print(f"   Время генерации: {rsa_key_gen_time:.4f} секунд")
    
    # RSA Шифрование/Дешифрование
    start_time = time.time()
    rsa_ciphertext = crypto.rsa_encrypt(short_message)
    rsa_encrypt_time = time.time() - start_time
    
    start_time = time.time()
    rsa_decrypted = crypto.rsa_decrypt(rsa_ciphertext)
    rsa_decrypt_time = time.time() - start_time
    
    print(f"   Шифрование: {rsa_encrypt_time:.4f} сек")
    print(f"   Дешифрование: {rsa_decrypt_time:.4f} сек")
    print(f"   Зашифрованный текст: {base64.b64encode(rsa_ciphertext).decode()[:50]}...")
    print(f"   Расшифрованный текст: {rsa_decrypted.decode()}")
    print(f"   Совпадение: {short_message == rsa_decrypted}")
    print()
    
    # RSA Цифровая подпись
    start_time = time.time()
    rsa_signature = crypto.rsa_sign(message)
    rsa_sign_time = time.time() - start_time
    
    start_time = time.time()
    rsa_verify_result = crypto.rsa_verify(message, rsa_signature)
    rsa_verify_time = time.time() - start_time
    
    print(f"2. RSA ЦИФРОВАЯ ПОДПИСЬ:")
    print(f"   Создание подписи: {rsa_sign_time:.4f} сек")
    print(f"   Проверка подписи: {rsa_verify_time:.4f} сек")
    print(f"   Подпись верна: {rsa_verify_result}")
    print(f"   Размер подписи: {len(rsa_signature)} байт")
    print()
    
    # Генерация ключей ECC
    start_time = time.time()
    ecc_private, ecc_public = crypto.generate_ecc_keys(ec.SECP256R1)
    ecc_key_gen_time = time.time() - start_time
    
    print(f"3. ECC КЛЮЧЕВАЯ ПАРА (SECP256R1):")
    print(f"   Время генерации: {ecc_key_gen_time:.4f} секунд")
    
    # ECC Гибридное шифрование
    start_time = time.time()
    ecc_ephemeral, ecc_ciphertext = crypto.ecc_encrypt_hybrid(message)
    ecc_encrypt_time = time.time() - start_time
    
    start_time = time.time()
    ecc_decrypted = crypto.ecc_decrypt_hybrid(ecc_ephemeral, ecc_ciphertext)
    ecc_decrypt_time = time.time() - start_time
    
    print(f"   Гибридное шифрование: {ecc_encrypt_time:.4f} сек")
    print(f"   Гибридное дешифрование: {ecc_decrypt_time:.4f} сек")
    print(f"   Расшифрованный текст: {ecc_decrypted.decode()}")
    print(f"   Совпадение: {message == ecc_decrypted}")
    print()
    
    # ECC Цифровая подпись
    start_time = time.time()
    ecc_signature = crypto.ecc_sign(message)
    ecc_sign_time = time.time() - start_time
    
    start_time = time.time()
    ecc_verify_result = crypto.ecc_verify(message, ecc_signature)
    ecc_verify_time = time.time() - start_time
    
    print(f"4. ECC ЦИФРОВАЯ ПОДПИСЬ:")
    print(f"   Создание подписи: {ecc_sign_time:.4f} сек")
    print(f"   Проверка подписи: {ecc_verify_time:.4f} сек")
    print(f"   Подпись верна: {ecc_verify_result}")
    print(f"   Размер подписи: {len(ecc_signature)} байт")
    print()

def compare_performance():
    """Сравнение производительности RSA и ECC"""
    
    print("=" * 70)
    print("СРАВНЕНИЕ ПРОИЗВОДИТЕЛЬНОСТИ RSA И ECC")
    print("=" * 70)
    
    crypto = AsymmetricEncryption()
    test_data = b"Performance test data for RSA and ECC comparison."
    
    # Тестирование разных размеров RSA ключей
    rsa_sizes = [1024, 2048, 3072, 4096]
    
    print("RSA РАЗНЫЕ РАЗМЕРЫ КЛЮЧЕЙ:")
    for size in rsa_sizes:
        start_time = time.time()
        crypto.generate_rsa_keys(size)
        key_gen_time = time.time() - start_time
        
        # Шифрование короткого сообщения
        short_msg = b"Test"
        start_time = time.time()
        cipher = crypto.rsa_encrypt(short_msg)
        encrypt_time = time.time() - start_time
        
        start_time = time.time()
        crypto.rsa_decrypt(cipher)
        decrypt_time = time.time() - start_time
        
        print(f"  {size} бит: Генерация={key_gen_time:.3f}с, "
              f"Шифр={encrypt_time:.3f}с, Дешифр={decrypt_time:.3f}с")
    
    print()
    
    # Тестирование разных ECC кривых
    ecc_curves = [
        (ec.SECP192R1, "SECP192R1"),
        (ec.SECP256R1, "SECP256R1"), 
        (ec.SECP384R1, "SECP384R1"),
        (ec.SECP521R1, "SECP521R1")
    ]
    
    print("ECC РАЗНЫЕ КРИВЫЕ:")
    for curve, name in ecc_curves:
        start_time = time.time()
        crypto.generate_ecc_keys(curve)
        key_gen_time = time.time() - start_time
        
        start_time = time.time()
        signature = crypto.ecc_sign(test_data)
        sign_time = time.time() - start_time
        
        start_time = time.time()
        crypto.ecc_verify(test_data, signature)
        verify_time = time.time() - start_time
        
        print(f"  {name}: Генерация={key_gen_time:.3f}с, "
              f"Подпись={sign_time:.3f}с, Проверка={verify_time:.3f}с")

def demonstrate_key_exchange():
    """Демонстрация обмена ключами"""
    
    print("\n" + "=" * 70)
    print("ДЕМОНСТРАЦИЯ ОБМЕНА КЛЮЧАМИ")
    print("=" * 70)
    
    # Алиса генерирует ключи
    alice_crypto = AsymmetricEncryption()
    alice_crypto.generate_ecc_keys(ec.SECP256R1)
    
    # Боб генерирует ключи  
    bob_crypto = AsymmetricEncryption()
    bob_crypto.generate_ecc_keys(ec.SECP256R1)
    
    print("СЦЕНАРИЙ: Алиса и Боб обмениваются ключами")
    print("Алиса генерирует ключевую пару ECC...")
    print("Боб генерирует ключевую пару ECC...")
    
    # Алиса вычисляет общий секрет с публичным ключом Боба
    alice_shared_secret = alice_crypto.ec_private_key.exchange(
        ec.ECDH(), 
        bob_crypto.ec_public_key
    )
    
    # Боб вычисляет общий секрет с публичным ключом Алисы
    bob_shared_secret = bob_crypto.ec_private_key.exchange(
        ec.ECDH(), 
        alice_crypto.ec_public_key
    )
    
    print(f"Общий секрет Алисы: {base64.b64encode(alice_shared_secret).decode()[:30]}...")
    print(f"Общий секрет Боба:  {base64.b64encode(bob_shared_secret).decode()[:30]}...")
    print(f"Секреты совпадают: {alice_shared_secret == bob_shared_secret}")
    
    # Демонстрация использования общего секрета
    derived_key_alice = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'key-exchange',
        backend=default_backend()
    ).derive(alice_shared_secret)
    
    derived_key_bob = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'key-exchange', 
        backend=default_backend()
    ).derive(bob_shared_secret)
    
    print(f"Производный ключ Алисы: {base64.b64encode(derived_key_alice).decode()[:30]}...")
    print(f"Производный ключ Боба:  {base64.b64encode(derived_key_bob).decode()[:30]}...")
    print(f"Ключи совпадают: {derived_key_alice == derived_key_bob}")

if __name__ == "__main__":
    # Установка необходимой библиотеки
    # pip install cryptography
    
    demonstrate_rsa_ecc()
    compare_performance() 
    demonstrate_key_exchange()
    
    print("\n" + "=" * 70)
    print("ВЫВОДЫ:")
    print("- RSA: Подходит для шифрования небольших данных, цифровых подписей")
    print("- ECC: Эффективнее по производительности и размеру ключей")
    print("- ECDH: Идеален для безопасного обмена ключами")
    print("- ECC подписи значительно меньше RSA подписей")
    print("=" * 70)
