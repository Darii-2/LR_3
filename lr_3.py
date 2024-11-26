import socket
import os
import datetime
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import CertificateBuilder, Name, NameOID

# Константи
SERVER_IP = "127.0.0.1"
SERVER_PORT = 5555

# Функції для роботи з ключами
def save_key_to_file(key, filename):
    with open(filename, "wb") as key_file:
        key_file.write(key)

def load_key_from_file(filename):
    with open(filename, "rb") as key_file:
        return key_file.read()

# Генерація ключів
def generate_private_key(curve, key_filename):
    private_key = ec.generate_private_key(curve)
    save_key_to_file(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ), key_filename)
    return private_key

def generate_public_key(private_key):
    return private_key.public_key()

def save_public_key_to_file(public_key, filename):
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    save_key_to_file(public_key_bytes, filename)

def load_private_key(key_filename):
    private_key_bytes = load_key_from_file(key_filename)
    return serialization.load_pem_private_key(private_key_bytes, password=None)

def derive_symmetric_key(shared_secret):
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"handshake data"
    ).derive(shared_secret)

# Шифрування та дешифрування
def encrypt_message(key, message):
    nonce = os.urandom(12)  # Генерація нового nonce для кожного повідомлення
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message) + encryptor.finalize()
    return nonce, ciphertext, encryptor.tag

def decrypt_message(key, nonce, ciphertext, tag):
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

# Створення Центру Сертифікації (CA)
def create_ca():
    # Генерація приватного ключа для CA
    private_key = generate_private_key(ec.SECP256R1(), "ca_private_key.pem")
    public_key = private_key.public_key()

    # Створення атрибутів для сертифікату
    subject = issuer = Name([ 
        NameOID.COUNTRY_NAME, "UA", 
        NameOID.STATE_OR_PROVINCE_NAME, "Kyiv", 
        NameOID.ORGANIZATION_NAME, "Simple CA", 
        NameOID.COMMON_NAME, "Simple Root CA"
    ])

    # Створення сертифікату
    certificate = CertificateBuilder().subject_name(subject) \
        .issuer_name(issuer) \
        .public_key(public_key) \
        .serial_number(1000) \
        .not_valid_before(datetime.datetime.utcnow()) \
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365)) \
        .sign(private_key, ec.ECDSA(hashes.SHA256()))

    # Збереження сертифікату
    cert_pem = certificate.public_bytes(encoding=serialization.Encoding.PEM)
    save_key_to_file(cert_pem, "ca_cert.pem")

    print("[CA] Центр сертифікації створено.")
    return private_key, cert_pem

# Сервер
def server():
    try:
        # Генерація приватного та публічного ключів сервера
        server_private_key = generate_private_key(ec.SECP256R1(), "server_private_key.pem")
        server_public_key = generate_public_key(server_private_key)
        save_public_key_to_file(server_public_key, "server_public_key.pem")

        # Відкриття сокету
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((SERVER_IP, SERVER_PORT))
        server_socket.listen(1)
        print(f"[Server] Запущено сервер на {SERVER_IP}:{SERVER_PORT}")

        conn, addr = server_socket.accept()
        print(f"[Server] З'єднано з {addr}")

        # Відправка публічного ключа сервера
        server_public_key_bytes = server_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        conn.sendall(server_public_key_bytes)

        # Отримання публічного ключа клієнта
        client_public_key_bytes = conn.recv(1024)
        client_public_key = serialization.load_pem_public_key(client_public_key_bytes)

        # Генерація спільного ключа
        shared_secret = server_private_key.exchange(ec.ECDH(), client_public_key)
        symmetric_key = derive_symmetric_key(shared_secret)
        print("[Server] Спільний ключ узгоджено.")

        # Збереження симетричного ключа в файл
        save_key_to_file(symmetric_key, "symmetric_key_server.pem")
        print("[Server] Симетричний ключ збережено.")

        # Після успішного рукостискання встановлюється захищений канал
        while True:
            encrypted_message = conn.recv(4096)
            if not encrypted_message:
                break
            nonce, ciphertext, tag = encrypted_message[:12], encrypted_message[12:-16], encrypted_message[-16:]
            message = decrypt_message(symmetric_key, nonce, ciphertext, tag)
            print(f"[Server] Отримано: {message.decode('utf-8')}")

            # Відправка підтвердження
            response = "Повідомлення отримано".encode("utf-8")
            nonce, ciphertext, tag = encrypt_message(symmetric_key, response)
            conn.sendall(nonce + ciphertext + tag)

        conn.close()
        server_socket.close()
    except Exception as e:
        print(f"[Server] Помилка: {e}")

# Клієнт
def client():
    try:
        # Генерація приватного та публічного ключів клієнта
        client_private_key = generate_private_key(ec.SECP256R1(), "client_private_key.pem")
        client_public_key = generate_public_key(client_private_key)
        save_public_key_to_file(client_public_key, "client_public_key.pem")

        # Відкриття сокету
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((SERVER_IP, SERVER_PORT))
        print("[Client] Підключено до сервера")

        # Отримання публічного ключа сервера
        server_public_key_bytes = client_socket.recv(1024)
        server_public_key = serialization.load_pem_public_key(server_public_key_bytes)

        # Відправка публічного ключа клієнта
        client_public_key_bytes = client_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        client_socket.sendall(client_public_key_bytes)

        # Генерація спільного ключа
        shared_secret = client_private_key.exchange(ec.ECDH(), server_public_key)
        symmetric_key = derive_symmetric_key(shared_secret)
        print("[Client] Спільний ключ узгоджено.")

        # Збереження симетричного ключа в файл
        save_key_to_file(symmetric_key, "symmetric_key_client.pem")
        print("[Client] Симетричний ключ збережено.")

        # Після успішного рукостискання встановлюється захищений канал
        while True:
            message = input("Введіть повідомлення (або 'exit' для виходу): ")
            if message.lower() == "exit":
                break

            # Відправка зашифрованого повідомлення
            nonce, ciphertext, tag = encrypt_message(symmetric_key, message.encode('utf-8'))
            client_socket.sendall(nonce + ciphertext + tag)

            # Отримання відповіді від сервера
            encrypted_response = client_socket.recv(4096)
            nonce, ciphertext, tag = encrypted_response[:12], encrypted_response[12:-16], encrypted_response[-16:]
            response = decrypt_message(symmetric_key, nonce, ciphertext, tag)
            print(f"[Client] Відповідь від сервера: {response.decode('utf-8')}")

        client_socket.close()
    except Exception as e:
        print(f"[Client] Помилка: {e}")

# Запуск
if __name__ == "__main__":
    mode = input("Виберіть режим (server/client): ").strip().lower()
    if mode == "server":
        server()
    elif mode == "client":
        client()
    else:
        print("Невірний вибір.")
