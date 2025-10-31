!pip install pycryptodome

#!/usr/bin/env python3
# multi_cipher_select.py
# Cifrado y descifrado DES, 3DES y AES-256 (modo CBC)
# Requiere: pip install pycryptodome

from Crypto.Cipher import DES, DES3, AES
from Crypto.Random import get_random_bytes
import binascii
import sys

# -------------------------------
# Constantes
# -------------------------------
DES_BLOCK = 8
DES_KEY = 8
TDES_BLOCK = 8
TDES_KEY = 24
AES_BLOCK = 16
AES_KEY = 32

# -------------------------------
# Padding PKCS#7
# -------------------------------
def pad(data: bytes, block_size: int) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len

def unpad(data: bytes, block_size: int) -> bytes:
    if not data or len(data) % block_size != 0:
        raise ValueError("Datos con longitud inválida para unpad.")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > block_size:
        raise ValueError("Padding inválido.")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Padding inválido.")
    return data[:-pad_len]

# -------------------------------
# Utilidades
# -------------------------------
def parse_input_to_bytes(s: str) -> bytes:
    """Convierte texto o cadena hex a bytes."""
    s = s.strip()
    maybe_hex = s[2:] if s.lower().startswith('0x') else s
    if all(c in "0123456789abcdefABCDEF" for c in maybe_hex) and len(maybe_hex) % 2 == 0:
        try:
            return binascii.unhexlify(maybe_hex)
        except binascii.Error:
            pass
    return s.encode('utf-8')

def adjust_key_random(key: bytes, target_len: int, label="Clave") -> bytes:
    """Ajusta la clave a longitud requerida (relleno aleatorio o truncado)."""
    if len(key) < target_len:
        missing = target_len - len(key)
        key += get_random_bytes(missing)
        print(f"[INFO] {label} más corta de {target_len} bytes → completando con {missing} bytes aleatorios.")
    elif len(key) > target_len:
        print(f"[INFO] {label} más larga de {target_len} bytes → truncando.")
        key = key[:target_len]
    print(f"→ {label} final (hex): {binascii.hexlify(key).decode()}")
    return key

def adjust_iv(iv: bytes, block_size: int) -> bytes:
    """Ajusta IV a longitud requerida (relleno o truncado)."""
    if len(iv) < block_size:
        iv += get_random_bytes(block_size - len(iv))
        print(f"[INFO] IV más corto de {block_size} bytes → completando aleatoriamente.")
    elif len(iv) > block_size:
        iv = iv[:block_size]
        print(f"[INFO] IV más largo de {block_size} bytes → truncando.")
    print(f"→ IV final (hex): {binascii.hexlify(iv).decode()}")
    return iv

def bytes_to_hex(b: bytes) -> str:
    return binascii.hexlify(b).decode('ascii')

# -------------------------------
# Funciones de cifrado/descifrado
# -------------------------------
def run_des(plaintext: bytes):
    print("\n[DES]")
    key = parse_input_to_bytes(input("Clave (8 bytes) > "))
    iv = parse_input_to_bytes(input("IV (8 bytes) > "))
    key = adjust_key_random(key, DES_KEY, "Clave DES")
    iv = adjust_iv(iv, DES_BLOCK)
    cipher = DES.new(key, DES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext, DES_BLOCK))
    print("→ Cifrado (hex):", bytes_to_hex(ciphertext))
    decipher = DES.new(key, DES.MODE_CBC, iv)
    decrypted = unpad(decipher.decrypt(ciphertext), DES_BLOCK)
    print("→ Descifrado:", decrypted.decode('utf-8', errors='replace'))

def run_3des(plaintext: bytes):
    print("\n[3DES]")
    key = parse_input_to_bytes(input("Clave (24 bytes) > "))
    iv = parse_input_to_bytes(input("IV (8 bytes) > "))
    key = adjust_key_random(key, TDES_KEY, "Clave 3DES")
    iv = adjust_iv(iv, TDES_BLOCK)
    try:
        key = DES3.adjust_key_parity(key)
    except ValueError:
        key = DES3.adjust_key_parity(get_random_bytes(TDES_KEY))
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext, TDES_BLOCK))
    print("→ Cifrado (hex):", bytes_to_hex(ciphertext))
    decipher = DES3.new(key, DES3.MODE_CBC, iv)
    decrypted = unpad(decipher.decrypt(ciphertext), TDES_BLOCK)
    print("→ Descifrado:", decrypted.decode('utf-8', errors='replace'))

def run_aes(plaintext: bytes):
    print("\n[AES-256]")
    key = parse_input_to_bytes(input("Clave (32 bytes) > "))
    iv = parse_input_to_bytes(input("IV (16 bytes) > "))
    key = adjust_key_random(key, AES_KEY, "Clave AES-256")
    iv = adjust_iv(iv, AES_BLOCK)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext, AES_BLOCK))
    print("→ Cifrado (hex):", bytes_to_hex(ciphertext))
    decipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = unpad(decipher.decrypt(ciphertext), AES_BLOCK)
    print("→ Descifrado:", decrypted.decode('utf-8', errors='replace'))

# -------------------------------
# Menú principal
# -------------------------------
def main():
    print("=== Cifrado/Descifrado CBC (DES, 3DES, AES-256) ===")
    print("Puedes ingresar texto normal o hexadecimal (ej: 0x0123abcd).")
    print("\nOpciones disponibles:")
    print("1. DES")
    print("2. 3DES")
    print("3. AES-256")
    print("4. Ejecutar los tres algoritmos")

    try:
        opcion = int(input("\nSeleccione una opción (1-4): "))
    except ValueError:
        print("Entrada inválida. Debe ser un número del 1 al 4.")
        sys.exit(1)

    texto = input("\nTexto plano a cifrar > ").encode('utf-8')

    if opcion == 1:
        run_des(texto)
    elif opcion == 2:
        run_3des(texto)
    elif opcion == 3:
        run_aes(texto)
    elif opcion == 4:
        run_des(texto)
        run_3des(texto)
        run_aes(texto)
    else:
        print("Opción no válida.")
        sys.exit(1)

    print("\n=== Fin del proceso ===")

if __name__ == "__main__":
    main()
