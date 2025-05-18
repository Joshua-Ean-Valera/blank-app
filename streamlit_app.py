# Joshua Ean
import streamlit as st
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding as asy_padding
import hashlib
import base64
import io
from Crypto.Random.random import getrandbits

st.title("Applied Cryptography Application")

menu = [
    "Symmetric Encryption/Decryption",
    "Asymmetric Encryption/Decryption",
    "Hashing Functions",
    "Algorithm Informations"
]
choice = st.sidebar.selectbox("Navigation", menu)

# --- Helper Functions ---

def pad(text, block_size):
    pad_len = block_size - len(text) % block_size
    return text + chr(pad_len) * pad_len

def unpad(text):
    pad_len = ord(text[-1])
    return text[:-pad_len]

def aes_encrypt(key, plaintext):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(plaintext, AES.block_size).encode())
    return base64.b64encode(cipher.iv + ct_bytes).decode()

def aes_decrypt(key, ciphertext):
    raw = base64.b64decode(ciphertext)
    iv = raw[:AES.block_size]
    ct = raw[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = cipher.decrypt(ct).decode()
    return unpad(pt)

# --- RC4 Stream Cipher Implementation ---
def rc4(key, data):
    S = list(range(256))
    j = 0
    out = []
    key = [ord(c) for c in key]
    # KSA Phase
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    # PRGA Phase
    i = j = 0
    for char in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        K = S[(S[i] + S[j]) % 256]
        out.append(chr(ord(char) ^ K))
    return ''.join(out)

# --- Vigenère Cipher Implementation (with custom alphabet, ignores spaces) ---
def vigenere_encrypt(plaintext, key, alphabet):
    """
    Encrypts plaintext using a Vigenère cipher with a custom alphabet, ignoring spaces during encryption.
    Spaces are preserved in their original positions.
    """
    if len(alphabet) == 0:
        raise ValueError("ValueError: Alphabet cannot be empty")
    if len(set(alphabet)) != len(alphabet):
        raise ValueError("ValueError: Alphabet must contain unique characters")
    if len(key) == 0:
        raise ValueError("ValueError: Key cannot be empty")
    if len(plaintext) == 0:
        raise ValueError("ValueError: Plaintext cannot be empty")
    alphabet_set = set(alphabet)
    invalid_plain = sorted({c for c in plaintext if c not in alphabet_set and c != ' '})
    invalid_key = sorted({c for c in key if c not in alphabet_set})
    if invalid_plain or invalid_key:
        part = ["Invalid characters!"]
        if invalid_plain:
            part.append(f"in plaintext: {', '.join(invalid_plain)}")
        if invalid_key:
            part.append(f"in key: {', '.join(invalid_key)}")
        total_invalid = len(invalid_plain) + len(invalid_key)
        ending = "is not in alphabet" if total_invalid == 1 else "are not in alphabet"
        part.append(ending)
        message = '\n'.join(part)
        raise ValueError(message)
    filtered_plaintext = ''.join([c for c in plaintext if c != ' '])
    extended_key = ''.join([key[i % len(key)] for i in range(len(filtered_plaintext))])
    char_to_index = {char: idx for idx, char in enumerate(alphabet)}
    ciphertext = []
    key_index = 0
    for p_char in plaintext:
        if p_char == ' ':
            ciphertext.append(' ')
        else:
            p_val = char_to_index[p_char]
            k_val = char_to_index[extended_key[key_index]]
            c_val = (p_val + k_val) % len(alphabet)
            ciphertext.append(alphabet[c_val])
            key_index += 1
    return ''.join(ciphertext)

def vigenere_decrypt(ciphertext, key, alphabet):
    """
    Decrypts ciphertext using a Vigenère cipher with a custom alphabet, ignoring spaces during decryption.
    Spaces are preserved in their original positions.
    """
    if len(alphabet) == 0:
        raise ValueError("ValueError: Alphabet cannot be empty")
    if len(set(alphabet)) != len(alphabet):
        raise ValueError("ValueError: Alphabet must contain unique characters")
    if len(key) == 0:
        raise ValueError("ValueError: Key cannot be empty")
    if len(ciphertext) == 0:
        raise ValueError("ValueError: Ciphertext cannot be empty")
    alphabet_set = set(alphabet)
    invalid_cipher = sorted({c for c in ciphertext if c not in alphabet_set and c != ' '})
    invalid_key = sorted({c for c in key if c not in alphabet_set})
    if invalid_cipher or invalid_key:
        part = ["Invalid characters!"]
        if invalid_cipher:
            part.append(f"in ciphertext: {', '.join(invalid_cipher)}")
        if invalid_key:
            part.append(f"in key: {', '.join(invalid_key)}")
        total_invalid = len(invalid_cipher) + len(invalid_key)
        ending = "is not in alphabet" if total_invalid == 1 else "are not in alphabet"
        part.append(ending)
        message = '\n'.join(part)
        raise ValueError(message)
    filtered_ciphertext = ''.join([c for c in ciphertext if c != ' '])
    extended_key = ''.join([key[i % len(key)] for i in range(len(filtered_ciphertext))])
    char_to_index = {char: idx for idx, char in enumerate(alphabet)}
    plaintext = []
    key_index = 0
    for c_char in ciphertext:
        if c_char == ' ':
            plaintext.append(' ')
        else:
            c_val = char_to_index[c_char]
            k_val = char_to_index[extended_key[key_index]]
            p_val = (c_val - k_val) % len(alphabet)
            plaintext.append(alphabet[p_val])
            key_index += 1
    return ''.join(plaintext)

def rsa_generate_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def rsa_encrypt(public_key, plaintext):
    key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(key)
    ct = cipher.encrypt(plaintext.encode())
    return base64.b64encode(ct).decode()

def rsa_decrypt(private_key, ciphertext):
    key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(key)
    pt = cipher.decrypt(base64.b64decode(ciphertext))
    return pt.decode()

def ecc_generate_keys():
    private_key = ec.generate_private_key(ec.SECP384R1())
    public_key = private_key.public_key()
    priv_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return priv_bytes, pub_bytes

def ecc_encrypt(public_key_pem, plaintext):
    # ECC is not typically used for direct encryption, but for demonstration, we'll simulate with ECDH + symmetric
    public_key = serialization.load_pem_public_key(public_key_pem)
    ephemeral_key = ec.generate_private_key(ec.SECP384R1())
    shared_key = ephemeral_key.exchange(ec.ECDH(), public_key)
    aes_key = hashlib.sha256(shared_key).digest()
    cipher = AES.new(aes_key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(plaintext, AES.block_size).encode())
    return base64.b64encode(cipher.iv + ct_bytes + ephemeral_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )).decode()

def ecc_decrypt(private_key_pem, ciphertext):
    # Simulate ECC decryption as above
    raw = base64.b64decode(ciphertext)
    iv = raw[:AES.block_size]
    ct = raw[AES.block_size:-215]  # 215 is length of PEM public key for SECP384R1
    ephemeral_pub_pem = raw[-215:]
    private_key = serialization.load_pem_private_key(private_key_pem, password=None)
    ephemeral_pub = serialization.load_pem_public_key(ephemeral_pub_pem)
    shared_key = private_key.exchange(ec.ECDH(), ephemeral_pub)
    aes_key = hashlib.sha256(shared_key).digest()
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    pt = cipher.decrypt(ct).decode()
    return unpad(pt)

def hash_text(text, algo):
    h = hashlib.new(algo)
    h.update(text.encode())
    return h.hexdigest()

def hash_file(file, algo):
    h = hashlib.new(algo)
    for chunk in iter(lambda: file.read(4096), b""):
        h.update(chunk)
    file.seek(0)
    return h.hexdigest()

# --- Diffie-Hellman Implementation ---
def dh_generate_params():
    # Use a small safe prime for demonstration (not secure for real use)
    p = 0xE95E4A5F737059DC60DFC7AD95B3D8139515620F
    g = 2
    return p, g

def dh_generate_private_key(p):
    return getrandbits(128) % p

def dh_generate_public_key(g, private_key, p):
    return pow(g, private_key, p)

def dh_compute_shared_secret(peer_public, private_key, p):
    return pow(peer_public, private_key, p)

def dh_shared_secret_to_aes_key(shared_secret):
    # Derive a 32-byte AES key from shared secret
    return hashlib.sha256(str(shared_secret).encode()).digest()

# --- XOR Block Cipher Implementation (Block size = 8, key = 8 chars) ---
def pad_message(message, block_size=8, padding_char='_'):
    padding_length = (block_size - len(message) % block_size) % block_size
    return message + (padding_char * padding_length)

def remove_padding(message, padding_char='_'):
    return message.rstrip(padding_char)

def xor_operation(block, key):
    return [ord(b) ^ ord(k) for b, k in zip(block, key)]

def xor_block_encrypt(text, key):
    text = pad_message(text)
    result = []
    for i in range(0, len(text), 8):
        block = text[i:i+8]
        encrypted_block = xor_operation(block, key)
        result.extend(encrypted_block)
    return ' '.join(format(byte, '02X') for byte in result)

def xor_block_decrypt(hex_text, key):
    try:
        hex_values = [int(h, 16) for h in hex_text.split()]
    except ValueError:
        return "Error: Invalid hex input for decryption"
    result = []
    for i in range(0, len(hex_values), 8):
        block = hex_values[i:i+8]
        decrypted_block = ''.join(chr(b ^ ord(k)) for b, k in zip(block, key))
        result.append(decrypted_block)
    return remove_padding(''.join(result))

# --- Caesar Cipher (multi-key) Implementation ---
def caesar_encrypt_decrypt(text, shift_keys, ifdecrypt, show_report=False):
    """
    Encrypts or decrypts text using Caesar Cipher with a list of shift keys.
    If show_report is True, returns (result_string, report_string).
    Otherwise, returns result_string.
    """
    result = []
    report_lines = []
    shift_keys_len = len(shift_keys)
    for i, char in enumerate(text):
        if 32 <= ord(char) <= 126:
            shift = shift_keys[i % shift_keys_len]
            effective_shift = -shift if ifdecrypt else shift
            shifted_char = chr((ord(char) - 32 + effective_shift) % 94 + 32)
            result.append(shifted_char)
            if show_report:
                report_lines.append(f"{i} {char} {shift} {shifted_char}")
        else:
            result.append(char)
            if show_report:
                report_lines.append(f"{i} {char} (no shift) {char}")
    if show_report:
        report_lines.append("----------")
        return ''.join(result), '\n'.join(report_lines)
    else:
        return ''.join(result)

# --- Custom RSA Implementation (educational, not secure for real use) ---
import random
from math import gcd

def is_prime(num):
    if num == 2:
        return True
    if num < 2 or num % 2 == 0:
        return False
    for n in range(3, int(num**0.5)+2, 2):
        if num % n == 0:
            return False
    return True

def generate_prime_number():
    while True:
        prime_candidate = random.randint(2**8, 2**9)
        if is_prime(prime_candidate):
            return prime_candidate

def rsa_generate_keypair_custom():
    p = generate_prime_number()
    q = generate_prime_number()
    n = p * q
    totient = (p - 1) * (q - 1)
    e = random.randrange(1, totient)
    g = gcd(e, totient)
    while g != 1:
        e = random.randrange(1, totient)
        g = gcd(e, totient)
    d = pow(e, -1, totient)
    # Return as dict for clarity
    return {
        "p": p,
        "q": q,
        "n": n,
        "totient": totient,
        "e": e,
        "d": d,
        "public": (e, n),
        "private": (d, n)
    }

def rsa_encrypt_custom(pk, plaintext):
    key, n = pk
    cipher = [pow(ord(char), key, n) for char in plaintext]
    return cipher

def rsa_decrypt_custom(pk, ciphertext):
    key, n = pk
    plain = [chr(pow(char, key, n)) for char in ciphertext]
    return ''.join(plain)

def rsa_ciphertext_to_str(cipher):
    return ' '.join(str(num) for num in cipher)

def rsa_str_to_cipher(cipher_str):
    try:
        return [int(x) for x in cipher_str.strip().split()]
    except Exception:
        return []

# --- Diffie-Hellman Implementation (simple, small primes, educational) ---
def dh_power(a, b, p):
    # Returns a^b mod p
    return pow(a, b, p)

def dh_demo_generate_keys(P, G, a, b):
    # Returns (x, y, ka, kb)
    x = dh_power(G, a, P)
    y = dh_power(G, b, P)
    ka = dh_power(y, a, P)
    kb = dh_power(x, b, P)
    return x, y, ka, kb

# --- UI Logic ---

if choice == "Symmetric Encryption/Decryption":
    st.header("Symmetric Encryption/Decryption")
    tab1, tab2 = st.tabs(["Text", "File"])
    with tab1:
        algo = st.selectbox("Algorithm", ["Block Cipher (XOR)", "Caesar Cipher (multi-key)", "Vigenère Cipher"])
        mode = st.radio("Mode", ["Encrypt", "Decrypt"])
        text = st.text_area("Text")
        if algo == "Block Cipher (XOR)":
            key = st.text_input("Key (exactly 8 characters)", value="my8chark")
            if st.button("Run"):
                if len(key) != 8:
                    st.error("Key must be exactly 8 characters")
                else:
                    try:
                        if mode == "Encrypt":
                            result = xor_block_encrypt(text, key)
                        else:
                            result = xor_block_decrypt(text, key)
                        st.code(result)
                    except Exception as e:
                        st.error(str(e))
        elif algo == "Caesar Cipher (multi-key)":
            shift_keys_str = st.text_input("Shift Keys (space-separated integers)", value="3 1 4")
            try:
                shift_keys = list(map(int, shift_keys_str.strip().split()))
            except Exception:
                shift_keys = []
            if st.button("Run"):
                if len(shift_keys) < 2 or len(shift_keys) > len(text):
                    st.error("Shift keys length must be between 2 and the length of the text.")
                else:
                    try:
                        if mode == "Encrypt":
                            cipher_text, enc_report = caesar_encrypt_decrypt(text, shift_keys, ifdecrypt=False, show_report=True)
                            decrypted_text, dec_report = caesar_encrypt_decrypt(cipher_text, shift_keys, ifdecrypt=True, show_report=True)
                            enc_title = "Encryption Steps"
                            dec_title = "Decryption Steps"
                        else:
                            cipher_text, enc_report = caesar_encrypt_decrypt(text, shift_keys, ifdecrypt=True, show_report=True)
                            decrypted_text, dec_report = caesar_encrypt_decrypt(cipher_text, shift_keys, ifdecrypt=False, show_report=True)
                            enc_title = "Decryption Steps"
                            dec_title = "Encryption Steps (Re-Encrypt)"
                        # Present results in a more readable, styled way
                        st.markdown(f"### {enc_title}")
                        st.markdown(f"<pre style='background:#f6f8fa;border-radius:6px;padding:10px'>{enc_report}</pre>", unsafe_allow_html=True)
                        st.markdown(f"### {dec_title}")
                        st.markdown(f"<pre style='background:#f6f8fa;border-radius:6px;padding:10px'>{dec_report}</pre>", unsafe_allow_html=True)
                        st.markdown("---")
                        st.markdown(f"<b>Text:</b> <code>{text}</code>", unsafe_allow_html=True)
                        st.markdown(f"<b>Shift keys:</b> <code>{' '.join(map(str, shift_keys))}</code>", unsafe_allow_html=True)
                        st.markdown(f"<b>Cipher:</b> <code>{cipher_text}</code>", unsafe_allow_html=True)
                        st.markdown(f"<b>Decrypted text:</b> <code>{decrypted_text}</code>", unsafe_allow_html=True)
                    except Exception as e:
                        st.error(str(e))
        elif algo == "Vigenère Cipher":
            alphabet = st.text_input("Alphabet (unique chars, e.g. ZYXWVUTSRQPONMLKJIHGFEDCBA)", value="ZYXWVUTSRQPONMLKJIHGFEDCBA")
            key = st.text_input("Vigenère Key (letters only)", value="KEY")
            if st.button("Run"):
                try:
                    if mode == "Encrypt":
                        result = vigenere_encrypt(text, key, alphabet)
                    else:
                        result = vigenere_decrypt(text, key, alphabet)
                    st.code(result)
                except Exception as e:
                    st.error(str(e))
    with tab2:
        algo = st.selectbox("Algorithm (File)", ["Block Cipher (XOR)", "Caesar Cipher (multi-key)", "Vigenère Cipher"])
        mode = st.radio("Mode (File)", ["Encrypt", "Decrypt"])
        uploaded_file = st.file_uploader("Upload File", type=None)
        if uploaded_file:
            if algo == "Block Cipher (XOR)":
                key = st.text_input("Key (exactly 8 characters)", value="my8chark", key="file_xor_key")
                if st.button("Run File Crypto", key="file_xor_btn"):
                    if len(key) != 8:
                        st.error("Key must be exactly 8 characters")
                    else:
                        try:
                            file_bytes = uploaded_file.read()
                            text = file_bytes.decode(errors='ignore')
                            if mode == "Encrypt":
                                out = xor_block_encrypt(text, key)
                                out_bytes = out.encode()
                            else:
                                out = xor_block_decrypt(text, key)
                                out_bytes = out.encode()
                            st.download_button("Download Result", data=out_bytes, file_name="result.txt", key="file_xor_download")
                            st.text_area("File Content Preview", text, height=150, key="file_xor_preview")
                        except Exception as e:
                            st.error(str(e))
            elif algo == "Caesar Cipher (multi-key)":
                shift_keys_str = st.text_input("Shift Keys (space-separated integers)", value="3 1 4", key="file_caesar_keys")
                if st.button("Run File Crypto", key="file_caesar_btn"):
                    try:
                        shift_keys = list(map(int, shift_keys_str.strip().split()))
                        file_bytes = uploaded_file.read()
                        text = file_bytes.decode(errors='ignore')
                        if len(shift_keys) < 2 or len(shift_keys) > len(text):
                            st.error("Shift keys length must be between 2 and the length of the file content.")
                        else:
                            if mode == "Encrypt":
                                out = caesar_encrypt_decrypt(text, shift_keys, ifdecrypt=False)
                            else:
                                out = caesar_encrypt_decrypt(text, shift_keys, ifdecrypt=True)
                            st.download_button("Download Result", data=out.encode(), file_name="result.txt", key="file_caesar_download")
                            st.text_area("File Content Preview", text, height=150, key="file_caesar_preview")
                    except Exception as e:
                        st.error(str(e))
            elif algo == "Vigenère Cipher":
                alphabet = st.text_input("Alphabet (unique chars, e.g. ZYXWVUTSRQPONMLKJIHGFEDCBA)", value="ZYXWVUTSRQPONMLKJIHGFEDCBA", key="file_vigenere_alphabet")
                key = st.text_input("Vigenère Key (letters only)", value="KEY", key="file_vigenere_key")
                if st.button("Run File Crypto", key="file_vigenere_btn"):
                    try:
                        file_bytes = uploaded_file.read()
                        text = file_bytes.decode(errors='ignore')
                        if mode == "Encrypt":
                            out = vigenere_encrypt(text, key, alphabet)
                        else:
                            out = vigenere_decrypt(text, key, alphabet)
                        st.download_button("Download Result", data=out.encode(), file_name="result.txt", key="file_vigenere_download")
                        st.text_area("File Content Preview", text, height=150, key="file_vigenere_preview")
                    except Exception as e:
                        st.error(str(e))

elif choice == "Asymmetric Encryption/Decryption":
    st.header("Asymmetric Encryption/Decryption")
    algo = st.selectbox("Algorithm", ["RSA (PyCryptodome)", "Diffie-Hellman"])
    mode = st.radio("Mode", ["Encrypt", "Decrypt"])
    text = st.text_area("Text")
    if algo == "RSA (PyCryptodome)":
        priv, pub = st.columns(2)
        with priv:
            if 'rsa_priv_val' not in st.session_state:
                st.session_state['rsa_priv_val'] = ""
            if 'rsa_pub_val' not in st.session_state:
                st.session_state['rsa_pub_val'] = ""
            private_key = st.text_area("Private Key (PEM)", height=150, value=st.session_state['rsa_priv_val'], key="rsa_priv_pem")
            if st.button("Generate RSA Keys"):
                priv_key, pub_key = rsa_generate_keys()
                st.session_state['rsa_priv_val'] = priv_key.decode()
                st.session_state['rsa_pub_val'] = pub_key.decode()
                try:
                    st.rerun()
                except AttributeError:
                    import streamlit as stlib
                    if hasattr(stlib, "experimental_rerun"):
                        stlib.experimental_rerun()
        with pub:
            public_key = st.text_area("Public Key (PEM)", height=150, value=st.session_state['rsa_pub_val'], key="rsa_pub_pem")
        if st.button("Run RSA"):
            try:
                if mode == "Encrypt":
                    result = rsa_encrypt(public_key, text)
                else:
                    result = rsa_decrypt(private_key, text)
                st.code(result)
            except Exception as e:
                st.error(str(e))
    elif algo == "Diffie-Hellman":
        st.markdown("#### Diffie-Hellman Key Exchange (educational, small primes)")
        # Default values for demonstration
        P = st.number_input("Prime number P", min_value=3, value=23, step=1)
        G = st.number_input("Primitive root G", min_value=2, value=9, step=1)
        a = st.number_input("Alice's private key (a)", min_value=1, value=4, step=1)
        b = st.number_input("Bob's private key (b)", min_value=1, value=3, step=1)
        if st.button("Run DH Demo"):
            x, y, ka, kb = dh_demo_generate_keys(P, G, a, b)
            st.markdown(f"**The value of P:** {P}")
            st.markdown(f"**The value of G:** {G}")
            st.markdown(f"**The private key a for Alice:** {a}")
            st.markdown(f"**The private key b for Bob:** {b}")
            st.markdown(f"**Alice computes:** x = G^a mod P = {G}^{a} mod {P} = {x}")
            st.markdown(f"**Bob computes:** y = G^b mod P = {G}^{b} mod {P} = {y}")
            st.markdown(f"**Alice computes secret key:** ka = y^a mod P = {y}^{a} mod {P} = {ka}")
            st.markdown(f"**Bob computes secret key:** kb = x^b mod P = {x}^{b} mod {P} = {kb}")
            if ka == kb:
                st.success(f"Shared secret established: {ka}")
            else:
                st.error("Shared secrets do not match!")

elif choice == "Hashing Functions":
    st.header("Hashing")
    tab1, tab2 = st.tabs(["Text", "File"])
    with tab1:
        algo = st.selectbox("Algorithm", ["sha256", "sha512", "md5", "sha1"])
        text = st.text_area("Text to Hash")
        if st.button("Hash Text"):
            try:
                result = hash_text(text, algo)
                st.code(result)
            except Exception as e:
                st.error(str(e))
    with tab2:
        algo = st.selectbox("Algorithm (File)", ["sha256", "sha512", "md5", "sha1"])
        uploaded_file = st.file_uploader("Upload File for Hashing", type=None, key="hashfile")
        if uploaded_file and st.button("Hash File"):
            try:
                # Preview file content (first 500 chars for safety)
                file_bytes = uploaded_file.read()
                preview_text = file_bytes[:500].decode(errors="ignore")
                st.text_area("File Content Preview", preview_text, height=150, key="hash_file_preview")
                uploaded_file.seek(0)
                result = hash_file(uploaded_file, algo)
                # (do not delete) st.code(result)
                st.download_button(
                    "Download Result",
                    data=result.encode(),
                    file_name="hash_result.txt",
                    key="hash_file_download"
                )
            except Exception as e:
                st.error(str(e))

elif choice == "Algorithm Informations":
    st.header("Algorithm Information")
    st.subheader("Symmetric Algorithms")
    st.markdown("""
- **Block Cipher (AES)**: Advanced Encryption Standard, widely used block cipher, 128/192/256-bit keys.
- **Stream Cipher (RC4)**: Rivest Cipher 4, stream cipher, variable key length, fast but not recommended for new systems.
- **Vigenère Cipher**: Classic polyalphabetic substitution cipher using a keyword for shifting letters, mainly of historical interest.
    """)
    st.subheader("Asymmetric Algorithms")
    st.markdown("""
- **RSA**: Rivest–Shamir–Adleman, public-key cryptosystem, widely used for secure data transmission.
- **Diffie-Hellman**: Key exchange protocol for establishing a shared secret over an insecure channel, often used to derive symmetric keys.
    """)
    st.subheader("Hashing Functions")
    st.markdown("""
- **SHA-256**: Secure Hash Algorithm 256-bit, widely used for integrity.
- **SHA-512**: Secure Hash Algorithm 512-bit, stronger variant.
- **MD5**: Message Digest 5, fast but not collision-resistant.
- **SHA-1**: Secure Hash Algorithm 1, legacy, not recommended for security.
    """)
    st.subheader("References")
    st.markdown("""
- [PyCryptodome](https://www.pycryptodome.org/)
- [cryptography](https://cryptography.io/)
- [hashlib](https://docs.python.org/3/library/hashlib.html)
    """)
