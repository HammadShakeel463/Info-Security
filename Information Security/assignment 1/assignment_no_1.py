# AES S-box and Rcon tables
SBox = (
    # S-box substitution values
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
)

Rcon = (
    # Rcon values for key expansion
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A, 0x2F
)

# AES key expansion
def key_expansion(key):
    key_schedule = [key[i:i + 4] for i in range(0, len(key), 4)]

    for i in range(len(key_schedule), 4 * 11):
        temp = key_schedule[i - 1]
        if i % 4 == 0:
            temp = [SBox[temp[j]] for j in range(4)]
            temp[0] ^= Rcon[i // 4 - 1]
        key_schedule.append([key_schedule[i - 4][j] ^ temp[j] for j in range(4)])

    return key_schedule

# AES substitution step (Byte Substitution)
def sub_bytes(state):
    return [[SBox[state[i][j]] for j in range(4)] for i in range(4)]

# AES shift rows step
def shift_rows(state):
    for i in range(1, 4):
        state[i] = state[i][i:] + state[i][:i]
    return state

# AES mix columns step
def mix_columns(state):
    def mix_column(column):
        temp = column.copy()
        column[0] = (
            (temp[0] << 1) ^ (temp[1] ^ (temp[1] << 1) ^ (temp[1] << 2) ^ (temp[1] << 3)) ^
            (temp[2] ^ (temp[2] << 1) ^ (temp[2] << 2) ^ (temp[2] << 3) ^ (temp[3] << 3))
        ) & 0xFF
        column[1] = (
            (temp[1] << 1) ^ (temp[2] ^ (temp[2] << 1) ^ (temp[2] << 2) ^ (temp[2] << 3)) ^
            (temp[3] ^ (temp[3] << 1) ^ (temp[3] << 2) ^ (temp[3] << 3) ^ (temp[0] << 3))
        ) & 0xFF
        column[2] = (
            (temp[2] << 1) ^ (temp[3] ^ (temp[3] << 1) ^ (temp[3] << 2) ^ (temp[3] << 3)) ^
            (temp[0] ^ (temp[0] << 1) ^ (temp[0] << 2) ^ (temp[0] << 3) ^ (temp[1] << 3))
        ) & 0xFF
        column[3] = (
            (temp[3] << 1) ^ (temp[0] ^ (temp[0] << 1) ^ (temp[0] << 2) ^ (temp[0] << 3)) ^
            (temp[1] ^ (temp[1] << 1) ^ (temp[1] << 2) ^ (temp[1] << 3) ^ (temp[2] << 3))
        ) & 0xFF
        return column

    return [mix_column([state[i][j] for i in range(4)]) for j in range(4)]

# AES add round key step
def add_round_key(state, round_key):
    return [[state[i][j] ^ round_key[i][j] for j in range(4)] for i in range(4)]

# AES encryption
def aes_encrypt(plaintext, key):
    key_schedule = key_expansion(key)

    # Pad the plaintext to be a multiple of 16 bytes
    padding_length = 16 - (len(plaintext) % 16)
    plaintext += bytes([padding_length] * padding_length)

    # Split the plaintext into 16-byte blocks
    blocks = [plaintext[i:i + 16] for i in range(0, len(plaintext), 16)]

    encrypted_blocks = []
    for block in blocks:
        state = [[block[i + j * 4] for i in range(4)] for j in range(4)]

        state = add_round_key(state, key_schedule[:4])

        for round_num in range(1, 10):
            state = sub_bytes(state)
            state = shift_rows(state)
            state = mix_columns(state)
            state = add_round_key(state, key_schedule[round_num * 4: (round_num + 1) * 4])

        state = sub_bytes(state)
        state = shift_rows(state)
        state = add_round_key(state, key_schedule[40:])

        ciphertext = [state[i][j] for j in range(4) for i in range(4)]
        encrypted_blocks.append(bytes(ciphertext))

    # Combine the encrypted blocks
    ciphertext = b''.join(encrypted_blocks)
    return ciphertext

# AES decryption
def aes_decrypt(ciphertext, key):
    key_schedule = key_expansion(key)

    # Split the ciphertext into 16-byte blocks
    blocks = [ciphertext[i:i + 16] for i in range(0, len(ciphertext), 16)]

    decrypted_blocks = []
    for block in blocks:
        state = [[block[i + j * 4] for i in range(4)] for j in range(4)]

        state = add_round_key(state, key_schedule[40:])

        for round_num in range(9, 0, -1):
            state = shift_rows(state)
            state = sub_bytes(state)
            state = add_round_key(state, key_schedule[round_num * 4: (round_num + 1) * 4])
            state = mix_columns(state)

        state = shift_rows(state)
        state = sub_bytes(state)
        state = add_round_key(state, key_schedule[:4])

        plaintext = [state[i][j] for j in range(4) for i in range(4)]
        decrypted_blocks.append(bytes(plaintext))

    # Remove the padding from the last block
    padding_length = decrypted_blocks[-1][-1]
    decrypted_blocks[-1] = decrypted_blocks[-1][:-padding_length]

    # Combine the decrypted blocks
    plaintext = b''.join(decrypted_blocks)
    return plaintext

# AES decryption without UTF-8 decoding
def aes_decrypt_hex(ciphertext, key):
    decrypted_text = aes_decrypt(ciphertext, key)
    return decrypted_text.hex()

# AES encryption and decryption for longer texts

# Input text and key
plaintext = input("Enter the plaintext: ").encode()
key = input("Enter the key (16 bytes): ").encode()

# Check input length
if len(key) != 16:
    print("The key must be 16 bytes in length.")
else:
    # Encryption
    ciphertext = aes_encrypt(plaintext, key)
    print("AES Encrypted:", ciphertext.hex())

    # Decryption and print as hexadecimal
    decrypted_hex = aes_decrypt_hex(ciphertext, key)
    print("AES Decrypted (Hex):", decrypted_hex)
