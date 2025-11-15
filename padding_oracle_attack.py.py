from binascii import unhexlify, hexlify
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

BLOCK_SIZE = 16  # AES block size is 16 bytes
KEY = b"this_is_16_bytes"

# Ciphertext = IV + encrypted blocks (from check_decrypt.py success)
CIPHERTEXT_HEX = (
    "746869735f69735f31365f6279746573"
    "9404628dcdf3f003482b3b0648bd920b"
    "3f60e13e89fa6950d3340adbbbb41c12"
    "b3d1d97ef97860e9df7ec0d31d13839a"
    "e17b3be8f69921a07627021af16430e1"
)


def padding_oracle(ciphertext: bytes) -> bool:
    """Returns True if the ciphertext decrypts with valid padding, False otherwise."""
    if len(ciphertext) % BLOCK_SIZE != 0:
        return False

    try:
        iv = ciphertext[:BLOCK_SIZE]
        ct = ciphertext[BLOCK_SIZE:]
        cipher = Cipher(algorithms.AES(KEY), modes.CBC(iv))
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(ct) + decryptor.finalize()

        unpadder = padding.PKCS7(BLOCK_SIZE * 8).unpadder()
        unpadder.update(decrypted)
        unpadder.finalize()
        return True
    except (ValueError, TypeError):
        return False


# ============================================================================
# TASK 2: Implement Block Splitting
# ============================================================================
def split_blocks(data: bytes, block_size: int = BLOCK_SIZE) -> list[bytes]:
    """Split data into blocks of the specified size."""
    blocks = []
    for i in range(0, len(data), block_size):
        blocks.append(data[i:i + block_size])
    return blocks


# ============================================================================
# TASK 3: Implement Single Block Decryption
# ============================================================================
def decrypt_block(prev_block: bytes, target_block: bytes) -> bytes:
    """
    Decrypt a single block using the padding oracle attack.
    Returns the decrypted plaintext block.

    Algorithm:
    1. Work backwards from last byte to first byte
    2. For each byte position:
       - Try all 256 possible byte values
       - Find the value that produces valid PKCS#7 padding
       - Calculate the intermediate value
       - XOR intermediate with previous block to get plaintext
    """
    # Initialize intermediate state (what we get after AES decryption, before XOR)
    intermediate = bytearray(BLOCK_SIZE)

    # Process bytes from right to left (last byte first)
    # padding_value represents the PKCS#7 padding we're trying to create
    for padding_value in range(1, BLOCK_SIZE + 1):
        # Current position we're attacking (counting from left)
        position = BLOCK_SIZE - padding_value

        # Create a modified version of the previous block
        # This will be used to manipulate what the oracle sees
        modified_prev = bytearray(BLOCK_SIZE)

        # Set bytes we've already discovered to produce correct padding
        # For example, if padding_value=3, we want the last 3 bytes to be [0x03, 0x03, 0x03]
        for i in range(position + 1, BLOCK_SIZE):
            # XOR the intermediate value with desired padding to get the modified byte
            modified_prev[i] = intermediate[i] ^ padding_value

        # Try all possible byte values (0-255) for current position
        found = False
        for guess in range(256):
            modified_prev[position] = guess

            # Create test ciphertext: our modified block + target block
            test_ciphertext = bytes(modified_prev) + target_block

            # Query the padding oracle
            if padding_oracle(test_ciphertext):
                # Valid padding found!
                # Calculate intermediate value: guess XOR padding_value
                intermediate[position] = guess ^ padding_value
                found = True

                # Special case: when padding_value == 1, we need to verify
                # This prevents false positives (e.g., confusing 0x01 with 0x02 0x02)
                if padding_value == 1 and position > 0:
                    # Verify by changing second-to-last byte
                    test_prev = bytearray(modified_prev)
                    test_prev[position - 1] ^= 1  # Flip a bit
                    test_ct = bytes(test_prev) + target_block

                    # If padding is still valid, we might have 0x02 0x02, not 0x01
                    if not padding_oracle(test_ct):
                        # Confirmed: we have genuine 0x01 padding
                        break
                    else:
                        # False positive, continue searching
                        continue
                break

        if not found:
            raise Exception(f"Failed to find valid padding at position {position}")

    # Now we have the full intermediate state
    # XOR it with the previous block to recover plaintext
    plaintext = bytes([intermediate[i] ^ prev_block[i] for i in range(BLOCK_SIZE)])
    return plaintext


# ============================================================================
# TASK 4: Implement Full Attack
# ============================================================================
def padding_oracle_attack(ciphertext: bytes) -> bytes:
    """Perform the padding oracle attack on the entire ciphertext."""
    # Split ciphertext into blocks
    blocks = split_blocks(ciphertext)

    print(f"[*] Total blocks (including IV): {len(blocks)}")
    print(f"[*] Number of encrypted blocks to decrypt: {len(blocks) - 1}")

    plaintext_blocks = []

    # Decrypt each block (skip the IV, which is blocks[0])
    # Start from block 1 (first encrypted block)
    for i in range(1, len(blocks)):
        print(f"\n[*] Decrypting block {i}/{len(blocks) - 1}...")

        prev_block = blocks[i - 1]  # Previous block (IV for first block)
        target_block = blocks[i]  # Block we want to decrypt

        # Perform padding oracle attack on this block
        decrypted_block = decrypt_block(prev_block, target_block)
        plaintext_blocks.append(decrypted_block)

        print(f"    Decrypted (hex): {decrypted_block.hex()}")
        print(f"    Decrypted (raw): {decrypted_block}")

    # Combine all decrypted blocks into final plaintext
    full_plaintext = b''.join(plaintext_blocks)
    return full_plaintext


# ============================================================================
# TASK 5: Implement Plaintext Decoding
# ============================================================================
def unpad_and_decode(plaintext: bytes) -> str:
    """Attempt to unpad and decode the plaintext."""
    try:
        # Remove PKCS#7 padding
        unpadder = padding.PKCS7(BLOCK_SIZE * 8).unpadder()
        unpadded = unpadder.update(plaintext) + unpadder.finalize()

        # Decode bytes to UTF-8 string
        decoded = unpadded.decode('utf-8')
        return decoded

    except Exception as e:
        print(f"[!] Error during unpadding/decoding: {e}")

        # Fallback: try to decode without unpadding
        try:
            return plaintext.decode('utf-8', errors='replace')
        except:
            # Last resort: return as string representation
            return str(plaintext)


# ============================================================================
# MAIN EXECUTION
# ============================================================================
if __name__ == "__main__":
    try:
        # Convert hex string to bytes
        ciphertext = unhexlify(CIPHERTEXT_HEX)

        print("=" * 70)
        print("PADDING ORACLE ATTACK - Starting Attack")
        print("=" * 70)
        print(f"[*] Ciphertext length: {len(ciphertext)} bytes")
        print(f"[*] IV: {ciphertext[:BLOCK_SIZE].hex()}")

        # Perform the attack
        recovered = padding_oracle_attack(ciphertext)

        print("\n" + "=" * 70)
        print("[+] Decryption complete!")
        print("=" * 70)
        print(f"    Recovered plaintext (raw bytes): {recovered}")
        print(f"    Hex: {recovered.hex()}")

        # Decode the plaintext
        decoded = unpad_and_decode(recovered)

        print("\n" + "=" * 70)
        print("FINAL PLAINTEXT:")
        print("=" * 70)
        print(decoded)
        print("=" * 70)

    except Exception as e:
        print(f"\n[!] Error occurred: {e}")
        import traceback

        traceback.print_exc()