from stream_ciphers import Trivium, RC4

def hex_to_bits(hex_str:str) -> list[int]:
    """Converts hex string to a list of bits."""

    byte_data = bytes.fromhex(hex_str)
    bits = []
    for byte in byte_data:
        for i in range(8):
            bits.append((byte >> i) & 1)
    return bits

def bits_to_hex(bits:list[int]) -> str:
    """Converts a list of bits to a hex string."""

    hex_str = ''
    for i in range(0, len(bits), 8):
        byte = 0
        for j in range(8):
            if i + j < len(bits):
                byte |= (bits[i + j] << j)
        hex_str += f'{byte:02x}'
    return hex_str

def hex_to_bytes(hex_str:str) -> bytes:
    """Converts hex string to bytes."""
    return bytes.fromhex(hex_str)

def bytes_to_hex(byte_data: list[int]) -> str:
    """Converts bytes to a hex string."""
    return ''.join(f'{byte:02x}' for byte in byte_data)

def Trivium_test():
    KEY_HEX = "0F62B5085BAE0154A7FA"
    IV_HEX = "288FF65DC42B92F960C7"
    EXP_OUT = "A4386C6D7624983FEA8D"

    key_bits = hex_to_bits(KEY_HEX)
    iv_bits = hex_to_bits(IV_HEX)

    key_bits = key_bits[::-1]
    iv_bits = iv_bits[::-1]

    cipher = Trivium(key_bits, iv_bits)
    output_bits = cipher.keystream(80)

    output_hex = bits_to_hex(output_bits)
    print(f"Output: {output_hex}")
    print(f"Expected: {EXP_OUT}")
    assert output_hex.lower() == EXP_OUT.lower(), "Output does not match expected value."
    print("Test passed!")

def RC4_test():
    KEY = b"Key"
    EXP = "EB9F7781B734CA72A719"

    cipher = RC4(KEY, 0)
    keystream = cipher.keystream(10)
    out = bytes_to_hex(keystream)

    print(f"\nTest (Key='Key')")
    print(f"Output:   {out}")
    print(f"Expected: {EXP}")
    assert out.lower() == EXP.lower(), "Test Failed"
    print("Test Passed!")
if __name__ == "__main__":
    RC4_test()