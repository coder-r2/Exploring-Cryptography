#Implementation of Trivium Stream Cipher

class Trivium:
    def __init__(self, key:list[int], iv:list[int]):
        if len(key) == 80 and len(iv) == 80:
            self._setup(key, iv)

    def _setup(self, key, iv):
        self.state = [0]*288

        self.state[:80] = key
        self.state[93:173] = iv
        self.state[285:] = [1,1,1]

        for _ in range(1152):
            self._clock()

    def _clock(self):
        ta = self.state[65]^self.state[92]
        tb = self.state[161]^self.state[176]
        tc = self.state[242]^self.state[287]

        z = ta^tb^tc

        fa = self.state[68] ^ (tc ^ (self.state[285]&self.state[286]))
        fb = self.state[170] ^ (ta ^ (self.state[90]&self.state[91]))
        fc = self.state[263] ^ (tb ^ (self.state[174]&self.state[175]))

        self.state = [fa] + self.state[0:92] + [fb] + self.state[93:176] + [fc] + self.state[177:287]

        return z

    def keystream(self, length):
        output = []
        for _ in range(length):
            output.append(self._clock())
        return output
    
#Auxillary Functions
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

def main():
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

if __name__ == "__main__":
    main()