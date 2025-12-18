#Implementation of Stream Ciphers

class Trivium:
    """Trivium stream cipher implementation."""

    def __init__(self, key:list[int], iv:list[int]):
        """
        Initializes the state of the Trivium cipher with a key and IV and warms up the cipher.
        
        key: List of 80 bits (0s and 1s)
        iv: List of 80 bits (0s and 1s)
        """
        self.state = [0]*288

        self.state[:80] = key
        self.state[93:173] = iv
        self.state[285:] = [1,1,1]

        for _ in range(1152):
            self._clock()   

    def _clock(self) -> int:
        """Clocks the cipher and returns one output bit."""
        ta = self.state[65]^self.state[92]
        tb = self.state[161]^self.state[176]
        tc = self.state[242]^self.state[287]

        z = ta^tb^tc

        fa = self.state[68] ^ (tc ^ (self.state[285]&self.state[286]))
        fb = self.state[170] ^ (ta ^ (self.state[90]&self.state[91]))
        fc = self.state[263] ^ (tb ^ (self.state[174]&self.state[175]))

        self.state = [fa] + self.state[0:92] + [fb] + self.state[93:176] + [fc] + self.state[177:287]

        return z

    def keystream(self, length:int) -> list[int]:
        """Generates a keystream of the specified length in bits."""
        output = []
        for _ in range(length):
            output.append(self._clock())
        return output
    
class RC4:
    def __init__(self, key, drop_bytes=1024):
        """
        Initialises the RC4 cipher with a key.

        key: List of bytes of length < 256
        """
        self.S = list(range(256))
        self.warmup_bytes = drop_bytes
        self.key = key
        self.key_length = len(key)
        self.j = 0
        self.i = 0
        self._setup()
    
    def _setup(self):
        """Sets the intial permutation in the state array S and drops intial bytes to fix statistical bias."""
        j = 0

        for k in range(256):
            j = (j + self.S[k] + self.key[k % self.key_length]) % 256
            self.S[k], self.S[j] = self.S[j], self.S[k]
        
        for _ in range(self.warmup_bytes):
            self._clock()
    
    def _clock(self) -> int:
        """Clocks the cipher and returns one byte."""
        self.i = (self.i + 1) % 256
        self.j = (self.j + self.S[self.i]) % 256
        self.S[self.i], self.S[self.j] = self.S[self.j], self.S[self.i]

        output = self.S[(self.S[self.i] + self.S[self.j]) % 256]
        return output
    
    def keystream(self, length:int) -> list[int]:
        """Generates a keystream of the specified length in bytes."""
        output = []
        for _ in range(length):
            output.append(self._clock())
        return output