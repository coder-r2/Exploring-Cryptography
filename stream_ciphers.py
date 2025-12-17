#Implementation of Stream Ciphers

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
    
