"""
AES Implementation
128 bit data block
128/192/256 bit key
10/12/14 rounds
Input in hex 
Output in hex
"""

class AES():
    def __init__(self, key):
        self.sbox=[[0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76],
    [0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0],
    [0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15],
    [0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75],
    [0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84],
    [0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF],
    [0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8],
    [0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2],
    [0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73],
    [0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB],
    [0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79],
    [0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08],
    [0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A],
    [0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E],
    [0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF],
    [0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16]]
        self.inverse_sbox=[[0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb],
    [0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb],
    [0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e],
    [0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25],
    [0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92],
    [0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84],
    [0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06],
    [0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b],
    [0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73],
    [0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e],
    [0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b],
    [0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4],
    [0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f],
    [0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef],
    [0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61],
    [0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d]]
        self.rcon=[0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000, 0x80000000, 0x1B000000, 0x36000000, 0x6c000000, 0xd8000000, 0xab000000, 0x4d000000]
        self.m=0x11b
        self.key=key
        self.keylen=len(self.key)
        if self.keylen==32 or self.keylen==48 and self.keylen==64:
            pass
        else:
            raise Exception("Invalid key length")
        self.rounds=(self.keylen//8)+6
        self.key_expansion()
    
    def encryption(self, plaintext):
        self.state=[]
        #initial state
        for i in range (4):
            self.state.append(plaintext[i*8:i*8+8])
        #round 0: add round key
        self.add_round_key(0)
        #remaining rounds: sub -> shift -> mix -> add round key
        for i in range(1, self.rounds+1):
            for j in range(4):
                self.state[j]=self.sub_bytes(self.state[j])
            self.shift_rows()
            if i<self.rounds:
                self.state=[[self.state[0][0:2],self.state[1][0:2],self.state[2][0:2],self.state[3][0:2]],[self.state[0][2:4],self.state[1][2:4],self.state[2][2:4],self.state[3][2:4]],[self.state[0][4:6],self.state[1][4:6],self.state[2][4:6],self.state[3][4:6]],[self.state[0][6:],self.state[1][6:],self.state[2][6:],self.state[3][6:]]]
                self.mix_columns()
                self.state=[self.state[0][0]+self.state[1][0]+self.state[2][0]+self.state[3][0],self.state[0][1]+self.state[1][1]+self.state[2][1]+self.state[3][1],self.state[0][2]+self.state[1][2]+self.state[2][2]+self.state[3][2],self.state[0][3]+self.state[1][3]+self.state[2][3]+self.state[3][3]]
            self.add_round_key(i)
        cipher=self.state[0]+self.state[1]+self.state[2]+self.state[3]
        return cipher
    
    def decryption(self, ciphertext):
        self.inv_w=[self.w[i] for i in range(4*(self.rounds+1))]
        self.state=[]
        for i in range (4):
            self.state.append(ciphertext[i*8:i*8+8])
        #round 0: add round key
        self.inv_add_round_key(self.rounds)
        #remaining rounds: sub -> shift -> mix -> add round key
        for i in range(self.rounds-1, -1, -1):
            for j in range(4):
                self.state[j]=self.inv_sub_bytes(self.state[j])
            self.inv_shift_rows()
            if i>0:
                self.state=[[self.state[0][0:2],self.state[1][0:2],self.state[2][0:2],self.state[3][0:2]],[self.state[0][2:4],self.state[1][2:4],self.state[2][2:4],self.state[3][2:4]],[self.state[0][4:6],self.state[1][4:6],self.state[2][4:6],self.state[3][4:6]],[self.state[0][6:],self.state[1][6:],self.state[2][6:],self.state[3][6:]]]
                self.inv_mix_columns()
                self.state=[self.state[0][0]+self.state[1][0]+self.state[2][0]+self.state[3][0],self.state[0][1]+self.state[1][1]+self.state[2][1]+self.state[3][1],self.state[0][2]+self.state[1][2]+self.state[2][2]+self.state[3][2],self.state[0][3]+self.state[1][3]+self.state[2][3]+self.state[3][3]]
            self.inv_add_round_key(i)
        plain=self.state[0]+self.state[1]+self.state[2]+self.state[3]
        return plain
    
    def add_round_key(self, round):
        for i in range(4):
            self.state[i]=self.xor(self.state[i],self.w[round*4+i])

    def inv_add_round_key(self, round):
        if round<=self.rounds-1 and round>0:
            temp=self.state[:]
            for i in range(4):
                self.state[i]=self.inv_w[round*4+i]
            self.inv_mix_columns()
            for i in range(4):
                self.inv_w[round*4+i]=self.state[i]
            self.state[i]=temp[:]
        for i in range(4):
            self.state[i]=self.xor(self.state[i],self.inv_w[round*4+i])

    def shift_rows(self):
        ans=[None for i in range(4)]
        ans[0]=self.state[0][0:2]+self.state[1][2:4]+self.state[2][4:6]+self.state[3][6:]
        ans[1]=self.state[1][0:2]+self.state[2][2:4]+self.state[3][4:6]+self.state[0][6:]
        ans[2]=self.state[2][0:2]+self.state[3][2:4]+self.state[0][4:6]+self.state[1][6:]
        ans[3]=self.state[3][0:2]+self.state[0][2:4]+self.state[1][4:6]+self.state[2][6:]
        self.state=ans[:]
    
    def inv_shift_rows(self):
        ans=[None for i in range(4)]
        ans[0]=self.state[0][0:2]+self.state[3][2:4]+self.state[2][4:6]+self.state[1][6:]
        ans[1]=self.state[1][0:2]+self.state[0][2:4]+self.state[3][4:6]+self.state[2][6:]
        ans[2]=self.state[2][0:2]+self.state[1][2:4]+self.state[0][4:6]+self.state[3][6:]
        ans[3]=self.state[3][0:2]+self.state[2][2:4]+self.state[1][4:6]+self.state[0][6:]
        self.state=ans[:]

    def mix_columns(self):
        ans=[[None for i in range(4)] for i in range(4)]
        mult_mx=[[2, 3, 1, 1], [1, 2, 3, 1], [1, 1, 2, 3], [3, 1, 1, 2]]
        for i in range (4):
            for j in range(4):
                res=[]
                for k in range(4):
                    a=mult_mx[j][k]
                    if a==1:
                        res.append(self.state[k][i])
                    elif a==2:
                        x2=int(self.state[k][i],16)*2
                        if x2>255:
                            x2=self.xor(hex(x2)[2:],hex(self.m)[2:])
                            x2=x2[1:]
                        else:
                            x2=hex(x2)[2:].zfill(2)
                        res.append(x2)
                    elif a==3:
                        x2=int(self.state[k][i],16)*2
                        if x2>255:
                            x2=self.xor(hex(x2)[2:],hex(self.m)[2:])
                            x2=x2[1:]
                        else:
                            x2=hex(x2)[2:].zfill(2)
                        x=self.xor(x2, self.state[k][i])
                        res.append(x)
                ans[j][i]=self.xor(res[0],self.xor(res[1],self.xor(res[2],res[3])))
        self.state=ans[:]
    
    def inv_mix_columns(self):
        ans=[[None for i in range(4)] for i in range(4)]
        mult_mx=[[0x0e, 0x0b, 0x0d, 0x09], [0x09, 0x0e, 0x0b, 0x0d], [0x0d, 0x09, 0x0e, 0x0b], [0x0b, 0x0d, 0x09, 0x0e]]
        for i in range (4):
            for j in range(4):
                res=[]
                for k in range(4):
                    a=mult_mx[j][k]
                    if a==0x0e:
                        pass
                    elif a==0x0b:
                        pass
                    elif a==0x0d:
                        pass
                    elif a==0x09:
                        for i in range(3):
                            if i==0:
                                x8=int(self.state[k][i],16)*2
                            else:
                                x8=int(x8,16)*2
                            if x8>255:
                                x8=self.xor(hex(x8)[2:],hex(self.m)[2:])
                                x8=x8[1:]
                            else:
                                x8=hex(x8)[2:].zfill(2)
                        x=self.xor(x8, self.state[k][i])
                        res.append(x)
                ans[j][i]=self.xor(res[0],self.xor(res[1],self.xor(res[2],res[3])))
        self.state=ans[:]
    
    def key_expansion(self):
        self.w=[]
        for i in range(len(self.key)//8):
            self.w.append(self.key[i*8:i*8+8])

        for i in range(len(self.key)//8, 4*(self.rounds+1)):
            temp=self.w[i-1]
            if i%4==0:
                temp=self.sub_bytes(self.rot_word(temp))
                temp=self.xor(temp, hex(self.rcon[i//4-1])[2:].zfill(8))
            self.w.append(self.xor(self.w[i-4], temp))

    def xor(self, a, b):
        start=len(a)
        if len(a)!=len(b):
            raise Exception("xor: Length of a and b must be same")
        a,b=int(a,16),int(b,16)
        return hex(a^b)[2:].zfill(start)
    
    def rot_word(self, word):
        return word[2:]+word[:2]
    
    def sub_bytes(self, word):
        for i in range(0,len(word),2):
            x,y=word[i],word[i+1]
            x,y=int(x,16),int(y,16)
            x,y=hex(self.sbox[x][y])[2:].zfill(2)[0],hex(self.sbox[x][y])[2:].zfill(2)[1]
            word=word[:i]+x+y+word[i+2:]
        return word

    def inv_sub_bytes(self, word):
        for i in range(0,len(word),2):
            x,y=word[i],word[i+1]
            x,y=int(x,16),int(y,16)
            x,y=hex(self.inverse_sbox[x][y])[2:].zfill(2)[0],hex(self.inverse_sbox[x][y])[2:].zfill(2)[1]
            word=word[:i]+x+y+word[i+2:]
        return word


# plain="0189fe7623abdc5445cdba3267ef9810" #input("Enter the 128 bit data block in hex: ")
# key="0f470caf15d9b77f71e8ad67c959d698" #input("Enter the 128/192/256 bit key in hex: ") 
# a=AES(key)
# cipher=a.encryption(plain)

a=AES("0f1571c947d9e8590cb7add6af7f6798") #0f 15 71 c9 47 d9 e8 59 0c b7 ad d6 af 7f 67 98
cipher=a.encryption("0123456789abcdeffedcba9876543210")
print("Cipher text: ", cipher)
print(len(cipher))
