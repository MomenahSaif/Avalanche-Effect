class DES:
  """
  A class implementing the DES encryption and decryption algorithm.
  """

  # Permutation and other tables (same as before)
  initial_perm = [58, 50, 42, 34, 26, 18, 10, 2,
                60, 52, 44, 36, 28, 20, 12, 4,
                62, 54, 46, 38, 30, 22, 14, 6,
                64, 56, 48, 40, 32, 24, 16, 8,
                57, 49, 41, 33, 25, 17, 9, 1,
                59, 51, 43, 35, 27, 19, 11, 3,
                61, 53, 45, 37, 29, 21, 13, 5,
                63, 55, 47, 39, 31, 23, 15, 7]
  key_comp = [14, 17, 11, 24, 1, 5,
            3, 28, 15, 6, 21, 10,
            23, 19, 12, 4, 26, 8,
            16, 7, 27, 20, 13, 2,
            41, 52, 31, 37, 47, 55,
            30, 40, 51, 45, 33, 48,
            44, 49, 39, 56, 34, 53,
            46, 42, 50, 36, 29, 32]              
  exp_d = [32, 1, 2, 3, 4, 5, 4, 5,
           6, 7, 8, 9, 8, 9, 10, 11,
           12, 13, 12, 13, 14, 15, 16, 17,
           16, 17, 18, 19, 20, 21, 20, 21,
           22, 23, 24, 25, 24, 25, 26, 27,
           28, 29, 28, 29, 30, 31, 32, 1]
  per = [16,  7, 20, 21,
       29, 12, 28, 17,
       1, 15, 23, 26,
       5, 18, 31, 10,
       2,  8, 24, 14,
       32, 27,  3,  9,
       19, 13, 30,  6,
       22, 11,  4, 25]
  shift_table = [1, 1, 2, 2,
               2, 2, 2, 2,
               1, 2, 2, 2,
               2, 2, 2, 1]     
  sbox = [[[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
         [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
         [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
         [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],
 
        [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
         [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
         [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
         [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],
 
        [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
         [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
         [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
         [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],
 
        [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
         [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
         [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
         [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],
 
        [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
         [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
         [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
         [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],
 
        [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
         [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
         [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
         [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],
 
        [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
         [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
         [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
         [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],
 
        [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
         [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
         [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
         [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]]
 
  # Final Permutation Table
  final_perm = [40, 8, 48, 16, 56, 24, 64, 32,
              39, 7, 47, 15, 55, 23, 63, 31,
              38, 6, 46, 14, 54, 22, 62, 30,
              37, 5, 45, 13, 53, 21, 61, 29,
              36, 4, 44, 12, 52, 20, 60, 28,
              35, 3, 43, 11, 51, 19, 59, 27,
              34, 2, 42, 10, 50, 18, 58, 26,
              33, 1, 41, 9, 49, 17, 57, 25]
              
  keyp = [57, 49, 41, 33, 25, 17, 9,
        1, 58, 50, 42, 34, 26, 18,
        10, 2, 59, 51, 43, 35, 27,
        19, 11, 3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15,
        7, 62, 54, 46, 38, 30, 22,
        14, 6, 61, 53, 45, 37, 29,
        21, 13, 5, 28, 20, 12, 4]            
        

  def __init__(self, key):
    """
    Initialize the DES object with the key.
    """
    self.key=key
    self.round_outputs = []

  def hex2bin(self, s):
      mp = {'0': "0000",
          '1': "0001",
          '2': "0010",
          '3': "0011",
          '4': "0100",
          '5': "0101",
          '6': "0110",
          '7': "0111",
          '8': "1000",
          '9': "1001",
          'A': "1010",
          'B': "1011",
          'C': "1100",
          'D': "1101",
          'E': "1110",
          'F': "1111"}
      bin = ""
      for i in range(len(s)):
          bin = bin + mp[s[i]]
      return bin   

  def bin2hex(self, s):
      mp = {"0000": '0',
          "0001": '1',
          "0010": '2',
          "0011": '3',
          "0100": '4',
          "0101": '5',
          "0110": '6',
          "0111": '7',
          "1000": '8',
          "1001": '9',
          "1010": 'A',
          "1011": 'B',
          "1100": 'C',
          "1101": 'D',
          "1110": 'E',
          "1111": 'F'}
      hex = ""
      for i in range(0, len(s), 4):
          ch = ""
          ch = ch + s[i]
          ch = ch + s[i + 1]
          ch = ch + s[i + 2]
          ch = ch + s[i + 3]
          hex = hex + mp[ch]
 
      return hex
  def bin2dec(self,binary):
 
    binary1 = binary
    decimal, i, n = 0, 0, 0
    while(binary != 0):
        dec = binary % 10
        decimal = decimal + dec * pow(2, i)
        binary = binary//10
        i += 1
    return decimal
 
# Decimal to binary conversion
 
 

  
  def dec2bin(self,num):
    res = bin(num).replace("0b", "")
    if(len(res) % 4 != 0):
        div = len(res) / 4
        div = int(div)
        counter = (4 * (div + 1)) - len(res)
        for i in range(0, counter):
            res = '0' + res
    return res
  

  def permute(self, k, arr, n):
    permutation = ""
    for i in range(0, n):
        permutation = permutation + k[arr[i] - 1]
    return permutation

  def shift_left(self, k, nth_shifts):
    s = ""
    for i in range(nth_shifts):
        for j in range(1, len(k)):
            s = s + k[j]
        s = s + k[0]
        k = s
        s = ""
    return k
 

  def xor(self, a, b):
    ans = ""
    for i in range(len(a)):
        if a[i] == b[i]:
            ans = ans + "0"
        else:
            ans = ans + "1"
    return ans

  def generate_round_keys(self):
      key = self.hex2bin(self.key)
      key = self.permute(key, self.keyp, 56)
      left = key[0:28]    # rkb for RoundKeys in binary
      right = key[28:56]  # rk for RoundKeys in hexadecimal
 
      rkb = []
      rk = []
      for i in range(0, 16):
    # Shifting the bits by nth shifts by checking from shift table
          left = self.shift_left(left, self.shift_table[i])
          right = self.shift_left(right, self.shift_table[i])
 
    # Combination of left and right string
          combine_str = left + right
 
    # Compression of key from 56 to 48 bits
          round_key = self.permute(combine_str, self.key_comp, 48)
 
          rkb.append(round_key)
          rk.append(self.bin2hex(round_key))
      return rkb,rk

  def encrypt(self, pt,rkb,rk):
    pt = self.hex2bin(pt)
 
    # Initial Permutation
    pt = self.permute(pt, self.initial_perm, 64)
    print("After initial permutation", self.bin2hex(pt))
 
    # Splitting
    left = pt[0:32]
    right = pt[32:64]
    for i in range(0, 16):
        #  Expansion D-box: Expanding the 32 bits data into 48 bits
        right_expanded = self.permute(right, self.exp_d, 48)
 
        # XOR RoundKey[i] and right_expanded
        xor_x = self.xor(right_expanded, rkb[i])
 
        # S-boxex: substituting the value from s-box table by calculating row and column
        sbox_str = ""
        for j in range(0, 8):
            row = self.bin2dec(int(xor_x[j * 6] + xor_x[j * 6 + 5]))
            col = self.bin2dec(
                int(xor_x[j * 6 + 1] + xor_x[j * 6 + 2] + xor_x[j * 6 + 3] + xor_x[j * 6 + 4]))
            val = self.sbox[j][row][col]
            sbox_str = sbox_str + self.dec2bin(val)
 
        # Straight D-box: After substituting rearranging the bits
        sbox_str = self.permute(sbox_str, self.per, 32)
 
        # XOR left and sbox_str
        result = self.xor(left, sbox_str)
        left = result
 
        # Swapper
        if(i != 15):
            left, right = right, left
        print("Round ", i + 1, " ", self.bin2hex(left),
              " ", self.bin2hex(right), " ", rk[i])
        formatted_left = ' '.join([self.bin2hex(left)[j:j+2] for j in range(0, len(self.bin2hex(left)), 2)])
        formatted_right = ' '.join([self.bin2hex(right)[j:j+2] for j in range(0, len(self.bin2hex(right)), 2)])
        formatted_rk = ' '.join([rk[i][j:j+2] for j in range(0, len(rk[i]), 2)])
        formatted_string = f"{formatted_left} {formatted_right} {formatted_rk}"
        self.round_outputs.append(formatted_string)
        #print(self.round_outputs) 
 
    # Combination
    combine = left + right
 
    # Final permutation: final rearranging of bits to get cipher text
    cipher_text = self.permute(combine, self.final_perm, 64)
    return cipher_text
  
def main():
  
  pt = "123456ABCD132536"
  key1 = "AABB09182736CCDD"
  key2 = "BBCC1928374655EE"
  print(" First Encryption")
  print("Plain Text:", pt)
  print("Key:", key1)
  des = DES(key1)
  rk,rkh=des.generate_round_keys()
  cipher_text = des.bin2hex(des.encrypt(pt,rk,rkh))
  print("First encryption output Text:", cipher_text)
  
  des2 = DES(key2)
  print("\nDecryption")
  print("Plain Text:", cipher_text)
  print("Key:", key2)
  rk2,rkh2=des2.generate_round_keys()
  rkb_rev = rk2[::-1]
  rk_rev = rkh2[::-1]
  text = des2.bin2hex(des2.encrypt(cipher_text, rkb_rev, rk_rev))
  print("Plain Text after decryption : ", text)
  
  des3 = DES(key1)
  print("\nSecond Encryption")
  print("Plain Text:", text)
  print("Key:", key1)
  rk3,rkh3=des3.generate_round_keys()
  cipher_text2 = des3.bin2hex(des3.encrypt(text,rk3,rkh3))
  print("Second encryption output Text:", cipher_text2)
  
  print("\n----------------------------First hex value changed----------------------------------")
  pt2 = "023456ABCD132536"
  des4 = DES(key1)
  print(" First Encryption")
  print("Plain Text:", pt2)
  print("Key:", key1)
  rk4,rkh4=des4.generate_round_keys()
  cipher_text3 = des4.bin2hex(des4.encrypt(pt2,rk4,rkh4))
  print("First encryption output Text:", cipher_text3)
  
  des5 = DES(key2)
  print("\nDecryption")
  print("Plain Text:", cipher_text3)
  print("Key:", key2)
  rk5,rkh5=des5.generate_round_keys()
  rkb_rev1 = rk5[::-1]
  rk_rev1 = rkh5[::-1]
  text1 = des5.bin2hex(des5.encrypt(cipher_text3, rkb_rev1, rk_rev1))
  print("Plain Text after decryption : ", text1)
  
  des6 = DES(key1)
  print("\nSecond Encryption")
  print("Plain Text:", text1)
  print("Key:", key1)
  rk6,rkh6=des6.generate_round_keys()
  cipher_text4 = des6.bin2hex(des6.encrypt(text1,rk6,rkh6))
  print("Second encryption output Text:", cipher_text4)
  print("\n\n------------------------Avalanche Effect--------------------------------\n")    
  #total_changed_bits = 0

    
  for i in range(16):  
        round_output_A = des3.round_outputs[i].replace(" ", "")  # Remove spaces
        round_output_B = des6.round_outputs[i].replace(" ", "")  # Remove spaces

        # Convert hexadecimal strings to binary strings
        binary_A = bin(int(round_output_A, 16))[2:].zfill(len(round_output_A) * 4)
        binary_B = bin(int(round_output_B, 16))[2:].zfill(len(round_output_B) * 4)

        # Calculate the number of differing bits
        changed_bits = sum(bit_A != bit_B for bit_A, bit_B in zip(binary_A, binary_B))

        print("Round", i + 1, "Changed bits:", changed_bits)
        #total_changed_bits += changed_bits

  #print("\nTotal changed bits:", total_changed_bits) 

  print("\n\n******************************************************------Question 2-------*********************************************************\n\n")
  print("\n----------------------------Last hex value changed----------------------------------")
  pt3 = "123456ABCD132537"
  des7 = DES(key1)
  print(" First Encryption")
  print("Plain Text:", pt3)
  print("Key:", key1)
  rk7,rkh7=des7.generate_round_keys()
  cipher_text7 = des7.bin2hex(des7.encrypt(pt3,rk7,rkh7))
  print("First encryption output Text:", cipher_text7)
  
  des8 = DES(key2)
  print("\nDecryption")
  print("Plain Text:", cipher_text7)
  print("Key:", key2)
  rk8,rkh8=des8.generate_round_keys()
  rkb_rev3 = rk8[::-1]
  rk_rev3 = rkh8[::-1]
  text3 = des8.bin2hex(des8.encrypt(cipher_text7, rkb_rev3, rk_rev3))
  print("Plain Text after decryption : ", text3)
  
  des9 = DES(key1)
  print("\nSecond Encryption")
  print("Plain Text:", text3)
  print("Key:", key1)
  rk9,rkh9=des9.generate_round_keys()
  cipher_text9 = des9.bin2hex(des9.encrypt(text3,rk9,rkh9))
  print("Second encryption output Text:", cipher_text9)
    
  print("\n\n------------------------Avalanche Effect--------------------------------\n")    
  #total_changed_bits3 = 0

    # Compare the round outputs of AESTest and AESTest3
  for i in range(16):  
        round_output_A3 = des3.round_outputs[i].replace(" ", "")  # Remove spaces
        round_output_B3 = des9.round_outputs[i].replace(" ", "")  # Remove spaces

        # Convert hexadecimal strings to binary strings
        binary_A3 = bin(int(round_output_A3, 16))[2:].zfill(len(round_output_A3) * 4)
        binary_B3 = bin(int(round_output_B3, 16))[2:].zfill(len(round_output_B3) * 4)

        # Calculate the number of differing bits
        changed_bits3 = sum(bit_A3 != bit_B3 for bit_A3, bit_B3 in zip(binary_A3, binary_B3))

        print("Round", i + 1, "Changed bits:", changed_bits3)
        #total_changed_bits3 += changed_bits3

  #print("\nTotal changed bits:", total_changed_bits3) 
    

if __name__ == "__main__":
  main()
