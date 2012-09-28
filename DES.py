#DES ENCRYPTION/DECRYPTION
#Currently have ECB, CBC, CFB, OFB
#Currently conducting testing on these four modes then will move forward
#All INPUT and OUTPUT is in BINARY

import sys
from utils import decimal2binary, binary2decimal, hex2binary, binary2hex

#DES Permutation Tables
IP = [58,50,42,34,26,18,10,2,\
      60,52,44,36,28,20,12,4,\
      62,54,46,38,30,22,14,6,\
      64,56,48,40,32,24,16,8,\
      57,49,41,33,25,17, 9,1,\
      59,51,43,35,27,19,11,3,\
      61,53,45,37,29,21,13,5,\
      63,55,47,39,31,23,15,7]
      
IP_INVERSE = [40, 8,48,16,56,24,64,32,\
              39, 7,47,15,55,23,63,31,\
              38, 6,46,14,54,22,62,30,\
              37, 5,45,13,53,21,61,29,\
              36, 4,44,12,52,20,60,28,\
              35, 3,43,11,51,19,59,27,\
              34, 2,42,10,50,18,58,26,\
              33, 1,41, 9,49,17,57,25]
              
PC_1 = [57,49,41,33,25,17, 9,\
         1,58,50,42,34,26,18,\
        10, 2,59,51,43,35,27,\
        19,11, 3,60,52,44,36,\
        63,55,47,39,31,23,15,\
         7,62,54,46,38,30,22,\
        14, 6,61,53,45,37,29,\
        21,13, 5,28,20,12, 4]
        
PC_2 = [14,17,11,24, 1, 5,\
         3,28,15, 6,21,10,\
        23,19,12, 4,26, 8,\
        16, 7,27,20,13, 2,\
        41,52,31,37,47,55,\
        30,40,51,45,33,48,\
        44,49,39,56,34,53,\
        46,42,50,36,29,32]
        
EBIT = [32, 1, 2, 3, 4, 5,\
         4, 5, 6, 7, 8, 9,\
         8, 9,10,11,12,13,\
        12,13,14,15,16,17,\
        16,17,18,19,20,21,\
        20,21,22,23,24,25,\
        24,25,26,27,28,29,\
        28,29,30,31,32, 1]

S = {1:[[14, 4,13, 1, 2,15,11, 8, 3,10, 6,12, 5, 9, 0, 7],\
        [ 0,15, 7, 4,14, 2,13, 1,10, 6,12,11, 9, 5, 3, 8],\
        [ 4, 1,14, 8,13, 6, 2,11,15,12, 9, 7, 3,10, 5, 0],\
        [15,12, 8, 2, 4, 9, 1, 7, 5,11, 3,14,10, 0, 6,13]],\

     2:[[15, 1, 8,14, 6,11, 3, 4, 9, 7, 2,13,12, 0, 5,10],\
        [ 3,13, 4, 7,15, 2, 8,14,12, 0, 1,10, 6, 9,11, 5],\
        [ 0,14, 7,11,10, 4,13, 1, 5, 8,12, 6, 9, 3, 2,15],\
        [13, 8,10, 1, 3,15, 4, 2,11, 6, 7,12, 0, 5,14, 9]],\

     3:[[10, 0, 9,14, 6, 3,15, 5, 1,13,12, 7,11, 4, 2, 8],\
        [13, 7, 0, 9, 3, 4, 6,10, 2, 8, 5,14,12,11,15, 1],\
        [13, 6, 4, 9, 8,15, 3, 0,11, 1, 2,12, 5,10,14, 7],\
        [ 1,10,13, 0, 6, 9, 8, 7, 4,15,14, 3,11, 5, 2,12]],\

     4:[[ 7,13,14, 3, 0, 6, 9,10, 1, 2, 8, 5,11,12, 4,15],\
        [13, 8,11, 5, 6,15, 0, 3, 4, 7, 2,12, 1,10,14, 9],\
        [10, 6, 9, 0,12,11, 7,13,15, 1, 3,14, 5, 2, 8, 4],\
        [ 3,15, 0, 6,10, 1,13, 8, 9, 4, 5,11,12, 7, 2,14]],\

     5:[[ 2,12, 4, 1, 7,10,11, 6, 8, 5, 3,15,13, 0,14, 9],\
        [14,11, 2,12, 4, 7,13, 1, 5, 0,15,10, 3, 9, 8, 6],\
        [ 4, 2, 1,11,10,13, 7, 8,15, 9,12, 5, 6, 3, 0,14],\
        [11, 8,12, 7, 1,14, 2,13, 6,15, 0, 9,10, 4, 5, 3]],\

     6:[[12, 1,10,15, 9, 2, 6, 8, 0,13, 3, 4,14, 7, 5,11],\
        [10,15, 4, 2, 7,12, 9, 5, 6, 1,13,14, 0,11, 3, 8],\
        [ 9,14,15, 5, 2, 8,12, 3, 7, 0, 4,10, 1,13,11, 6],\
        [4, 3, 2,12, 9, 5,15,10,11,14, 1, 7, 6, 0, 8,13]],\

     7:[[ 4,11, 2,14,15, 0, 8,13, 3,12, 9, 7, 5,10, 6, 1],\
        [13, 0,11, 7, 4, 9, 1,10,14, 3, 5,12, 2,15, 8, 6],\
        [ 1, 4,11,13,12, 3, 7,14,10,15, 6, 8, 0, 5, 9, 2],\
        [ 6,11,13, 8, 1, 4,10, 7, 9, 5, 0,15,14, 2, 3,12]],\

     8:[[13, 2, 8, 4, 6,15,11, 1,10, 9, 3,14, 5, 0,12, 7],\
        [ 1,15,13, 8,10, 3, 7, 4,12, 5, 6,11, 0,14, 9, 2],\
        [ 7,11, 4, 1, 9,12,14, 2, 0, 6,10,13,15, 3, 5, 8],\
        [ 2, 1,14, 7, 4,10, 8,13,15,12, 9, 0, 3, 5, 6,11]]}
        
P = [16, 7,20,21,\
     29,12,28,17,\
      1,15,23,26,\
      5,18,31,10,\
      2, 8,24,14,\
     32,27, 3, 9,\
     19,13,30, 6,\
     22,11, 4,25]


#Calculate the permutation of the given data with the given permutation list
def permute(data,p):
    new = ''
    for x in p:
        new += data[x-1]
    return new
    

#Generate 16 sub keys from main key
def gen_keys(k):
    k_perm = permute(k,PC_1)
      
    shifts = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]
      
    C = k_perm[:28]
    D = k_perm[28:]
    
    keys = []
    
    for index in range(0,16):
        new_C,new_D = C,D
        for s in range(shifts[index]):
            new_C = new_C[1:]+new_C[0]
            new_D = new_D[1:]+new_D[0]
        
        CD = new_C + new_D
        keys.append(permute(CD,PC_2))
        
        C,D = new_C,new_D
        
    return keys


#perform XOR operation on two pieces of data
def xor(data1,data2):
    new = ''
    
    for i,b in enumerate(data1):
        if b == data2[i]:
            new += '0'
        else:
            new += '1'
            
    return new


#DES function
def function(d,key):
    data = xor(E(d),key)
    s_result = ''
    
    for index in range(1,9):
        s = S[index]
        
        B = data[(index-1)*6:(index-1)*6+6]
        
        row = binary2decimal(B[0]+B[5])
        col = binary2decimal(B[1:5])
        
        s_result += decimal2binary(s[row][col],places=4)
    
    return permute(s_result,P)
    
  
#32-bit input, 48-bit output
def E(data):
    result = ''
    
    for index in EBIT:
        result += data[index-1]
        
    return result
    

#Encode data with DES encryption in ECB mode
def encode_ECB(data,key):
    keys = gen_keys(key)
    
    encoded = ''
    
    padded = False
    while not padded:
        #PADDING
        if len(data) < 64:
            remaining = len(data) / 8
            for x in range(remaining):
                data += decimal2binary(remaining,places=8)
                
            padded = True
            
        ip = permute(data[0:64],IP)
        
        prev_L = ip[:32]
        prev_R = ip[32:]
        
        for x in range(0,16):
            L = prev_R
            R = xor(prev_L,function(prev_R,keys[x]))
            
            prev_L = L
            prev_R = R
        
        RL = R + L
        next = permute(RL,IP_INVERSE)
        encoded += next
        
        data = data[64:]
    
    return encoded


#Decode data encrypted with DES encryption in ECB mode
def decode_ECB(data,key):
    keys = gen_keys(key)
    
    decoded = ''
    
    while len(data) > 0:
        ip = permute(data[0:64],IP)
        
        prev_L = ip[:32]
        prev_R = ip[32:]
        
        for x in range(16,0,-1):
            L = prev_R
            R = xor(prev_L,function(prev_R,keys[x-1]))
            
            prev_L = L
            prev_R = R
        
        RL = R + L
        next = permute(RL,IP_INVERSE)
        
        #remove padding
        if len(data) == 64:
            last = next[56:]
            for x in range(binary2decimal(last)):
                next = next[0:len(next)-8]
        
        decoded += next
        
        data = data[64:]
    
    return decoded
    
    
#Encode data with DES encryption in CBC mode
def encode_CBC(data,key,IV):
    keys = gen_keys(key)
    
    encoded = ''
    
    while len(data) > 0:
        #PADDING
        if len(data) < 64:
            data += '1'
            
            while len(data) < 64:
                data += '0'
        
        block = data[:64]
        ip = permute(xor(block,IV),IP)
        
        prev_L = ip[:32]
        prev_R = ip[32:]
        
        for x in range(0,16):
            L = prev_R
            R = xor(prev_L,function(prev_R,keys[x]))
            
            prev_L = L
            prev_R = R
        
        RL = R + L
        
        enc = permute(RL,IP_INVERSE)
        
        IV = enc
        encoded += enc
        
        data = data[64:]
    
    return encoded
    
    
#Decode data encoded with DES encryption in CBC mode
def decode_CBC(data,key,IV):
    keys = gen_keys(key)
    
    decoded = ''
    
    while len(data) > 0:
        block = data[:64]
        ip = permute(block,IP)
        
        prev_L = ip[:32]
        prev_R = ip[32:]
        
        for x in range(16,0,-1):
            L = prev_R
            R = xor(prev_L,function(prev_R,keys[x-1]))
            
            prev_L = L
            prev_R = R
        
        RL = R + L
        
        decoded += xor(permute(RL,IP_INVERSE),IV)
        
        IV = block
        data = data[64:]
    
    return decoded


#Encode data with DES encryption in CFB mode
def encode_CFB(data,key,IV):
    keys = gen_keys(key)
    
    encoded = ''
    
    while len(data) > 0:
        #Last Block if not 64 bits
        if len(data) < 64:
            pass
        
        block = data[:64]
        ip = permute(IV,IP)
        
        prev_L = ip[:32]
        prev_R = ip[32:]
        
        for x in range(0,16):
            L = prev_R
            R = xor(prev_L,function(prev_R,keys[x]))
            
            prev_L = L
            prev_R = R
        
        RL = R + L
        
        enc = xor(permute(RL,IP_INVERSE),block)
        
        IV = enc
        encoded += enc
        
        data = data[64:]
    
    return encoded
    
    
#Decode data encrypted with DES encryption in CFB mode
def decode_CFB(data,key,IV):
    keys = gen_keys(key)
    
    decoded = ''
    
    while len(data) > 0:
        #Last Block if not 64 bits
        if len(data) < 64:
            pass
        
        block = data[:64]
        ip = permute(IV,IP)
        
        prev_L = ip[:32]
        prev_R = ip[32:]
        
        for x in range(0,16):
            L = prev_R
            R = xor(prev_L,function(prev_R,keys[x]))
            
            prev_L = L
            prev_R = R
        
        RL = R + L
        
        dec = xor(permute(RL,IP_INVERSE),block)
        
        IV = block
        decoded += dec
        
        data = data[64:]
    
    return decoded


#Encode data with DES encryption in OFB mode
def encode_OFB(data,key,IV):
    keys = gen_keys(key)
    
    encoded = ''
    
    while len(data) > 0:
        #Last Block if not 64 bits
        if len(data) < 64:
            pass
        
        block = data[:64]
        ip = permute(IV,IP)
        
        prev_L = ip[:32]
        prev_R = ip[32:]
        
        for x in range(0,16):
            L = prev_R
            R = xor(prev_L,function(prev_R,keys[x]))
            
            prev_L = L
            prev_R = R
        
        RL = R + L
        
        IV = permute(RL,IP_INVERSE)
        
        encoded += xor(block,IV)
        
        data = data[64:]
    
    return encoded
    
    
#Decode data encrypted with DES encryption in OFB mode
def decode_OFB(data,key,IV):
    keys = gen_keys(key)
    
    decoded = ''
    
    while len(data) > 0:
        block = data[:64]
        ip = permute(IV,IP)
        
        prev_L = ip[:32]
        prev_R = ip[32:]
        
        for x in range(0,16):
            L = prev_R
            R = xor(prev_L,function(prev_R,keys[x]))
            
            prev_L = L
            prev_R = R
        
        RL = R + L
        
        IV = permute(RL,IP_INVERSE)
        
        decoded += xor(block,IV)
        
        data = data[64:]
    
    return encoded

    
#Main DES Encode Function
def DES_encode(data,mode,key,IV=None):
    if mode == 'ECB':
        return encode_ECB(data,key)
    elif mode == 'CBC':
        if IV is not None:
            return encode_CBC(data,key,IV)
        else:
            pass
            #throw exception
    elif mode == 'CFB':
        if IV is not None:
            return encode_CFB(data,key,IV)
        else:
            pass
            #throw exception
    elif mode == 'OFB':
        if IV is not None:
            return encode_OFB(data,key,IV)
        else:
            pass
            #throw exception

#Main DES Decode Function
def DES_decode(data,mode,key,IV=None):
    if mode == 'ECB':
        return decode_ECB(data,key)
    elif mode == 'CBC':
        if IV is not None:
            return decode_CBC(data,key,IV)
        else:
            pass
            #throw exception
    elif mode == 'CFB':
        if IV is not None:
            return decode_CFB(data,key,IV)
        else:
            pass
            #throw exception
    elif mode == 'OFB':
        if IV is not None:
            return decode_OFB(data,key,IV)
        else:
            pass
            #throw exception
        

#Main TripleDES Encode Function
def DES_encode3(data,mode,key1,key2,key3=-1,IV=None):
    p1 = DES_encode(data,mode,key1)
    p2 = DES_decode(p1,mode,key2)
    if key3 == -1:
        p3 = DES_encode(p2,mode,key1)
    else:
        p3 = DES_encode(p2,mode,key3)
    
    return p3


#Main TripleDES Decode Function
def DES_decode3(data,mode,key1,key2,key3=-1,IV=None):
    if key3 == -1:
        p1 = DES_decode(data,mode,key1)
    else:
        p1 = DES_decode(data,mode,key3)
    
    p2 = DES_encode(p1,mode,key2)
    p3 = DES_decode(p2,mode,key1)
    
    return p3
    
    
#Format Printer
def f_print(data,block=4):
    new = ''
    
    for i in range(0,len(data)-block+1,block):
        new += data[i:i+block]
        new += ' '
        
    print new
    

#MAIN PROGRAM TESTING
if __name__ == '__main__':
    #DES testing
    ECB_M = "0101010001101000011010010111001100100000011010010111001100100000011101000110100001100101001000000110110101100101011100110111001101100001011001110110010100100000011101000110111100100000011001010110111001100011011100100111100101110000011101000010000100100001"
    ECB_K = "0011000100110010001100110011010000110101001101100011011100111000"
    f_print(ECB_M,block=8)
    
    print ""
    
    encoded = DES_encode(ECB_M,"ECB",ECB_K)
    f_print(encoded,block=8)
    
    print ""
    
    decoded = DES_decode(encoded,"ECB",ECB_K)
    f_print(decoded,block=8)
    
    print ""
    print ECB_M == decoded
    print encoded == "0100110010101111101110011001001101111100000000000000000000000000"
    
    
    
    
    
    
    
    
    
