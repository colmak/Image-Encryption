import numpy as np
sbox = [
  [0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76],
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
  [0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16]
]

def convert_to_hex(st): # convert the string to a hex array and transpose it to get the correct format
    st = np.array([hex(ord(c))[2:] for c in st]).reshape(4,4)
    return np.transpose(st)

def add_round_key(key,pt): # add round key 
   sm = np.zeros((4, 4), dtype=int)
   for i in range(4):
    sm[i] = [int(k, 16) ^ int(j, 16) for k, j in zip(key[i], pt[i])]
   sm = np.array([[format(x, '02x') for x in row] for row in sm])
   return sm

def sub_bytes(sm): # substituion bytes
    rowcol = []
    for s in range(4):
     rowcol += [[int(k,16) for k in r] for r in sm[s]]
    new_sm = [hex(sbox[i[0]][i[1]])[2:] for i in rowcol]
    new_sm = np.array(new_sm,dtype=str).reshape(4,4)
    return new_sm

def shift_rows(sm): #shift rows
  for i in range(4):
    sm[i] = np.roll(sm[i],-i)
  return np.array(sm).reshape(4,4)

def poly_mul(p1, p2): #function for poly prime multiplication
    p1 = np.poly1d([int(i) for i in p1[::1]])
    p2 = np.poly1d([int(i) for i in p2[::1]])
    mul = np.polymul(p1, p2)
    result = [str(x) for x in mul.coeffs.tolist()]

    if len(result) >= 9:
      del result[0]
      result[3]=str(int(result[3])+1)
      result[4]=str(int(result[4])+1)
      result[6]=str(int(result[6])+1)
      result[7]=str(int(result[7])+1)

    elif len(result)<8:
       for i in range(8-len(result)):
           result.insert(i,'0')

    for i in range(len(result)):
        result[i] = '0' if int(result[i])%2 == 0 else '1'
    return int("".join(result).zfill(2),2)

def mix_columns(MixColumns):  #mix columns  
    A = np.array([['02', '03', '01', '01'],
     ['01', '02', '03', '01'],
     ['01', '01', '02', '03'],
     ['03', '01', '01', '02']])
    result = np.zeros((4, 4), dtype=int)
    for i in range(4):
        for j in range(4):
            for k in range(4):
                x = format(int(A[i][k],16), "08b")
                y = format(int(MixColumns[k][j],16), "08b")
                result[i][j]^=poly_mul(x,y)
    result = np.array([[hex(x)[2:] for x in i] for i in result]).reshape(4,4)
    return result
 
def round_key_gen(key,r):   #key expansion or round key generation
  w = key
  gw3 = w[3]
  gw3 = np.roll(gw3,-1)
  rowcol = [[int(k,16) for k in r] for r in gw3]
  for i in rowcol:
     if len(i)==1:
        i.insert(0,0)

  for i in rowcol:
      gw3[rowcol.index(i)] = hex(sbox[i[0]][i[1]])[2:]

  temp = np.zeros(10,int).astype(str)
  temp[-(r+1)] = '1'
  temp = temp.tolist()
  rc_poly = np.poly1d([int(i) for i in temp])
  result = [str(i) for i in rc_poly.coeffs.tolist()]

  if len(result)>=9:
     del result[0]
     result[3] = str(int(result[3])+1)
     result[4] = str(int(result[4])+1)
     result[6] = str(int(result[6])+1)
     result[7] = str(int(result[7])+1)
     
  temp = hex(int(''.join(result),2))[2:]
  rc = [temp,'0','0','0']
  gw3 = [hex(int(k,16)^int(j,16))[2:] for k,j in zip(gw3,rc)]

  for i in range(4):
    temp = w[i].tolist()
    if i==0:
      rkey = [hex(int(k,16)^int(j,16))[2:] for k,j in zip(gw3,temp)]
    else:
      rkey.extend([hex(int(k,16)^int(j,16))[2:] for k,j in zip(rkey[4*(i-1):],temp)])
  rkey = np.array(rkey).reshape(4,4)
  return np.transpose(rkey)
  
def perform_aes(key, pt): #performs all operations of aes to produce the ciphertext
  key_list = key.reshape(1,16).tolist()
  print(key_list)
  print("Secret Key: ")
  print(key)
  print("Plaintext: ")
  print(pt)
  new_sm = add_round_key(key.tolist(),pt.tolist())
  print("\nRound 0: ")
  print("Round Key: " +  ' '.join(key_list[0]).upper())
  print("Ciphertext: ")
  print(new_sm)
  for i in range(10):
      print("\nRound " + str(i+1) + ": ")
      new_sm = sub_bytes(new_sm.tolist())
      new_sm = shift_rows(new_sm.tolist())
      key = round_key_gen(np.transpose(key),i)
      key_list = key.reshape(1,16).tolist()
      print("Round Key: " + ' '.join(key_list[0]).upper())
      if i!=9:
          new_sm = mix_columns(new_sm)
      new_sm = add_round_key(key.tolist(),new_sm.tolist())
      print("Ciphertext: ")
      print(new_sm)

  new_sm = np.transpose(new_sm)
  new_sm = new_sm.reshape(1,16)
  new_sm = new_sm.tolist()
  return ' '.join(new_sm[0])
   
secret_key = "Thats my Kung Fu" #input("Enter the secret key: ")  
# key = convert_to_hex(secret_key)


# plaintext = "Two One Nine Two" #input("Enter Plaintext to encrypt: ") 
# pt = convert_to_hex(plaintext)

# ct = perform_aes(key,pt)
# print("Ciphertext: "+ ct.upper())

key1 = bytes.fromhex('00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00')
key = ' '.join([hex(byte)[2:].zfill(2) for byte in key1])

