# -*- coding: utf-8 -*-
"""
Created on Mon Jul 20 16:20:03 2020
@author: EL HADDAD MOUAD
"""
import string
import random
import numpy as np
from sympy import Matrix
import copy as cp
import codecs

""" Homophonic Cipher"""
alphabet_string = string.ascii_lowercase
alphabet_list = list(alphabet_string)
liste = [["07", "31", "50", "63", "66", "77", "84"], ["11", "64"], ["17", "33", "49"], ["10", "27", "51", "76"],
         ["25", "26", "28", "32", "48", "67", "69", "72", "75", "79", "82", "85"], ["08", "09"], ["44", "83"],
         ["19", "20", "21", "54", "70", "87"], ["02", "03", "29", "53", "68", "73"], ["18"], ["41"],
         ["42", "81", "86", "95"], ["40", "52"], ["00", "43", "80", "88", "89"],
         ["16", "30", "61", "65", "91", "94", "96"], ["01", "62"], ["15"], ["04", "24", "39", "58", "71", "99"],
         ["06", "34", "56", "57", "59", "90"], ["05", "23", "35", "37", "38", "60", "74", "78", "92"],
         ["13", "14", "36"], ["22"], ["45", "46"], ["12"], ["55", "93"], ["47"]]
dictionaire_d_info = {alphabet_list[i]: liste[i] for i in range(len(alphabet_list))}


def splitword(word):  # convert a string to a liste of char
    return [char for char in word]


def splitword2(word):
    scopy = ""
    scopy = scopy.join(word.split())
    l = []
    for i in range(0, len(scopy) - 1, 2):
        l.append(scopy[i:i + 2])
    return l


def encrypthomo(text):
    global dictionaire_d_info
    global alphabet_list
    text = text.lower()
    l = splitword(text)
    S = ""
    for i in l:
        if i in alphabet_list:
            S += dictionaire_d_info[i][random.randint(0, len(dictionaire_d_info[i]) - 1)]
        else:
            S += i
    return S


def decrypthomo(string):
    l = splitword2(string)
    decrypted = []
    for i in l:
        for key in dictionaire_d_info:
            if i in dictionaire_d_info[key]:
                decrypted.append(key)
    lis = string.split()
    la = []
    lb = []
    lc = []
    for i in range(len(lis) - 1):
        la.append(lis[i])
        la.append(' ')
    la.append(lis[len(lis) - 1])
    for i in la:
        if i != ' ':
            lb.append(splitword2(i))
        else:
            lb.append(i)
    for i in lb:
        if i != ' ':
            for j in range(len(i)):
                lc.append(i[j])
        else:
            lc.append(i)
    j = 0
    for i in range(len(lc)):
        if lc[i] != ' ':
            lc[i] = decrypted[j]
            j += 1
    return "".join(lc)


"""Cesar Cipher"""


def encryptcesar(shift, plaintext):  # encrypte the plaintext
    T = splitword(plaintext)
    T2 = []
    for i in T:
        if ord(i) >= 65 and ord(i) <= 90:
            T2.append(chr(((ord(i) + shift - 65) % 26) + 65))
        elif ord(i) >= 97 and ord(i) < 123:
            T2.append(chr(((ord(i) + shift - 97) % 26) + 97))
        else:
            T2.append(i)
    ciphertext = ""
    ciphertext = ciphertext.join(T2)
    return ciphertext


def decryptcesar(shift, ciphertext):  # decrypte ciphertext
    T = splitword(ciphertext)
    T2 = []
    for i in T:
        if ord(i) >= 65 and ord(i) <= 90:
            T2.append(chr(((ord(i) - shift - 65) % 26) + 65))
        elif ord(i) >= 97 and ord(i) < 123:
            T2.append(chr(((ord(i) - shift - 97) % 26) + 97))
        else:
            T2.append(i)
    plaintext = ""
    plaintext = plaintext.join(T2)
    return plaintext


"""Hill Cipher"""


def chr_to_int(char):
    char = char.upper()
    integer = ord(char) - 65
    return integer


def create_matrix_of_integers_from_string(string):
    integers = [chr_to_int(c) for c in string]
    length = len(integers)
    M = np.zeros((3, int(length / 3)), dtype=np.int32)
    iterator = 0
    for column in range(int(length / 3)):
        for row in range(3):
            M[row][column] = integers[iterator]
            iterator += 1
    return M


def create_matrix_of_integers_for_key(string):
    integers = [chr_to_int(c) for c in string]
    length = len(integers)
    M = np.zeros((3, int(length / 3)), dtype=np.int32)
    iterator = 0
    for row in range(3):
        for column in range(int(length / 3)):
            M[row][column] = integers[iterator]
            iterator += 1
    return M


def hillencrypte(msg, key):
    msg = msg.upper().replace(" ", "")
    ciphertext = ""
    msg = msg[:len(msg) - (len(msg) % 3)]
    mesg3D = create_matrix_of_integers_from_string(msg)
    encry3D = np.zeros((3, len(msg) // 3), dtype=int)
    key = key.upper().replace(" ", "")
    if len(key) != 9:
        return "Invalid key"
    else:
        key3D = create_matrix_of_integers_for_key(key)
        det = int(np.linalg.det(key3D)) % 26
        mul_inv = -1
        for i in range(26):
            temp_inv = det * i
            if temp_inv % 26 == 1:
                mul_inv = i
                break
            else:
                continue
        if mul_inv == -1:
            return "Invalid key"
        else:
            for i in range(len(msg) // 3):
                encry3D[:, i] = key3D.dot(mesg3D[:, i]) % 26
            for i in range(len(encry3D[0])):
                for j in range(len(encry3D)):
                    ciphertext += chr(encry3D[j][i] + 65)
            return ciphertext


def hilldecrypte(msg, key):
    msg = msg.upper().replace(" ", "")
    plaintext = ""
    msg = msg[:len(msg) - (len(msg) % 3)]
    mesg3D = create_matrix_of_integers_from_string(msg)
    encry3D = np.zeros((3, len(msg) // 3), dtype=int)
    key = key.upper().replace(" ", "")
    if len(key) != 9:
        return "Invalid key"
    else:
        key3D = create_matrix_of_integers_for_key(key)
        det = np.linalg.det(key3D) % 26
        mul_inv = -1
        for i in range(26):
            temp_inv = det * i
            if temp_inv % 26 == 1:
                mul_inv = i
                break
            else:
                continue
        if mul_inv == -1:
            return "Invalid key"
        else:
            key3D = Matrix(key3D).adjugate()
            key3D = np.array(key3D)
            key3D = (mul_inv * key3D) % 26
            for i in range(len(msg) // 3):
                encry3D[:, i] = key3D.dot(mesg3D[:, i]) % 26
            for i in range(len(encry3D[0])):
                for j in range(len(encry3D)):
                    plaintext += chr(encry3D[j][i] + 65)
            return plaintext


"""Vigenere Cipher"""
universe = [c for c in (chr(i) for i in range(32, 127))]
uni_len = len(universe)


def vignere(txt='', key='', typ='d'):
    if not txt:
        return 'Needs text.'
    if not key:
        return 'Needs key.'
    if typ not in ('d', 'e'):
        return 'Type must be "d" or "e".'
    if any(t not in universe for t in key):
        return 'Invalid characters in the key. Must only use ASCII symbols.'
    ret_txt = ''
    k_len = len(key)
    for i, l in enumerate(txt):
        if l not in universe:
            ret_txt += l
        else:
            txt_idx = universe.index(l)
            k = key[i % k_len]
            key_idx = universe.index(k)
            if typ == 'd':
                key_idx *= -1
            code = universe[(txt_idx + key_idx) % uni_len]
            ret_txt += code
    return ret_txt


"""Vernam Cipher"""
standardkey = []


def vernamencrypt(key, message):
    global standardkey
    message = str(message)
    m = message.upper().replace(" ", "")
    encryptest = ""
    encrypt = ""
    lastencrypt = ""
    a = 0
    if key in standardkey:
        return "This key is already used"
    elif len(key) < len(message):
        return "the lenght of the key is lower than the lenght of the message.Try to give a valid key"
    else:
        standardkey.append(key)
        key = key.upper().replace(" ", "")
        for i in range(len(m)):
            encryptest += chr((((ord(m[i]) - 65) + (ord(key[i]) - 65)) % 26) + 65)
        for i in range(len(message)):
            if not message[i].isalpha():
                encrypt += message[i]
                a += 1
            else:
                encrypt += encryptest[i - a]
        for i in range(len(message)):
            if message[i].isupper():
                lastencrypt += encrypt[i].upper()
            else:
                lastencrypt += encrypt[i].lower()
        return lastencrypt


def vernamdecrypt(key, message):
    message = str(message)
    m = message.upper().replace(" ", "")
    decryptest = ""
    decrypt = ""
    lastdecrypt = ""
    a = 0
    if len(key) < len(message):
        return "the lenght of the key is lower than the lenght of the message.Try to give a valid key"
    else:
        key = key.upper().replace(" ", "")
        for i in range(len(m)):
            decryptest += chr((((ord(m[i]) - 65) - (ord(key[i]) - 65)) % 26) + 65)
        for i in range(len(message)):
            if not message[i].isalpha():
                decrypt += message[i]
                a += 1
            else:
                decrypt += decryptest[i - a]
        for i in range(len(message)):
            if message[i].isupper():
                lastdecrypt += decrypt[i].upper()
            else:
                lastdecrypt += decrypt[i].lower()
        return lastdecrypt


"""Sub Cipher"""


def matrixTR(key, msg):
    taille = len(key)
    cpt = 0
    msg = msg.replace(" ", "#")
    if len(msg) % taille != 0:
        msg += "#" * (taille - len(msg) % taille)
    matrix = np.chararray((len(msg) // taille, len(key)))
    for i in range(len(matrix)):
        for j in range(len(matrix[0])):
            matrix[i][j] = msg[cpt]
            cpt += 1
    return matrix


def encryptSub(key, msg):
    cipher = ""
    mat = matrixTR(key, msg)
    tablekey = [char for char in key]
    tablekeyindex = cp.deepcopy(tablekey)  # on utilise une deepcopie pour que notre premiere var reste intacte
    tablekeyindex.sort()
    matrixF = cp.deepcopy(mat)
    for i in range(len(tablekeyindex)):
        matrixF[:, i] = mat[:, tablekey.index(tablekeyindex[i])]
        tablekey[tablekey.index(tablekeyindex[i])] = "#"
    for i in range(len(matrixF)):
        for j in range(len(matrixF[0])):
            cipher += str(matrixF[i][j])[1:]
    return cipher.replace("'", "")


def decryptSub(key, msg):
    plaintext = ""
    mat = matrixTR(key, msg)
    tablekey = [char for char in key]
    tablekeyindex = cp.deepcopy(tablekey)
    tablekeyindex.sort()
    matrixF = cp.deepcopy(mat)
    for i in range(len(tablekeyindex)):
        matrixF[:, i] = mat[:, tablekeyindex.index(tablekey[i])]
        tablekeyindex[tablekeyindex.index(tablekey[i])] = "#"
    for i in range(len(matrixF)):
        for j in range(len(matrixF[0])):
            plaintext += str(matrixF[i][j])[1:]
    plaintext = plaintext.replace("'", "")
    plaintext = plaintext.replace("#", " ")
    plaintext = plaintext.rstrip()
    return plaintext


"""ECB"""


def ECBencypt(key, block, text):
    ind = 0
    T = [text[i:i + block] for i in range(0, len(text), block)]
    cipher = ""
    for i in T:
        cipher += vignere(i, key, 'e')
    cipher = cipher[:len(text) - ind]
    return cipher


def ECBdecypt(key, block, text):
    ind = 0
    T = [text[i:i + block] for i in range(0, len(text), block)]
    cipher = ""
    for i in T:
        cipher += vignere(i, key, 'd')
    cipher = cipher[:len(text) - ind]
    return cipher


"""CTR"""


##Couter-mode-encryption(CTR)

# encrypt a phrase using a shift value
def shift_phrase(phrase, decalage):
    phrase_cryptee = []
    for lettre in phrase:
        code_lettre_cryptee = (ord(lettre) + decalage) % 255
        lettre_cryptee = chr(code_lettre_cryptee)
        phrase_cryptee.append(lettre_cryptee)
    phrase_cryptee = "".join(phrase_cryptee)
    return phrase_cryptee


# Binay coded msg ,each letter made up of one Byte
def bin_block(msg):
    B = []
    for i in msg:
        b = bin(ord(i)).replace("0b", "")
        z = 8 - len(b)
        B.append((z * "0") + b)
    return B


# Encrypt or decrypt a message: m with a key k, and an initial value of the counter:counter using CTR encryption/decryption
def en_dec_CTR(m, k, counter):
    # complete the msg with zeros so its lenght would be a multiple of the key lenght
    t_k = len(k)
    r = len(m) % t_k
    m += ((t_k - r) * "0")
    # divide the msg into blocks with the same lenght as the key
    M = []
    q = len(m) // t_k
    for i in range(0, q):
        M.append(m[i * t_k:(i + 1) * t_k])
    # XOR operation between each block of the msg and the encrypted and incremented counter (binary form)
    bin_crypt = []
    for i in range(0, q):
        B = bin_block(M[i])
        B = "".join(B)
        en_k = shift_phrase(str((int(counter) + i) % (2 ** t_k)), len(k))
        en_k = en_k + ((t_k - len(en_k)) * "0")
        cpt_bin = bin_block(en_k)
        cpt_bin = "".join(cpt_bin)
        bin_crypt.append("".join([str(int(B[k]) ^ int(cpt_bin[k])) for k in range(0, len(cpt_bin))]))
    # recover the chr form of the encrypted msg
    msg_crypt = []
    for i in range(0, q):
        for j in range(0, t_k):
            msg_crypt.append(bin_crypt[i][j * 8:(j + 1) * 8])
    msg_crypt = [chr(int(msg_crypt[i], 2)) for i in range(0, (q * t_k) - (t_k - r))]
    return "".join(msg_crypt)


"""RC4"""


def KSA(key):
    key_length = len(key)
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % key_length]) % 256
        S[i], S[j] = S[j], S[i]
    return S


def PRGA(S):
    i = 0
    j = 0
    while True:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]  # swap values
        K = S[(S[i] + S[j]) % 256]
        yield K


def get_keystream(key):
    S = KSA(key)
    return PRGA(S)


def encrypt(key, text):
    key = [ord(c) for c in key]
    keystream = get_keystream(key)
    res = []
    for c in text:
        val = ("%02X" % (c ^ next(keystream)))  # XOR
        res.append(val)
    return ''.join(res)


def encrypt_Hex(key, plaintext):
    plaintext = [ord(c) for c in plaintext]
    return encrypt(key, plaintext)


def encrypt_bin(key, plaintext):
    plaintext = [ord(c) for c in plaintext]
    HEX = encrypt(key, plaintext)
    return bin(int(HEX, 16)).zfill(8)


def decrypt_Hex(key, ciphertext):
    ciphertext = codecs.decode(ciphertext, 'hex_codec')
    res = encrypt(key, ciphertext)
    return codecs.decode(res, 'hex_codec').decode('utf-8')


def decrypt_bin(key, ciphertext):
    ciphertextconv = "{0:0>4X}".format(int(ciphertext, 2))
    ciphertextconv = codecs.decode(ciphertextconv, 'hex_codec')
    res = encrypt(key, ciphertextconv)
    return codecs.decode(res, 'hex_codec').decode('utf-8')


"""CBC"""


def div(text):
    lenn = len(text)
    s = 0
    for i in range(1, lenn):
        if lenn % i == 0:
            s = i
    return s


def CBCencryption(text, key):
    block = div(text)
    init = "A" * block
    T = [text[i:i + block] for i in range(0, len(text), block)]
    T0 = []
    for i in T:
        T0.append(vignere(binar(i, init), key, 'e'))
        init = vignere(binar(i, init), key, 'e')
    return "".join(T0)


def CBCdecryption(text, key):
    block = div(text)
    init = "A" * block
    T = [text[i:i + block] for i in range(0, len(text), block)]
    T0 = []
    for i in T:
        T0.append(binar(init, vignere(i, key, 'd')))
        init = i
    return "".join(T0)


def binar(text, mesg):
    T = [bin(ord(i))[2:] for i in text]
    T0 = [bin(ord(i))[2:] for i in mesg]
    T1 = []
    T2 = []
    for i in range(len(T)):
        T[i] = "0" * (8 - len(T[i])) + str(T[i])
    for i in range(len(T0)):
        T0[i] = "0" * (8 - len(T0[i])) + str(T0[i])
    for i in range(len(T)):
        for j in range(8):
            T1.append(str((int(T[i][j]) ^ int(T0[i][j]))))
    for i in range(0, len(T1), 8):
        T2.append(chr((int("".join(T1[i:i + 8]), 2))))
    return "".join(T2)
