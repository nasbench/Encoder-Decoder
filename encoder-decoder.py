import base64
import hashlib
import os
import sys
import binascii


def xor(data, key):
    return bytearray(a^b for a, b in zip(*map(bytearray, [data, key])))


def md5(string_to_hash):
    return hashlib.md5(string_to_hash).hexdigest()


def sha1(string_to_hash):
    return hashlib.sha1(string_to_hash).hexdigest()


def sha224(string_to_hash):
    return hashlib.sha224(string_to_hash).hexdigest()


def sha256(string_to_hash):
    return hashlib.sha256(string_to_hash).hexdigest()


def sha384(string_to_hash):
    return hashlib.sha384(string_to_hash).hexdigest()


def sha512(string_to_hash):
    return hashlib.sha512(string_to_hash).hexdigest()


def hash_all(string_to_hash):
    print ("\n")
    print ("MD5    : " + str(md5(string_to_hash)))
    print ("SHA1   : " + str(sha1(string_to_hash)))
    print ("SHA224 : " + str(sha224(string_to_hash)))
    print ("SHA256 : " + str(sha256(string_to_hash)))
    print ("SHA384 : " + str(sha384(string_to_hash)))
    print ("SHA512 : " + str(sha512(string_to_hash)))


def en_base2(string_to_encode):
    return "0" + bin(int(binascii.hexlify(string_to_encode), 16))[2:]


def de_base2(string_to_decode):
    try:
        s = int(string_to_decode, 2)
        binascii.unhexlify('%x' % s)
    except (TypeError, ValueError) :
        print ("Non-Binary String Provided")


def en_base16(string_to_encode):
    return base64.b16encode(string_to_encode)


def de_base16(string_to_decode):
    try:
        if string_to_decode[:2].lower() == '0x':
            string_to_decode = string_to_decode[2:]
        decoded_string = base64.b16decode(string_to_decode)
        return decoded_string
    except TypeError:
        print ("Non-Hexadecimal String Provided")


def en_base32(string_to_encode):
    return base64.b32encode(string_to_encode)


def de_base32(string_to_decode):
    try:
        decoded_string = base64.b32decode(string_to_decode)
        return decoded_string
    except TypeError:
        print ("Non-Base32 String Provided")


def en_base64(string_to_encode):
    return base64.b64encode(string_to_encode)


def de_base64(string_to_decode):
    try:
        decoded_string = base64.b64decode(string_to_decode)
        return decoded_string
    except TypeError:
        print ("Non-Base64 String Provided")


def en_all(string_to_encode):
    print ("Binary : " + str(en_base2(string_to_encode)))
    print ("Base16 : " + str(en_base16(string_to_encode)))
    print ("Base32 : " + str(en_base32(string_to_encode)))
    print ("Base64 : " + str(en_base64(string_to_encode)))


def de_all(string_to_decode, string_type):
    if string_type == "b":
        print ("Decoded String : " + str(de_base2(string_to_decode)))
    elif string_type == "b16":
        print ("Decoded String : " + str(de_base16(string_to_decode)))
    elif string_type == "b32":
        print ("Decoded String : " + str(de_base32(string_to_decode)))
    elif string_type == "b64":
        print ("Decoded String : " + str(de_base64(string_to_decode)))
    else:
        print ("Error")


def get_checksum(file_path, hash_method="all"):
    if hash_method == "md5":
        hash_ = hashlib.md5()
    elif hash_method == "sha1":
        hash_ = hashlib.sha1()
    elif hash_method == "sha224":
        hash_ = hashlib.sha224()
    elif hash_method == "sha256":
        hash_ = hashlib.sha256()
    elif hash_method == "sha384":
        hash_ = hashlib.sha384()
    elif hash_method == "sha512":
        hash_ = hashlib.sha512()

    if hash_method == "all":
        for hash_name, hash_element in {"MD5    ": hashlib.md5(), "SHA1   ": hashlib.sha1(), "SHA224 ": hashlib.sha224(),
                                        "SHA256 ": hashlib.sha256(), "SHA384 ": hashlib.sha384(),
                                        "SHA512 ": hashlib.sha512()}.iteritems():
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_element.update(chunk)
            print (hash_name + ":" + str(hash_element.hexdigest()))
    else:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_.update(chunk)
        print (hash_method.upper() + " : " + str(hash_.hexdigest()))


# Main menu
def main_menu():

    print ("1. Encode")
    print ("2. Decode")
    print ("3. Checksum")
    print ("4. Hash")
    print ("5. XoR")
    print ("\n0. Quit")
    choice = str(raw_input(" >>  "))
    exec_menu(choice)

    return


# Execute menu
def exec_menu(choice):
    print ("\n")
    ch = choice.lower()
    if ch == '':
        menu_actions['main_menu']()
    else:
        try:
            menu_actions[ch]()
        except KeyError:
            print "Invalid selection, please try again.\n"
            menu_actions['main_menu']()
    return


# Encode Menu
def encode_menu():
    string_to_encode = str(raw_input("Enter the string you want to ENCODE : "))
    en_all(string_to_encode)
    exec_menu("9")
    return


# Decode Menu
def decode_menu():
    string_to_decode = str(raw_input("Enter the string you want to DECODE : "))
    string_type = str(raw_input("Enter the string type (b: Binary, b16: Base16, b32: Base32, b64: Base64) : "))
    de_all(string_to_decode, string_type)
    exec_menu("9")
    return


# Checksum Menu
def checksum_menu():
    path_of_file = str(raw_input("Path of file : "))
    get_checksum(path_of_file)
    exec_menu("9")
    return


# Hash Menu
def hash_menu():
    string_to_hash = str(raw_input("Enter the string you want to HASH : "))
    hash_all(string_to_hash)
    exec_menu("9")
    return


# Xor Menu
def xor_menu():
    string_to_xor = str(raw_input("Enter the string you want to XOR : "))
    key = str(raw_input("Key : "))
    print ("Results : " + str(xor(string_to_xor, key)))
    exec_menu("9")
    return


# Back to main menu
def back():
    menu_actions['main_menu']()


# Exit program
def exit_():
    sys.exit()


# Menu definition
menu_actions = {
    'main_menu': main_menu,
    '1': encode_menu,
    '2': decode_menu,
    '3': checksum_menu,
    '4': hash_menu,
    '5': xor_menu,
    '9': back,
    '0': exit_,
}

# Main Program
if __name__ == "__main__":
    main_menu()
