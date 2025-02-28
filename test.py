import base64
import pefile
import os
import sys

"""
- check wether the character return 0 or not and from deep analysis it always return one so I ignored this part
- get the character index from the custom base
- get the number index from the custom base
- sub number index from length of the custom base
- add the result to the charactar index
- get the mod with 3f which is the length of the custom base to make sure it's in the range
- it's the index of the character to be replaced and the actual of the base64 encoded string
- add padding to the string to make sure it's a multiple of 4
- decode the base64 encoded string
"""

base = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 "
key = "79b045586f66910a6b18ceb88b16c09b"

def write_configs(string):  # this function is used to write the decoded strings to a file called configs.txt
    with open("configs.txt", "a") as f:
        f.write(string + "\n")
  
        
def decode_base64(string):
    x = 0
    f_string = ""
    for c in (string):
        if c == "=":
            break
        if c == '+':
            f_string += '+'
            continue
        for i, cc in enumerate(base):
            if cc == c:
                char_index = i
                break
            else:
                char_index = -1
        for i, cc in enumerate(base):
            if cc == key[x % len(key)]:
                num_index = i
                break
            else:
                num_index = -1
        result = 63 - num_index
        result = (char_index + result) % 63
        f_string += base[result]
        x += 1
    # Add padding to f_string
    f_string += '=' * ((4 - len(f_string) % 4) % 4)
    return f_string


def get_data(pe_exe):
    pe = pefile.PE(pe_exe)
    for section in pe.sections:
        if ".rdata" in section.Name.decode('utf-8'):
            string = section.get_data()
            #return string[49224:51930]
            return string


def decrypt_configs(string):
    d_string = ""
    count = 0
    config_num = 0
    f_string = ""
    for c in string:
        if c != 0:
            d_string += chr(c)
            count = 0
        elif c == 0:
            try:
                if count < 1:
                    count += 1
                    config_num += 1
                    write_configs(f"Encoded Base64: {d_string}")
                    f_string = decode_base64(d_string)
                    decoded_string = base64.b64decode(f_string).decode('utf-8')
                    print(f"Encoded Base64: {d_string}")
                    print(f"Decoded Base64: {f_string}")
                    print(f"Decoded String --> {decoded_string} \n")
                    d_string = ""
                    write_configs(f"Decoded Base64: {f_string}")
                    write_configs(f"Decoded String --> {decoded_string}\n")
                else:
                    continue
            except:
                d_string = ""
                continue
    return config_num


if __name__ == "__main__":
    """ if len(sys.argv) != 2:
        print("Usage: python test.py <path_to_exe>")
        sys.exit(1) """
    string = get_data(r'D:\Malware\3BFE6351E6073548\book.bin')
    #print(string)
    config_num = decrypt_configs(string)
    write_configs(f"\nConfigurations Found: {config_num}")
    print(f"Configurations Found: {config_num}")



