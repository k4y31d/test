import sys
import pefile
import base64
import re

BASE = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 '

def locate_config(data):
    pattern_key = r"[a-f0-9]{32}"  
    key_object = re.search(pattern_key, data)
    key = data[key_object.start() : key_object.end()]
    configs = data
    return configs, key

def get_strings(pe_exe):
    with open(pe_exe,'rb') as f:
        file_data = f.read()
    strings = []
    for m in re.finditer(rb'[a-zA-Z =0-9]{4,}',file_data):
        strings.append(m.group().decode('utf-8'))
    return strings

def is_ascii(s):
    return all(ord(c) < 128 or c == 0 for c in s)

def decode_base64(string, key):
    decoded_string = ""
    for i, char in enumerate(string):
        if char not in BASE:
            decoded_string += char
            continue

        char_index = BASE.find(char)
        num_index = BASE.find(key[i % len(key)])
        f_index = (char_index + len(BASE) - num_index) % len(BASE)
        decoded_string += BASE[f_index]

    try:
        return base64.b64decode(decoded_string).decode('utf-8')
    except Exception:
        return None

def decrypt_configs(string, key):
    strings = [m.group(0) for m in re.finditer(r'[a-zA-Z =0-9]{4,}', string)]
    for s in strings:
        try:
            config = decode_base64(s, key)
            if config and is_ascii(config):
                print(config)
        except Exception:
            continue

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python test.py <path_to_exe>")
        sys.exit(1) 
    string = get_strings(sys.argv[1])
    full_string = "\n".join(string) 
    if full_string:
        string, key = locate_config(full_string)
        if string and key:
            decrypt_configs(string, key)
