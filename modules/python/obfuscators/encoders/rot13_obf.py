from codecs import encode
import json

# NOTE: The passed shellcode is a string, so the function doesn't shift shellcode's bytes, but the characters in the text

config = json.load(open(file='./config.json', encoding="utf-8"))    # Read json config file
DEOBFUSCATION_CODE_PLACEHOLDER = config["deobfuscation_code_placeholder"]
DEOBFUSCATION_FUNCTION_PLACEHOLDER = config["deobfuscation_function_placeholder"]

rot13_decode = f"""
proc rot13decode(stringToEncode: string): string =
    for c in stringToEncode:
        case toUpperAscii(c)
            of 'N'..'Z':
                result = result & chr(ord(c) - 13)
            of 'A'..'M':
                result = result & chr(ord(c) + 13)
            else:
                result = result & c

{DEOBFUSCATION_FUNCTION_PLACEHOLDER}
"""

rot13_decoding_code = f"""
for i in 0..<{{}}:            # Count added in add_rot13_decoding_code()
    sc = rot13decode(sc)

# Adding this so other obfuscators can inject their codes too
{DEOBFUSCATION_CODE_PLACEHOLDER}
"""

def rot13_obf(sc: str, count: int = 1) -> str:
    for _ in range(count):
        sc = encode(sc, 'rot13')
        # print(sc + '\n')  # DEBUG
    return sc

def add_rot13_decoding_code(nim_code: str, count: int = 1) -> str:
    nim_code = nim_code.replace(DEOBFUSCATION_CODE_PLACEHOLDER, rot13_decoding_code.format(count))
    return nim_code