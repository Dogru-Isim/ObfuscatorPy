import base64
import json

config = json.load(open(file='./config.json', encoding="utf-8"))                    # Read json config file
DEOBFUSCATION_CODE_PLACEHOLDER = config["deobfuscation_code_placeholder"]

base64_decoding_code = F"""
for i in 0..<{{}}:
    sc = sc.decode()

# Adding this so other encoders can inject their codes too
{DEOBFUSCATION_CODE_PLACEHOLDER}
"""

# Turn shellcode into base64
def b64_obf(sc: str, count: int = 1) -> str:
    for _ in range(count):
        sc = base64.b64encode(sc.encode()).decode()
        # print(sc + '\n')  # DEBUG
    return sc

def add_base64_decoding_code(nim_code: str, count: int = 1) -> str:
    nim_code = nim_code.replace(DEOBFUSCATION_CODE_PLACEHOLDER, base64_decoding_code.format(count))
    return nim_code
