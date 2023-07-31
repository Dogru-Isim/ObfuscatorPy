from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import json

# Don't touch this, it's working :)

config = json.load(open(file='./config.json', encoding="utf-8"))

DEOBFUSCATION_FUNCTION_PLACEHOLDER = config["deobfuscation_function_placeholder"]
DEOBFUSCATION_CODE_PLACEHOLDER = config["deobfuscation_code_placeholder"]

seperateStringInto2 = f"""
proc seperateStringInto2(buf: string): seq[string] =
    var tmp = ""

    var count = 0
    for letter in buf:
        tmp = tmp & letter
        if count == 1.int:
            result.add(tmp)
            count = 0
            tmp = ""
        else:
            count = count + 1

{DEOBFUSCATION_FUNCTION_PLACEHOLDER}
"""
byteSeqToString = f"""
proc byteSeqToString(bytes: seq[byte]): string =
  result = newString(bytes.len)
  copyMem(result[0].addr, bytes[0].unsafeAddr, bytes.len)

{DEOBFUSCATION_FUNCTION_PLACEHOLDER}  
"""

strToByteSeq = f"""
proc strToByteSeq(str: string): seq[byte] =
    str.seperateStringInto2()
        .map(proc (x: string): string = x.strip())
        .map(parseHexInt)
        .map(proc (x: int): byte = byte x)

{DEOBFUSCATION_FUNCTION_PLACEHOLDER}
"""

decryptAES = f"""
proc decryptAES(enc_sc: string, key: string, iv: string, padding_length: int): string =
    var ctx = initAES()
    let key_seq = strToByteSeq(key)
    let iv_seq = strToByteSeq(iv)
    let sc_seq = strToByteSeq(enc_sc)

    let key_bytes = byteSeqToString(key_seq)
    let iv_bytes = byteSeqToString(iv_seq)
    let sc_bytes = byteSeqToString(sc_seq)

    check ctx.setDecodeKey(key_bytes) == true
    var decrypted = ctx.decryptCBC(iv_bytes, sc_bytes)

    decrypted = decrypted[0..^padding_length+1]  # Remove padding depending on it's length
    decrypted

{DEOBFUSCATION_FUNCTION_PLACEHOLDER}  
"""

def aes_obf(sc: str, key_length: int = 16) -> (str, str, str, str):
    """
    aes_obf(sc, key_length=16)

    Get shellcode, encrypt it using AES-CBC (length=16: 128-bit)

    Return: 
            hex-aes encrypted shellcode (str),

            hex encoded key (str),

            hex encoded iv (str),

            added padding (str)
    """

    key = get_random_bytes(key_length)
    iv = get_random_bytes(key_length)

    padded_sc = b''
    padded_sc = pad(sc.encode(), AES.block_size)
    added_padding = padded_sc.decode().removeprefix(sc)  # Get the added padding so we can return it

    # AES Encrypt (128-bit) (Block size: 16, IV len: 16, Key len: 16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted_sc = cipher.encrypt(padded_sc)

    # AES decrypt (128-bit)
    # NOT USED apart from # DEBUG purposes
    #decrypt_cipher = AES.new(key, AES.MODE_CBC, iv)
    #print(len(unpad(decrypt_cipher.decrypt(encrypted_sc), AES.block_size)))

    hex_aes_sc = encrypted_sc.hex()
    hex_key = key.hex()
    hex_iv = iv.hex()
    padding_length = len(added_padding)

    return hex_aes_sc, hex_key, hex_iv, padding_length

aes_decryption_code = f"""
sc = decryptAES(sc, "{{}}", "{{}}", {{}})

# Adding this so other obfuscators can inject their codes too
{DEOBFUSCATION_CODE_PLACEHOLDER}
"""

def add_aes_decryption_code(nim_code: str, key: str, iv: str, padding_length: str) -> str:
    nim_code = nim_code.replace(DEOBFUSCATION_CODE_PLACEHOLDER, aes_decryption_code.format(key, iv, padding_length))
    return nim_code

if __name__ == '__main__':
    sc = 'Hax0r!'
    hex_aes_sc, hex_key, hex_iv = aes_obf(sc)

    print(
        f"""
        sc: {sc}
        encrypted_sc: {hex_aes_sc}
        key: {hex_key}
        iv: {hex_iv}    
        """
    )

