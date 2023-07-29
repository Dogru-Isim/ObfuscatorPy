#!/usr/bin/env python3
import sys
import binascii
import json

config = json.load(open(file='./config.json', encoding="utf-8"))    # Read json config file
TEMPORARY_SHELLCODE_FILENAME = config["temporary_shellcode_filename"]

def read_file(filename: str) -> str:
    print("Reading file...")
    with open(filename, 'rb') as f:
        bin_data = f.read()
    return bin_data

def convert2hex(bin_data: str) -> str:
    print("Converting to hex...")
    sc = binascii.hexlify(bin_data, sep=',').decode()
    return sc

def print2file(sc: str):
    print("Formatting...")
    with open(TEMPORARY_SHELLCODE_FILENAME , "w") as f:
        f.write('0x')
        f.write(sc.replace(",", ",0x"))

def bin2sc(filename: str):
    bin_data = read_file(filename)
    sc = convert2hex(bin_data)
    print2file(sc)

if __name__ == "__main__":
    filename = sys.argv[1]
    bin2sc(filename)
    