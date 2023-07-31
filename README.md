# ObfuscatorPy

## Parameters:

- `--target-application-path:` Change the target app which you'll inject into

- `--obfuscator-list:` Choose obfuscation list

- `--msfvenom-command:` Give a shellcode directly from an `msfvenom` command (not to be used with `--shellcode`)

- `--shellcode:` Provide a shellcode (bin) file (output from msfvenom, C2) (not to be used with `--msfvenom-command`)

- `--cpu:` Change cpu type (amd64, i386 etc.)

- `--app:` Final application type (gui, console, dll etc.)

## Example commands:

### From bin file

`./ObfuscatorPy.py -sc messagebox.bin -ol "rot13,base64,rot13" -o /home/user/output.exe`

1. Get a shellcode from a bin file (output of msfvenom, C2)

2. Use rot13, base64 and rot13 again to obfuscate the shellcode

3. Output to `/home/user/output.exe` (default is `output/output.exe`)

4. Note: rot13 won't change the shellcode as bytes but as a string (letter by letter)

### From direct msfvenom command

`./ObfuscatorPy.py -ol "aes-cbc" -mc "msfvenom -p windows/x64/messagebox -f nim" -o "/home/user/output.exe"`

1. Get the shellcode directly from `msfvenom` (format must be what you want the injector language to be - in this case: nim)

2. Use aes-cbc to obfuscate the shellcode

3. Output to `/home/user/output.exe` (default is `output/output.exe`)

4. Note: rot13 won't change the shellcode as bytes but as a string (letter by letter)



### More in --help
