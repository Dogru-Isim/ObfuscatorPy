# ObfuscatorPy

## Install:

Run the following command in the tools directory.

```shell
bash ./install.sh 
```

This will install the required packages

You can now look at the [Example Commands](## Example Commands) and [Parameters](## Parameters)



## Parameters:

- `--target-application-path:` Change the target app which you'll inject into

- `--obfuscator-list:` Choose obfuscation list

- `--msfvenom-command:` Give a shellcode directly from an `msfvenom` command (not to be used with `--shellcode`)

- `--shellcode:` Provide a shellcode (bin) file (output from msfvenom, C2) (not to be used with `--msfvenom-command`)

- `--cpu:` Change cpu type (amd64, i386 etc.)

- `--app:` Final application type (gui, console, dll etc.)

- **More in `--help`**



## Example Commands:

### From bin file:

`./ObfuscatorPy.py -sc messagebox.bin -ol "rot13,base64,rot13"`

1. Get a shellcode from a bin file (output of msfvenom, C2)

2. Use rot13, base64 and rot13 again to obfuscate the shellcode

3. Output to `./output/output.exe` (default)

4. Note: rot13 won't change the shellcode as bytes but as a string (letter by letter)

### From direct msfvenom command:

`./ObfuscatorPy.py -ol "aes-cbc" -mc "msfvenom -p windows/x64/messagebox -f nim`

1. Get the shellcode directly from `msfvenom` (format must be what you want the injector language to be - in this case: nim)

2. Use aes-cbc to obfuscate the shellcode

3. Output to `./output/output.txt` (default)

4. Note: rot13 won't change the shellcode as bytes but as a string (letter by letter)
