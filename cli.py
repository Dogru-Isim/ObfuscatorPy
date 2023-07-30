import argparse
import sys
import json

config = json.load(open(file="./config.json", encoding="utf-8"))

AVAILABLE_OBFUSCATION_METHODS = config["available_obfuscation_methods"].split(',')
AVAILABLE_APP_TYPES = config["application_configs"]["available_app_types"].split(',')

DEFAULT_APP_TYPE = config["application_configs"]["default_app_type"]
DEFAULT_OUTPUT_PATH = config["application_configs"]["default_output_path"]
DEFAULT_CPU_TYPE = config["application_configs"]["default_cpu_type"]
DEFAULT_TARGET_APP = config["default_target_app"]

TOOL_NAME = config["tool_name"]

def generate_cli_args():
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description='Obfuscate shellcode',
        conflict_handler='resolve'
    )

    parser.add_argument("-ap", "--target-application-path", default=DEFAULT_TARGET_APP, help="full path of the application to inject into (default: notepad)")
    parser.add_argument("-ol", "--obfuscator-list", required=True, help=f"A list of comma seperated obfuscation methods that will be used sequentially to obfuscate the shellcode {{{','.join(AVAILABLE_OBFUSCATION_METHODS)}}}")
    # Shellcode options
    parser.add_argument("-mc", "--msfvenom-command", help="msfvenom shellcode generation command (necessary if you want to generate with metasploit)")
    parser.add_argument("-sc", "--shellcode", help="path to shellcode (raw or python formatted 0x41,0x42...) necessary if --msfvenom-command is not specified")
    # Compiler options
    parser.add_argument("--cpu", default=DEFAULT_CPU_TYPE, help="cpu type: amd64|i386|arm etc. (default: amd64)")
    parser.add_argument("--app", default=DEFAULT_APP_TYPE, choices=AVAILABLE_APP_TYPES, help=f"app type: {'|'.join(AVAILABLE_APP_TYPES)} (default: {DEFAULT_APP_TYPE})")
    parser.add_argument("-o", "--output", default=DEFAULT_OUTPUT_PATH, help="path for the final binary")

    args = parser.parse_args()
    if not args.msfvenom_command:
        parser.add_argument("-sc", "--shellcode", required=True, help="path to shellcode (raw or python formatted 0x41,0x42...) necessary if --msfvenom-command is not specified")
    
    # Change default name from .exe to .dll if the user wants a dll
    if args.output == DEFAULT_OUTPUT_PATH and args.app == "lib":
        args.output = args.output.split('.')[0] + '.dll'    # Change .exe to .dll


    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()
    return args
