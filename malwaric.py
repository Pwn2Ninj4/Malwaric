import config
from Malwaric.modules import banner
from Malwaric.modules import colors
from Malwaric.tools import interpreter
from Malwaric.MalwaricData import *
import sys
from argparse import ArgumentParser, RawTextHelpFormatter, ArgumentTypeError

def arguments():
    parser = ArgumentParser(description=f"{colors.red}\t\tMalwaric.py{colors.normal}\n\t{colors.blue}>{colors.normal}By D4nex", formatter_class=RawTextHelpFormatter)
    parser.optional_title = "Arguments"
    parser.add_argument('-f', "--file", help='Select a file for analysis', metavar='')
    parser.add_argument('-i', "--interactive", help='Analyze the file from an interactive console', action='store_true')
    args = parser.parse_args()
    return args
    
if __name__ == '__main__':
    
    TOKEN = config.API_TOKEN
    args = arguments()
    
    file = args.file
    
    if args.interactive:
        banner.get()
        interpreter.run(file, TOKEN)
    
    else:
        print(f"\n{colors.red}[!]Usage: {colors.normal}python malwaric.py --help {colors.red}<help_menu>{colors.normal}")




