from Malwaric.MalwaricHashes import *
from Malwaric.MalwaricDiscovery import *
from Malwaric.MalwaricData import *
from Malwaric.modules import colors
from Malwaric.modules import get_paths as path
from Malwaric.modules import logs
from Malwaric.modules import analysis_database as db

import readline, sys, os

CMD_LOGS = '.malwaric_cmd.log'


if os.path.exists(CMD_LOGS):
    readline.read_history_file(CMD_LOGS)
    
def save_cmd_logs():
    
    readline.write_history_file(CMD_LOGS)
    
def help_panel():
    print(f"\n-create_db                   Start Malwaric database\n-save                        Saves the analysis results of the analyzed file to the database (requires starting the database)\n-view_db                     Review the results of a previously analyzed file (requires starting the database\n\n\t{colors.red}DATA{colors.normal}\n\n-hashes                 Obtain the hashes of the file for later analysis\n-metadata(m/d)          Get the metadata of the file under analysis\n-view_strings(v/s)      View the readable strings of analyzed file\n-sections(s/e)          Obtain information about the sections of the analyzed file (Permissions, Entropy, Others)\n-api_calls(a/c)         Xtract malicious or suspicious calls to the Windows API\n-dump_url(d/u)          Xtract possible urls or ips within the file strings\n-dump_dll(d/d)          Xtracts the shared libraries (DLLs) used by the file\n-x_emb(x/e)             Xtract possible files embedded within the analyzed file (save in an individual document)\n\n\t{colors.red}DISCOVERY{colors.normal}\n\n-file_scan(f/s)                Scan the file using the VirusTotal API for malicious detection signs\n-url_scan(url) <URL>           Scan the URL using the VirusTotal API for malicious detection signs\n-ip_info(ip) <IP_ADDRESS>      Extract information about the IP address (Status, Location, Time Zone, ISP, ASN)\n\n")



def get_hashes(file):
    
    global MD5
    
    hasher = MalwaricHashes(file)
    
    MD5 = hasher.MD5()
    SHA256 = hasher.SHA256()
    SHA1 = hasher.SHA1()
    return MD5, SHA256, SHA1
    
def get_metadata(file):
    
    global Malwaric
    Malwaric = MalwaricData(file)
    
    metadata = Malwaric.METADATA()
    
    return metadata
    
def get_strings(file):
    
    strings = Malwaric.STRINGS()
    return strings
    
def get_api_calls(file):
    
    api_calls = Malwaric.API_CALLS()
    return api_calls

def get_sections(file):
    
    sections = Malwaric.SECTIONS()
    return sections

def get_urls(file):
    
    urls = Malwaric.DUMP_URL()
    return urls

def get_dll(file):
    
    dlls = Malwaric.DUMP_IMPORT()
    return dlls
    
def file_scan(file, vttoken):
    
    vt = MalwaricDiscovery(file, vttoken)
    vt_scan_file = vt.VTSCAN_FILE()
    return vt_scan_file
    
def url_scan(argument, vttoken):
    
    vt = MalwaricDiscovery(argument, vttoken)
    vt_scan_url = vt.VTSCAN_URL()
    return vt_scan_url
    
def get_ip_info(argument, vttoken):
    
    disc = MalwaricDiscovery(argument, vttoken)
    ip_info = disc.IP_INFO()
    return ip_info
    
def run(get_file, token=None):
    
    global file
    global vttoken
    
    file = get_file
    vttoken = token
    
    
    commands ={
        'hashes': get_hashes(get_file),
        'metadata': get_metadata(get_file),
        'view_strings': get_strings(get_file),
        'sections': get_sections(get_file),
        'api_calls': get_api_calls(get_file),
        'dump_url': get_urls(get_file),
        'dump_dll': get_dll(get_file),
    }
    try:
        logs.info(f'Analyzing {file}')
        
        while True:
            
            
            cmd = input(f"[0x{file}]{colors.red}>{colors.normal} ")
            verify_arguments = cmd.split(maxsplit=1)
            cmd = verify_arguments[0]
            argument = verify_arguments[1] if len(verify_arguments) > 1 else None
            
            if cmd == 'help' or cmd == 'h':
                help_panel()
            
            if cmd == 'hashes' in commands:
                hashes = commands[cmd]
                try:
                    if argument:
                        print(f"{colors.red}Invalid input:{colors.normal} <{cmd}> does not accept arguments.")
                        print('\nFor help, type "help"')
                    else:
                        print(f"{colors.red}HASH.MD5{colors.normal}> {hashes[0]}\n{colors.red}HASH.SHA1{colors.normal}> {hashes[2]}\n{colors.red}HASH.SHA256{colors.normal}> {hashes[1]}\n")
                except Exception as e:
                    print(e)
                
                    
            if cmd == 'metadata' in commands or cmd == 'm/d':
                metadata = commands['metadata']
                
                file_size = metadata['File Size(bytes)']
                time_stamp = metadata['Time Stamp']
                file_type = metadata['File Type']
                extensions = metadata['Extension']
                entry_point = metadata['Entry Point']
                subsystem = metadata['Subsystem']
                try:
                    if argument:
                        print(f"{colors.red}Invalid input:{colors.normal} <{cmd}> does not accept arguments.")
                        print('\nFor help, type "help"')
                    else:
                        print(f"\n\n{colors.red}File Size{colors.normal}: \t{file_size}\n{colors.red}File Type{colors.normal}: \t{file_type}\n{colors.red}Time Stamp{colors.normal}: \t{time_stamp}\n{colors.red}Extension{colors.normal}: \t{extensions}\n{colors.red}Entry Point{colors.normal}: \t{entry_point}\n{colors.red}Subsystem{colors.normal}: \t{subsystem}\n\n")
                except Exception as e:
                    print(e)
                    
            if cmd == 'view_strings' in commands or cmd == 'v/s':
                strings = commands['view_strings']
                try:
                    if argument:
                        print(f"{colors.red}Invalid input:{colors.normal} <{cmd}> does not accept arguments.")
                        print('\nFor help, type "help"')
                    else:
                        logs.info('Listing binary strings')
                        for ids, string in strings.items():
                            print(string)
                except Exception as e:
                    print(e)
                
            if cmd == 'sections' in commands or cmd == 's/e':
                sections = commands['sections']
                try:
                    if argument:
                        print(f"{colors.red}Invalid input:{colors.normal} <{cmd}> does not accept arguments.")
                        print('\nFor help, type "help"')
                    else:
                        logs.info('Analyzing sections')
                        for name, info in sections.items():
                            print(f"{colors.red}Section{colors.normal}:{name}")
                            for key, value in info.items():
                                print(f"    {key}: {value}")
                except Exception as e:
                    print(e)
                    
            if cmd == 'api_calls' in commands or cmd == 'a/c':
                api_calls = commands['api_calls']
                try:
                    if argument:
                        print(f"{colors.red}Invalid input:{colors.normal} <{cmd}> does not accept arguments.")
                        print('\nFor help, type "help"')
                    else:
                        logs.info('Searching for malicious API calls')
                        with open(path.api_calls_rules('malicious_api_calls.txt')) as malicious_calls:
                            content = [x for x in (line.strip() for line in malicious_calls) if x]
                            for i in api_calls:
                                if i in content:
                                    print(f"\n{colors.red}[!]Malicious API CALL found{colors.normal}:\t{i}")
                                    
                except Exception as e:
                    print(e)
                
            if cmd == 'dump_url' in commands or cmd == 'd/u':
                logs.info('Searching for urls')
                urls = commands['dump_url']
                for url in urls:
                    print(f"[{colors.red}!{colors.normal}]Extract URL: ")
                    print(url.decode())
            
            if cmd == 'dump_dll' in commands or cmd == 'd/d':
                dlls = commands['dump_dll']
                try:
                    if argument:
                        print(f"{colors.red}Invalid input:{colors.normal} <{cmd}> does not accept arguments.")
                        print('\nFor help, type "help"')
                    else:
                        logs.info('Searching for imported DLLs in the binary')
                        for dll, functions in dlls.items():
                            print(f"\n{colors.red}DLL{colors.normal}:{dll}")
                            for function in functions:
                                print(f"    Name: {function['Name']},         Address: {function['Address']}")
                except Exception as e:
                    print(e)
                    
            if cmd == 'x_emb' or cmd == 'x/e':
                Malwaric.EXTRACT_EMB()
                
            if cmd == 'file_scan' or cmd == 'f/s':
                logs.info('Preparing to analyze the file with VirusTotal')
                results = file_scan(get_file, token)
                for key in results.values():
                    method = key.get("method")
                    engine_name = key.get("engine_name")
                    engine_version = key.get("engine_version")
                    category = key.get("category")
                    result = key.get("result")
                    if category == "malicious":                     
                        
                        
                        print("+-------------------------+-----------+----------------------------------+")
                        print("{2}{0:15s}{2} {3}{1:^5}{4} {2} {3}{5:32s}{4} {2}".format(engine_name, category, '|', colors.blue, colors.normal, result))
                        print("+-------------------------+-----------+----------------------------------+")
                    
                    
            if cmd == 'url_scan' or cmd == 'url':
                if argument:
                    logs.info('Preparing to analyze the  with VirusTotal')
                    results = url_scan(argument, token)
                    
                    for key in results.values():
                        method = key.get("method")
                        engine_name = key.get("engine_name")
                        engine_version = key.get("engine_version")
                        category = key.get("category")
                        result = key.get("result")
                        
                        
                        print("+-------------------------+-----------+------------------+")
                        print("{2}{0:25s}{2} {3}{1:^15s}{4} {2} {3}{5:^10s}{4} {2}".format(engine_name, category, '|', colors.blue, colors.normal, result))
                        print("+-------------------------+-----------+------------------+")
                else:
                    print(f"{colors.red}Invalid input:{colors.normal} <{cmd}> need arguments.")
                    print('\nFor help, type "help"')
                    
            if cmd == 'ip_info' or cmd == 'ip':
                if argument:
                    result = get_ip_info(argument, token)
                    for category, value in result.items():
                        print("+"+"-"*40+"+")
                        print("{3}{0:^15s}{4}{1}{2:^25}{1}".format(category, '|', value, colors.blue, colors.normal))
                        print("+"+"-"*40+"+")
                else:
                    print(f"{colors.red}Invalid input:{colors.normal} <{cmd}> need arguments.")
                    print('\nFor help, type "help"')
                    
            if cmd == "create_db":
                logs.info("Creating database")
                db.create_db()
                
            if cmd == "save":
                hashes = commands['hashes']
                status = input(f"\t{colors.blue}>{colors.normal}Add a status: ")
                engines = input(f'\t{colors.blue}>{colors.normal}Add the engines that detected "malicious": ')
                note = input(f"\t{colors.blue}>{colors.normal}Add a note: ")
                logs.info("Saving analysis in the database")
                
                try:
                    db.insert_db(get_file, hashes[0], status, engines, note)
                except Exception as e:
                    print(f"{colors.red}An error has ocurred{colors.normal}: {e}")
                    
            if cmd == "view_db":
                logs.info("Loading Database")
                data = db.view_content()
                for reports in data:
                    print(reports)
                    
            if cmd == 'quit' or cmd == 'q':
                break
            
    except KeyboardInterrupt:
        print(f"\n{colors.red}KeyboardInterrupt{colors.normal}: Exiting!")
        
    finally:
        save_cmd_logs()
