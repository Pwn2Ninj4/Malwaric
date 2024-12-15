import os
import math
import re

from Malwaric.modules import entropy
from Malwaric.modules import colors


try:
    import pefile
except ImportError:
    print("Cannot import pefile library")

class MalwaricData:
    """
    MalwaricData is a class to extract data about the analyzed binary (Metadata, Sections, Urls and embedded files, among other things)
    
        Method METADATA: Extract binary's metadata.
        
        Method STRINGS: Extra the strings from the binary with a length of 10 or more.
        
        Method SECTIONS: List the sections of a binary and its characteristics.
        
        Method API_CALLS: Shows malicious Windows API calls made by the binary.
        
        Method DUMP_URL: Extract possible urls or IP addresses within the binary strings.
        
        Method DUMP_IMPORT: Shows the DLLs used by the binary.
        
        Method EXTRACT_EMB: Extract possible files embedded within the binary.
    """
    
    def __init__(self, objects):
        
        self.file = objects
        self.url_pattern = b'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        
    def METADATA(self):
        """
        Method: Extract binary's metadata
        """
        try:
            info= {
        'File Size(bytes)': os.path.getsize(self.file),
        'Time Stamp': os.path.getmtime(self.file),
        'File Type': 'PE' if self.file.endswith('.exe') or self.file.endswith('.dll') else 'Other',
        'Extension': os.path.splitext(self.file)[1]
                
            }
    
            if info['File Type'] == 'PE':
                pe = pefile.PE(self.file)
                pe_info = {
            'Entry Point': hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
            'Subsystem': pe.OPTIONAL_HEADER.Subsystem
                }
                return {**info, **pe_info}
            return info
        except Exception as e:
            
            print(f"{colors.red}An error has ocurred{colors.normal}: {e}")
            

    def STRINGS(self, leng=10):
        """
        Method: Extra the strings from the binary with a length of 10 or more
        """
        
        iter_strings = {}
        try:
            with open(self.file, 'rb') as f:
                content = f.read()
                
                strings = re.findall(rb'[\x20-\x7E]{' + str(leng).encode() + rb',}', content)
            
                for index, string in enumerate(strings):
                    iter_strings[index] = string.decode('utf-8', errors='ignore')
                    
        except Exception as e:
            print(f"{colors.red}An error has ocurred{colors.normal}: {e}")
        
        return iter_strings
        
    def SECTIONS(self):
        """
        Method: List the sections of a binary and its characteristics
        """
        
        try:
            pe_file = pefile.PE(self.file)
            info = {}
            
            for section in pe_file.sections:
                perms = []
                section_name = section.Name.decode('utf-8').strip('\x00')
                
                if section.Characteristics & 0x20000000:  # IMAGE_SCN_EXECUTE (0x20000000)
                    perms.append("X")
                if section.Characteristics & 0x40000000:  # IMAGE_SCN_WRITE (0x40000000)
                    perms.append("W")
                if section.Characteristics & 0x80000000:  # IMAGE_SCN_READ (0x80000000)
                    perms.append("R")
                
                perms_str = ', '.join(perms) if perms else "Ninguno"
                
                info[section_name] = {
                    "Virtual Address": hex(section.VirtualAddress),
                    "Virtual Size": hex(section.Misc_VirtualSize),
                    "Data Size": hex(section.SizeOfRawData),
                    "Permissions": perms_str,
                    "Entropy": str(entropy.getEntropy(section.get_data()))
                }
            pe_file.close()
            return info
                
        except Exception as e:
            print(f"{colors.red}An error has ocurcolors.red{colors.normal}: {e} | Not PE binary")
            
    def API_CALLS(self):
        """
        Method: Shows malicious Windows API calls made by the binary.
        """
        
        api_calls = []
        try:
            pe = pefile.PE(self.file)
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    api_calls.append(imp.name.decode('utf-8') if imp.name else None)
            return api_calls
                
                    
        except Exception as e:
            print(f"{colors.red}An error has ocurred{colors.normal}: {e}")
            
    def DUMP_URL(self):
        """
        Extract possible urls or IP addresses within the binary strings
        """
        
        try:
            
            with open(self.file, 'rb') as f:
                file_content = f.read()
                
            urls = re.findall(self.url_pattern, file_content)
            return urls
            
        except Exception as e:
            print(f"{colors.red}An error has ocurred{colors.normal}: {e}")

    def DUMP_IMPORT(self):
        """
        Method: Shows the DLLs used by the binary
        """
        
        try:
            pe = pefile.PE(self.file)
            imports_info ={}
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    
                    dll_name = entry.dll.decode('utf-8')
                    functions = []
                    
                    for imports in entry.imports:
                        functions.append({
                            "Name": imports.name.decode('utf-8') if imports.name else None,
                            "Address": hex(imports.address) if imports.address else None,
                            })
                    imports_info[dll_name] = functions
            return imports_info
            
        except Exception as e:
            print(f"{colors.red}An error has ocurred{colors.normal}: {e}")
            
    def EXTRACT_EMB(self):
        """
        Extract possible files embedded within the binary
        """
        
        try:
            pe = pefile.PE(self.file)
            if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
                for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    if hasattr(resource_type, 'directory'):
                        for resource_id in resource_type.directory.entries:
                            if hasattr(resource_id, 'directory'):
                                for resource_lang in resource_id.directory.entries:
                                    data = pe.get_data(resource_lang.data.struct.OffsetToData, resource_lang.data.struct.Size)
                                    file_name = f"{self.file}_resource_{resource_type.struct.Id}_{resource_id.struct.Id}_{resource_lang.struct.Id}"
                                    with open(file_name, 'wb') as f:
                                        f.write(data)
                                    print(f"{colors.red}Embed Resource{colors.normal}: {file_name}")
            else:
                print(f"\n{colors.red}Embed Resource Not Found{colors.normal}")
        except Exception as e:
            print(f"{colors.red}An error has ocurred{colors.normal}: {e}")