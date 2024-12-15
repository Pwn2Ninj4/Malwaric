import requests
import json
import time

from Malwaric.modules import colors

try:
    import vt
except ImportError:
    print("Cannot import vt-py, Not support for VirusTotal API")
        
class MalwaricDiscovery:
    """
    MalwaricDiscovery is a class for analyzing files and hosts using the Virus Total API and discovery
            
        Method VTSCAN_FILE: Scans the file using the VT API to detect possible signatures similar to other malware within the binary.
        
        Method VTSCAN_URL: Scan a url using the VT api to detect possible malware within the urls.
        
        Method IP_INFO: Extract geolocation data from an IP address
    """
    
    
    def __init__(self, objects, vt_token=None):
        
        self.file = objects #file
        self.url = objects #url
        self.ip = objects #ip_address
        self.ip_api = "http://ip-api.com/json/"
        self.vt_token = vt_token
        self.client = vt.Client(f"{vt_token}")
    
    def VTSCAN_FILE(self):
        """
        Method: Scans the file using the VT API to detect possible signatures similar to other malware within the binary
        """
        
        try:
            with open(self.file, 'rb') as f:
                analysis = self.client.scan_file(f)
                myobject = self.client.get_object("/analyses/{}", analysis.id)
            results = myobject.results
            
            time.sleep(4)
            if len(results) < 4:
                time.sleep(120)
                return results
                
            elif len(results) >= 4:
                
                return results
            
        except Exception as e:
            print(f"{colors.red}An error has ocurred{colors.normal}: {e}")
            
    def VTSCAN_URL(self):
        """
        Method: Scan a url using the VT api to detect possible malware within the urls
        """
        try:
            analysis = self.client.scan_url(self.url)
            myobject = self.client.get_object("/analyses/{}", analysis.id)
            
            results = myobject.results
            
            time.sleep(4)
            if len(results) <= 4:
                time.sleep(120)
                return results
                
            elif len(results) >= 4:
                return results
                
        except Exception as e:
            print(f"{colors.red}An error has ocurred{colors.normal}: {e}")
            
    def IP_INFO(self):
        """
        Method: Extract geolocation data from an IP address
        """
        
        full_url = f"{self.ip_api}{self.ip}"
        
        try:
            response = requests.get(full_url)
            data = response.text
            values = json.loads(data)
            
            return values
            
        except Exception as e:
            print(f"{colors.red}An error has ocurred{colors.normal}: {e}")
        