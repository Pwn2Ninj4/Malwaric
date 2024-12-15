import hashlib

class MalwaricHashes:
    #MalwaricHashes is a class to analyze the hashes of a binary (md5, sha1, sha224, sha256, sha512)
    def __init__(self, file):
        
        self.file = file
        self.md5 = hashlib.md5()
        self.sha256 =  hashlib.sha256()
        self.sha1 = hashlib.sha1()
        
    
    def MD5(self):
        
        hasher = self.md5
        with open(self.file, 'rb') as f:
            buff = f.read()
            hasher.update(buff)
        return hasher.hexdigest()
    
    def SHA256(self):
        
        hasher = self.sha256
        with open(self.file, 'rb') as f:
            buff = f.read()
            hasher.update(buff)
        return hasher.hexdigest()
    
    def SHA1(self):
        
        hasher = self.sha1
        with open(self.file, 'rb') as f:
            buff = f.read()
            hasher.update(buff)
        return hasher.hexdigest()