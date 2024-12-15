import os, sys

#Get malicious calls and malicious signatures

def api_calls_rules(path):
    my_dir = os.path.dirname(sys.modules['__main__'].__file__)
    return os.path.join(my_dir, 'rules/api_calls', path)

def packed_rules(path):
    
    my_dir = os.path.dirname(sys.modules['__main__'].__file__)
    return os.path.join(my_dir, 'rules/packed', path)

def database_path():
    
    my_dir = os.path.dirname(sys.modules['__main__'].__file__)
    databases_dir = str(os.path.join(my_dir, 'database/'))
    return databases_dir