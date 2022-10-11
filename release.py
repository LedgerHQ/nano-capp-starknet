#!/usr/bin/python3

import sys, getopt
import json, shutil

def update_manifest(json_path, version):
    json_file = open(json_path, 'r+')
    data = json.load(json_file)
    
    data['version'] = version
    json_file.seek(0)
    
    json.dump(data, json_file, indent=4)
    json_file.close()

def main(argv):
    target = ''
    version = ''
    try:
        opts, args = getopt.getopt(argv,"ht:v:",["target=", "version="])
    except getopt.GetoptError:
        print ('release.py -t <target>')
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print ('release.py -t <target>')
            sys.exit()
        elif opt in ("-t", "--target"):
            target = arg
        elif opt in ("-v", "--version"):
            version = arg

    if target == 'TARGET_NANOS2':
        update_manifest('pkg/nanosp/nanosp.json', version)
        shutil.copyfile(r'bin/app.hex', r'pkg/nanosp/app_nanosp.hex')

    elif target == 'TARGET_NANOS':
        update_manifest('pkg/nanos/nanos.json', version)
        shutil.copyfile(r'bin/app.hex', r'pkg/nanos/app_nanos.hex')

if __name__ == "__main__":
   main(sys.argv[1:])