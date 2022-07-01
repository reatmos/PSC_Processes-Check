import urllib
import urllib.request
import urllib.parse
import json
import time
import sqlite3
import os

def CheckVT():
    tempkey = '66fe7b2e720aa2f435f0725ace9df1426b90b2b5159eb5cd3b7efd1ac4a3b750'
    host = 'www.virustotal.com'
    surl = 'https://www.virustotal.com/vtapi/v2/file/scan'
    rurl = 'https://www.virustotal.com/vtapi/v2/file/report'
    sha256str = ''
    
    """
    keyfile = open(r"C:\WLAV\Temp\vtkey.txt", 'r')
    line=keyfile.readline()
    vtkey = line.strip('\n')

    """
    txtf = open('C:\PS\Hash.txt', 'r')

    while True:
        line=txtf.readline()
        sha256str = line.strip('\n')
        if not sha256str: break
        parameters = {'resource': sha256str, 'apikey': tempkey}
        data = urllib.parse.urlencode(parameters).encode('utf-8')
        req = urllib.request.Request(rurl, data)
        response = urllib.request.urlopen(req)
        data = response.read()
        data = json.loads(data.decode('utf-8'))
        sha256 = data.get('sha256', {})
        scan = data.get('scans', {})
        keys = scan.keys()
        conn = sqlite3.connect(r"C:\PS\Process.db")
        cur = conn.cursor()
        print ("")
        print("========== Virus Total Loading ==========")
        print("=========================================")
        if sha256 == {}:
            print("!!!!!!!!!! Sorry, No Match !!!!!!!!!!")
            with open("C:\\PS\\Result.txt", "w" ) as pRes:
                        pRes.write("0")
        else:
            print("sha256 :", sha256)
        
        print("=========================================")
        time.sleep(20)
        for key in keys:
            if key == 'AhnLab-V3':
                print('%-20s: %s' % (key, scan[key]['result']))
                if scan[key]['result'] == None:
                    with open("C:\\PS\\Result.txt", "w" ) as pRes:
                        pRes.write("1")
                elif scan[key]['result'] != None:
                    with open("C:\\PS\\Result.txt", "w" ) as pRes:
                        pRes.write("2")
                    break
            elif key == 'ALYac':
                print('%-20s: %s' % (key, scan[key]['result']))
                if scan[key]['result'] == None:
                    with open("C:\\PS\\Result.txt", "w" ) as pRes:
                        pRes.write("1")
                elif scan[key]['result'] != None:
                    with open("C:\\PS\\Result.txt", "w" ) as pRes:
                        pRes.write("2")
                    break
            elif key == 'nProtect':
                print('%-20s: %s' % (key, scan[key]['result']))
                if scan[key]['result'] == None:
                    with open("C:\\PS\\Result.txt", "w" ) as pRes:
                        pRes.write("1")
                elif scan[key]['result'] != None:
                    with open("C:\\PS\\Result.txt", "w" ) as pRes:
                        pRes.write("2")
                    break
            elif key == 'ViRobot':
                print('%-20s: %s' % (key, scan[key]['result']))
                if scan[key]['result'] == None:
                    with open("C:\\PS\\Result.txt", "w" ) as pRes:
                        pRes.write("1")
                elif scan[key]['result'] != None:
                    with open("C:\\PS\\Result.txt", "w" ) as pRes:
                        pRes.write("2")
                    break
        
    txtf.close()
    print("\n========== clear ==========\n")
