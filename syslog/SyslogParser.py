import os
import subprocess
import sys
import hashlib
import socket
import base64


# Only used if it is syslog-ng logs
def hostname_parser(log):
    parser = log.split(" ")
    if parser[3] in hosts:
        parser[3] = hosts.get(parser[3])
    else:
        hashed = hashlib.md5(parser[3].encode())
        parser[3] = hashed.hexdigest()
        hosts.append(parser[3])

    return " ".join(parser) + "\n"

# Defines the syslog module for anonimization of ip address
def syslog_module():
    f = subprocess.Popen(['tail', '-f', '/var/log/syslog'], \
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    fich = open("anon_syslogs.txt", "w+")
    while True:
        try:     
            syslog = f.stdout.readline()
            anonlog = hostname_parser(str(syslog))  
            print(anonlog)        
            fich.write(anonlog)
        
        except KeyboardInterrupt:
            f.kill()
            fich.close()
            sys.exit(0)


def main(argv):
    syslog_module()

if __name__ == "__main__":
    hosts = []
    main(sys.argv)
