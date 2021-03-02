import os, re, random, os.path, apache_log_parser, subprocess, sys, hashlib, socket, getopt
import psutil

from apache import *
from config_network import *

# Apache log anonymizer 
def apache_module(input_file, output_file):
    a = Apache(input_file, output_file, size)

    #Open log file
    try:
        log = open(input_file, 'r', errors = 'backslashreplace')
    except:
        print("Cannot read log file " + output_file)
        quit()

    #Process log entries
    while(1):
        time.sleep(0.01)
        if(a.log_process(a.log_readline(log))):
            print("Log entry valid, ", end='')
        else:
            print("Log entry invalid, skipping...")
            continue

        if(a.bf_query(a.entry['remote_host'].encode('utf-8'), hash_chars, hash_count) == "found"):
            #IP already found, log accordingly
            print("IP already exists, logging as " + default_log_ip)
            a.output_genline(default_log_ip)
        else:
            #New IP, record in bloom filter, then log
            print("new IP found, logging as " + str(a.counter_ip))
            a.bf_write(a.bits, 1)
            a.output_genline(a.counter_ip)
            
            a.counter_ip = ip_address(a.counter_ip) + 1
        if(decay_rate != 0) and (randint(1, decay_rate) == 1):
            a.bf_decay(size)



# Syslog-ng logs anonymization 
def hostname_parser(log):
    parser = log.split(" ")

    if parser[3] in hosts.keys():
        parser[3] = hosts[parser[3]]
    else:
        hostname = parser[3]
        hashed = hashlib.md5(parser[3].encode())
        parser[3] = hashed.hexdigest()

        hosts[hostname] = parser[3]

    return " ".join(parser)


# Anonimyzes real time syslog log events
# Keeps track of the number of hostnames and 
# the last line of syslog output file is the 
# number of different hostnames
# By default tails the '/var/log/syslog' file
def syslog_real_time_anon(output_file):
    try:    
        fich = open(output_file, 'w+')
    except:
        print("Could not open or creat file '{}' .".format(output_file))
        sys.exit(2)


    f = subprocess.Popen(['tail', '-f', '/var/log/syslog'], \
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    
    print("Starting real time syslog anonimization. Ctrl+C to terminate.")
    while True:
        try:     
            syslog = f.stdout.readline()
            anonlog = hostname_parser(syslog.decode('utf-8'))  
            print(anonlog)        
            fich.write(anonlog)
        
        except KeyboardInterrupt:
            fich.write("Number of diferente hostnames " + str(len(hosts)))
            f.kill()
            fich.close()
            sys.exit(0)
        

# Anonymizes a syslog file type
def syslog_anon_file(input_file, output_file):
    try:
        os.path.isfile(input_file)
    except FileNotFoundError:
        print("Read file '{}' not found.".format(input_file))
        sys.exit(2)
    
    w = open(output_file, 'w')
    with open(input_file, 'r') as r:
        for line in r:
            anonlog = hostname_parser(line)
            print(anonlog)
            w.write(str(anonlog))

    w.write("Number of diferente hostnames " + str(len(hosts)))

    sys.exit()


def verifyExtension(file):
    extension = file.split(".")[1]
    if extension != "pcap":
        return False
    return True


# WARNING: The tool will silently over-write any existing file with the same name as the output file that you specify. 
def network_pcap_parser(input_file, output_file):
    print("Anonymizating file: '{}' ".format(input_file))

    if verifyExtension(input_file) and verifyExtension(output_file):
        try:
            f = subprocess.Popen(['scrub-tcpdump-0.1/scrub-tcpdump',\
                                "-r", input_file,\
                                "-w", output_file,\
                                "-o", options],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)  
        except KeyboardInterrupt:
            print("Shutting down anonymization.")
            f.terminate()
            sys.exit(0)

    else:
        print("File extension must be libpcap: '{}' format.".format(".pcap"))
        sys.exit(1)


# WARNING: The tool will silently over-write any existing file with the same name as the output file that you specify. 
def network_real_time_anon(output_file):
    print("Starting real time network anonymization. Ctrl+C to terminate.")
    if verifyExtension(output_file):
        while True:
            try:
                f = subprocess.Popen(['../../scrub-tcpdump-0.1/scrub-tcpdump',\
                                    "-i", adapter,\
                                    "-w", output_file,\
                                    "-o", options],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)  
            except KeyboardInterrupt:
                print("Shutting down anonymization.")
                f.terminate()
                sys.exit(0)
    else:
        print("File extension must be libpcap: '{}'.".format(".pcap"))
        sys.exit(1)


def main(argv):    
    opts, args = getopt.getopt(argv,"sravnhi:o:",["ifile=","ofile=", "help"]) 
    if(len(argv) < 2):
        print(USAGE)
        sys.exit(2)

    option = ""
    for opt, arg in opts:
        print(opt)
        if opt in ('-h', "--help"):
            print(USAGE)
            sys.exit(0)

        elif opt in ("-i", "--ifile"):
            input_file = arg
        
        elif opt in ("-o", "--ofile"):
            output_file = arg

        elif arg == "":
            option = opt


    if(output_file == ""):
        print("Outpute file required.")
        print(USAGE)


    if option == "-s":
        syslog_anon_file(input_file, output_file)
    
    elif option == "-v":
        syslog_real_time_anon(output_file)

    elif option == "-n":
        network_pcap_parser(input_file, output_file)

    elif option == "-r":
        network_real_time_anon(output_file)
        

    elif option == "-a":
        apache_module(input_file, output_file)

    else:
        print("Invalid option.")
        print(USAGE)


USAGE = "\nUsage: api.py [option] [optionFile] <file>\n"\
        "\t----------+------------------------------------------------------\n"\
        "\t  Option  |          Description                                 \n"\
        "\t  -v      | real time syslog anonymization                       \n"\
        "\t  -s      | syslog file anonymization                            \n"\
        "\t  -r      | real time network anonymization (SCRUB-tcpdump)      \n"\
        "\t  -n      | network anonymization (SCRUB-tcpdump)                \n"\
        "\t  -a      | apache anonymization                                 \n\n"\
        "\t--------------+--------------------------------------------------\n"\
        "\t  OptionFile  |          Description                             \n"\
        "\t  -i          | file to read                                     \n"\
        "\t  -o          | file to write (it's mandatory)                   \n"

if __name__ == "__main__":
    # Syslog hostname counter
    hosts = {}
    main(sys.argv[1:])


