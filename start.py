import subprocess
import xml.etree.ElementTree as ET
import ipaddress
import traceback
from multiprocessing.pool import ThreadPool as Pool #Simple solution is to switch from Pool to ThreadPool. ThreadPool shares memory with the main thread, rather than creating a new process
from multiprocessing import active_children
from typing import Union
import multiprocessing
import numpy
import os
import sys
import time
import threading
import signal
import configparser
import re
import logging
import pathlib
import random


class nmapScanner():
    config = None
    NUMBER_WORKERS = multiprocessing.cpu_count() * 2
    scan_finished = False
    ips_to_scan = []
    results = None
    # Values read from the config file
    MAX_SCAN_TIME = 3600 # in seconds
    subnets_target = []
    ips_target = []
    server_ip = None
    server_port = None
    item_key = None
    item_key_error = None
    psk_identity = None
    psk_file = None
    logger = None
    last_zabbix_trap = None

    def __init__(self) -> None:
        self.results = dict()
        self.scans_status = dict()
        if os.geteuid() != 0: # change if another user has root rights
            print("Script must be run as root!")
            sys.exit(1)
        self.init_logging()
        self.last_zabbix_trap = int(time.time())

    def init_logging(self):
        pathlib.Path('logs').mkdir(parents=True, exist_ok=True)
        log_filename = 'log_{0}.log'.format(time.strftime("%Y-%m-%d_%H-%M-%S"))
        log_file_path = pathlib.Path.joinpath(pathlib.Path(__file__).parent, 'logs', log_filename)
        logging.basicConfig(filename=log_file_path,
                            filemode='a',
                            format='%(asctime)s.%(msecs)d,%(levelname)s,%(message)s',
                            datefmt='%H:%M:%S',
                            level=logging.INFO)
        logging.info("Starting Nmap Zabbix")
        self.logger = logging.getLogger('Nmap Zabbix')

    def importConfigFile(self) -> None:
        """Read config file and validate values
        """
        self.config = configparser.ConfigParser()
        try:
            self.config.read('config.ini')
        except:
            print("Cannot read config file. QUITTING!")
            sys.exit(2)
        # SERVER block
        try:
            try:
                self.server_ip = str(ipaddress.ip_address(self.config['SERVER']['server_ip']))
            except:
                print('Invalid server IP address. QUITTING!')
                logging.critical('Invalid server IP address. QUITTING!')
                sys.exit(2)
            if self.config['SERVER']['server_port'].isdigit():
                self.server_port = self.config['SERVER']['server_port']
            else:
                print('Server port is not a digit. QUITTING!')
                logging.critical('Server port is not a digit. QUITTING!')
                sys.exit(2)
            if bool(re.match("^[A-Za-z0-9_]*$", self.config['SERVER']['item_key'])):
                self.item_key = self.config['SERVER']['item_key']
            else:
                print('item_key can contain only alphanumeric and underscore char. QUITTING!')
                logging.critical('item_key can contain only alphanumeric and underscore char. QUITTING!')
                sys.exit(2)
            if bool(re.match("^[A-Za-z0-9_]*$", self.config['SERVER']['item_key_error'])):
                self.item_key_error = self.config['SERVER']['item_key_error']
            else:
                print('item_key_error can contain only alphanumeric and underscore char. QUITTING!')
                logging.critical('item_key_error can contain only alphanumeric and underscore char. QUITTING!')
                sys.exit(2)
            if bool(re.match("^[A-Za-z0-9_]*$", self.config['SERVER']['psk_identity'])):
                self.psk_identity = self.config['SERVER']['psk_identity']
            else:
                print('psk_identity can contain only alphanumeric and underscore char. QUITTING!')
                logging.critical('psk_identity can contain only alphanumeric and underscore char. QUITTING')
                sys.exit(2)
            if bool(re.match("^[A-Za-z0-9_]*$", self.config['SERVER']['psk_file'])):
                self.psk_file = self.config['SERVER']['psk_file']
            else:
                print('psk_file can contain only alphanumeric and underscore char. QUITTING!')
                logging.critical('psk_file can contain only alphanumeric and underscore char. QUITTING!')
                sys.exit(2)
        except:
            traceback.print_exc()
        # SCAN_OPTIONS block
        try:
            subnets = self.config['SCAN_OPTIONS']['subnets_target'].split(',')
            if ('[' or ']') in self.config['SCAN_OPTIONS']['subnets_target']:
                logging.critical('Incorrect subnets in config file. Do not use brackets!')
                sys.exit(2)
            subnets = [x.strip(' ') for x in subnets]
            self.subnets_target = subnets
        except:
            logging.critical('Cannot parse input subnets targets')
            traceback.print_exc()
            sys.exit(2)
        try:
            ips = self.config['SCAN_OPTIONS']['ips_target'].split(',')
            if ('[' or ']') in self.config['SCAN_OPTIONS']['ips_target']:
                logging.critical('Incorrect IPs in config file. Do not use brackets!')
                sys.exit(2)
            ips = [x.strip(' ') for x in ips]
            self.ips_target = ips
        except:
            #print('Cannot parse input ip targets')
            logging.critical('Cannot parse input ip targets')
            traceback.print_exc()
            sys.exit(2)
        if self.config['SCAN_OPTIONS']['MAX_SCAN_TIME'].isdigit():
            self.MAX_SCAN_TIME = self.config['SCAN_OPTIONS']['MAX_SCAN_TIME']
        else:
            logging.warning('MAX_SCAN_TIME is not a digit. Using default value.')


    def run(self) -> None:
        """Start monitoring thread and multiprocessing scan.
        """
        self.importConfigFile()
        self.prepareTargets()
        monitor_thread = threading.Thread(target=self.print_scan_info)
        monitor_thread.start()
        scan_tasks = self.split_work(self.NUMBER_WORKERS, self.ips_to_scan)
        print(self.send_workers(self.NUMBER_WORKERS, scan_tasks))
        self.scan_finished = True

    def split_work(self, poolsize: int, ips_list: list) -> list:
        """Split scan into independent threads

        :param poolsize: Number of separate processes
        :type poolsize: int

        :param ips_list: List of all IP addresses to scan
        :type ips_list: list

        :return: List containing the list of IPs to be scanned per process
        :rtype: list
        """
        list_tasks_nmap = []
        for ip in numpy.array_split(ips_list, poolsize):
            list_tasks_nmap.append(list(ip))
        return list_tasks_nmap

    def send_workers(self, poolsize: int, list_tasks_nmap: list) -> None:
        """Run scans in multiprocessing

        :param poolsize: Number of separate processes
        :type poolsize: int

        :list_tasks_nmap: Scan tasks divided into multiple arrays.
        :type list_tasks_nmap: list
        """
        pool = Pool(poolsize)
        s = pool.map(self.make_job, list_tasks_nmap)
        print('Active children count: %d'%len(active_children()))
        pool.close()
        pool.join()

    def make_job(self, task_list: list) -> None:
        """Initialize scan from multiprocessing module
        """
        for element in task_list:
            self.scan(element)

    def prepareTargets(self) -> None:
        """Create list of IP addresses to scan from input IPs and subnets
        """
        for subnet in self.subnets_target:
            hosts_subnet = list(ipaddress.IPv4Network(subnet).hosts())
            if (type(hosts_subnet) == list):
                self.ips_to_scan.extend(map(str,hosts_subnet))
            elif (type(hosts_subnet) == ipaddress.IPv4Address):
                self.ips_to_scan.append(str(hosts_subnet))
        for ip in self.ips_target:
            if ip not in self.ips_to_scan:
                self.ips_to_scan.append(ip)
        print(self.ips_to_scan)
        sys.exit(1)

    def print_scan_info(self) -> None:
        """Periodically print the time that has elapsed since the start of a specific host scan.
        And kill nmap process if the scan is running too long.
        """
        while(self.scan_finished is False):
            time.sleep(120)
            scan_status_dict_copy = self.scans_status.copy() # to avoid race condition during iteration
            for k, v in scan_status_dict_copy.items():
                elapsed_time = int(time.time() - v[0])
                if elapsed_time > self.MAX_SCAN_TIME:
                    print('{0} - Host is being scanned too long:  {1} seconds.'.format(v[1], elapsed_time))
                    try:
                        print('{0} - Trying kill PID: {1}'.format(v[1], k))
                        logging.info('{0} - Trying kill PID: {1}'.format(v[1], k))
                        os.kill(k, signal.SIGTERM)
                        print('{0} - Scan process {1} killed'.format(v[1], k))
                        logging.info('{0} - Scan process {1} killed'.format(v[1], k))
                        self.send_error_to_zabbix(v[1], "Scan_terminated_after_{0}_seconds".format(elapsed_time))
                    except:
                        print('{0} - Error during killing process'.format(v[1]))
                        logging.error('{0} - Error during killing process'.format(v[1]))
                        traceback.print_exc()
                print('{0} - Host is being scanned for {1} seconds. PID: {2}'.format(v[1], elapsed_time, k))
                logging.info('{0} - Host is being scanned for {1} seconds. PID: {2}'.format(v[1], elapsed_time, k))

    def scan(self, ip: str) -> None:
        """Execude nmap command with provided IP address

        :param ip: Single IP address appended to nmap command
        :type ip: str
        """
        host = ip
        nmap_output = None
        status = None
        results = None
        try:
            logging.info('{0} - Starting scanning host'.format(host))
            print('{0} - Starting scanning host'.format(host))
            nmap_proc = subprocess.Popen(['nmap', '-sS', '-vv', '-T3', '-p-', '-oX', '-', str(host)], stdin=None, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            pid = nmap_proc.pid
            self.scans_status[pid] = [time.time(), str(host)]
            nmap_output = nmap_proc.communicate()[0].decode('utf-8').rstrip()
            logging.info('{0} - Scan ended'.format(host))
            #print("{0} scanned".format(host))
        except KeyboardInterrupt:
            logging.info('{0} - Quitting scan!'.format(host))
            return
        except:
            traceback.print_exc()
        finally:
            del self.scans_status[pid]
        if nmap_output is not None:
            status, results = self.parseResults(nmap_output, str(host))
            if status:
                self.send_to_zabbix_server(results)
            
        
    def parseResults(self, nmap_output: str, host_addr: str) -> Union[bool, dict]:
        """
        :param nmap_output: nmap output in XML format parsed to string
        :type nmap_output: str

        :param host_addr: Host IP Address for debugging purposes
        :type host_addr: str

        :return: Boolean indicating if scan was performed successfully and dict with ports states
        :rtype: Union[bool, dict]
        """
        parser_results = dict()
        root = None
        try:
            root = ET.fromstring(nmap_output)
        except:
            logging.warning('{0} - Nmap result is not a valid XML. Was task terminated by user? Aborting!'.format(host_addr))
            return False, parser_results
        runstats = root.find('runstats')
        elapsed_time = runstats.find('finished').get('elapsed')
        logging.info("{0} - scanned in {1} seconds".format(host_addr, elapsed_time))
        host = root.find('host')
        if host is None:
            return False, parser_results
        logging.debug('{0} - Host address'.format(host_addr))
        parser_results['Host_addr'] = host_addr
        ports = host.find('ports')
        ports_results = []
        if ports is not None:
            for port in ports.iter('port'):
                ports_results.append({port.get('portid') : port[0].get('state')})
        parser_results['Ports'] = ports_results
        logging.debug('{0} - {1}'.format(host_addr, parser_results))
        return True, parser_results

    def send_to_zabbix_server(self, parsed_results: dict) -> None:
        """Send ports info to the Zabbix server
        
        :param parsed_results: dict with ports states
        :type parsed_results: dict
        """
        host_ip = parsed_results['Host_addr']
        ports_string = ""
        if len(parsed_results['Ports']) == 0:
            ports_string = "all_closed"
        else:
            for port in parsed_results['Ports']:
                (number, state), = port.items()
                p_string = "{0}:{1}_".format(number,state)
                ports_string += p_string
            ports_string = ports_string[:-1]
        host_name = str(host_ip)
        while int(time.time()) - self.last_zabbix_trap < 5:
            time.sleep(random.randint(6,12))
        logging.info("{0} - Sending data to zabbix server".format(host_name))
        subprocess_command = 'zabbix_sender -vv -z {0} -p {1} -s {2} -k {3} -o {4} --tls-connect psk --tls-psk-identity {5} --tls-psk-file {6}'.format(self.server_ip,
        self.server_port, host_name, self.item_key, ports_string, self.psk_identity, self.psk_file)
        try:
            self.last_zabbix_trap = int(time.time())
            subprocess.check_output(subprocess_command,stderr=subprocess.STDOUT, shell=True, universal_newlines=True)
            self.last_zabbix_trap = int(time.time())
        except subprocess.CalledProcessError as exc:
            print("{0} - Zabbix_sender status : FAIL. Return code: {1}\nOutput:\n{2}".format(host_name, exc.returncode, exc.output))
            logging.error("{0} - Zabbix_sender status : FAIL. Return code: {1}\nOutput:\n{2}".format(host_name, exc.returncode, exc.output))
        else:
            logging.info('{0} - Data sent successfully'.format(host_name))
            #print("Output: \n{}\n".format(response))

    def send_error_to_zabbix(self, host_name: str, message: str) -> None:
        print("{0} - Sending error data to zabbix server".format(host_name))
        try:
            subprocess_command = 'zabbix_sender -vv -z {0} -p {1} -s {2} -k {3} -o {4} --tls-connect psk --tls-psk-identity {5} --tls-psk-file {6}'.format(self.server_ip,
            self.server_port, host_name, self.item_key_error, message, self.psk_identity, self.psk_file)
            subprocess.call(subprocess_command, shell=True)
        except:
            print("{0} - Error during sending error data".format(host_name))

if __name__ == "__main__":
    nmapScanner = nmapScanner()
    start_time = time.time()
    nmapScanner.run()
    print("Scan finished in {0}".format(time.time() - start_time))
    logging.info('Scan finished in {0}'.format(time.time() - start_time))
    logging.shutdown()
    sys.exit(0)
