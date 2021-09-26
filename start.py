from asyncio import tasks
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

class nmapScanner():
    NUMBER_WORKERS = multiprocessing.cpu_count() * 2
    MAX_SCAN_TIME = 3600 # in seconds
    subnets_target = ['192.168.0.0/24']
    ips_target = []
    ips_to_scan = []
    results = None
    server_ip = '135.125.107.36'
    server_port = '21055'
    item_key = 'ports_item_key'
    item_key_error = 'ports_item_key_error'
    psk_identity = 'ports_psk_identity'
    psk_file = 'ports_psk_identity'
    scans_status = None

    def __init__(self) -> None:
        self.results = dict()
        self.scans_status = dict()
        if os.geteuid() != 0: # change if another user has root rights
            print("Script must be run as root!")
            sys.exit(1)

    def run(self) -> None:
        """Start monitoring thread and multiprocessing scan.
        """
        self.prepareTargets()
        monitor_thread = threading.Thread(target=self.print_scan_info)
        monitor_thread.start()
        scan_tasks = self.split_work(self.NUMBER_WORKERS, self.ips_to_scan)
        print(self.send_workers(self.NUMBER_WORKERS, scan_tasks))

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
            self.ips_to_scan.append(ip)
    

    def print_scan_info(self) -> None:
        """Periodically print the time that has elapsed since the start of a specific host scan.
        And kill nmap process if the scan is running too long.
        """
        while(True):
            time.sleep(120)
            scan_status_dict_copy = self.scans_status.copy() # to avoid race condition during iteration
            for k, v in scan_status_dict_copy.items():
                elapsed_time = int(time.time() - v[0])
                if elapsed_time > self.MAX_SCAN_TIME:
                    print("Host {0} is being scanned too long:  {1} seconds.".format(v[1], elapsed_time))
                    try:
                        print("Trying kill PID: {0}".format(k))
                        os.kill(k, signal.SIGTERM)
                        print("Scan process {0} killed".format(k))
                        self.send_error_to_zabbix(v[1], "Scan_terminated_after_{0}_seconds".format(elapsed_time))
                    except:
                        print("Error during killing process")
                        traceback.print_exc()
                print("Host {0} is being scanned for {1} seconds. PID: {2}".format(v[1], elapsed_time, k))

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
            print('Starting scanning host: {0}'.format(host))
            nmap_proc = subprocess.Popen(['nmap', '-sS', '-vv', '-T3', '-p-', '-oX', '-', str(host)], stdin=None, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            pid = nmap_proc.pid
            self.scans_status[pid] = [time.time(), str(host)]
            nmap_output = nmap_proc.communicate()[0].decode('utf-8').rstrip()
            print("{0} scanned".format(host))
            del self.scans_status[pid]
        except KeyboardInterrupt:
            print("Quitting scan!")
            return
        except:
            traceback.print_exc()
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
            print("Nmap result is not a valid XML. Was task terminated? Aborting!")
            return False, parser_results
        runstats = root.find('runstats')
        elapsed_time = runstats.find('finished').get('elapsed')
        print("{0} scanned in {1} seconds".format(host_addr, elapsed_time))
        host = root.find('host')
        if host is None:
            return False, parser_results
        print("Host address: {0}".format(host_addr))
        parser_results['Host_addr'] = host_addr
        ports = host.find('ports')
        ports_results = []
        if ports is not None:
            for port in ports.iter('port'):
                ports_results.append({port.get('portid') : port[0].get('state')})
        parser_results['Ports'] = ports_results
        print(parser_results)
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
        print("Sending data to zabbix server")
        try:
            subprocess_command = 'zabbix_sender -v -z {0} -p {1} -s {2} -k {3} -o {4} --tls-connect psk --tls-psk-identity {5} --tls-psk-file {6}'.format(self.server_ip,
            self.server_port, host_name, self.item_key, ports_string, self.psk_identity, self.psk_file)
            subprocess.call(subprocess_command, shell=True)
        except:
            print("Error during sending data")
        print(host_ip + " - " + ports_string)

    def send_error_to_zabbix(self, host_name: str, message: str) -> None:
        print("Sending error data to zabbix server")
        try:
            subprocess_command = 'zabbix_sender -v -z {0} -p {1} -s {2} -k {3} -o {4} --tls-connect psk --tls-psk-identity {5} --tls-psk-file {6}'.format(self.server_ip,
            self.server_port, host_name, self.item_key_error, message, self.psk_identity, self.psk_file)
            subprocess.call(subprocess_command, shell=True)
        except:
            print("Error during sending erro data")

if __name__ == "__main__":
    nmapScanner = nmapScanner()
    start_time = time.time()
    nmapScanner.run()
    print("Scan finished in {0}".format(time.time() - start_time))
    sys.exit(0)
