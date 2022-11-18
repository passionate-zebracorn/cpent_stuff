#!/usr/bin/python3
import argparse
import subprocess
import re

targets = []

#Take options and user things
all_args = argparse.ArgumentParser(prog = 'python3 cpent_scanner.py', description = 'This attempts to run netdiscover to find IPs, scan those for open ports with nmap, send the ports found to service scan with nmap, then make it prettiful.', usage='%(prog)s <IP address(es)> [options]')

all_args.add_argument('-s', '--skip', choices=['netdiscover', 'portscan', 'nmap'], nargs='+', help='You can skip netdiscover, portscan or nmap')
all_args.add_argument('-p', nargs='*', help='Big Bird says \'The letter p is for ports\'')
all_args.add_argument('-o', '--outfile', default='/tmp/transformers.html', help='Define the html output file. The default is /tmp/transformers.html')
all_args.add_argument('-i', help='Define an interface')
all_args.add_argument('ips', help='The ips should be the argument that follows the calling of the script. The IP can be in any nmap acceptable format')

parse_em = all_args.parse_args()
#Run netdiscover
def run_netdiscover(ips, interface):
    alive_targs = []
    proc = subprocess.Popen(['netdiscover', '-i', interface, '-P', '-r', ips], stdout=subprocess.PIPE)
    raw_netdiscover_out = proc.stdout.read()
    strings_netdiscover_out = raw_netdiscover_out.decode('utf-8').split('\n')
    search_ips = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
    for i in range(len(strings_netdiscover_out)):
        if search_ips.search(strings_netdiscover_out[i]):
            alive_targs.append(strings_netdiscover_out[i].split()[0])
    print('Netdiscover has completed and found these ips: ' + str(alive_targs))
    return alive_targs

#Run portscan
#nmap -Pn --top-ports 100 -i <interface> -T4 -oG - <ips> 
def run_portscan(ports, ips, interface, skipped):
    open_ports = set()
    alive_targs = set()
    if not isinstance(ips, list):
        if ports is None: 
            cmd = ['nmap', '-Pn', '--top-ports','100', '-e', interface, '-T4', '-oG', '-', ips]
        else:
            cmd = ['nmap', '-Pn', ports, '-e', interface, '-T4', '-oG', '-', ips]
    else:
        if ports is None:
            cmd = ['nmap', '-Pn', '--top-ports','100', '-e', interface, '-T4', '-oG', '-']
            cmd.extend(ips)
        else:
            cmd = ['nmap', '-Pn', '-sV', '-p', open_ports, '-oX', '-']
            cmd.extend(ips)
    print('Running portscan now on ' + str(ips))
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE)
    raw_portscan_out = proc.stdout.read()
    strings_portscan_out = raw_portscan_out.decode('utf-8').split('\n')
    for result in strings_portscan_out:
        if 'open' in result:
            list_of_results = result.split()
            alive_targs.add(list_of_results[1])
            for port in list_of_results:
                if 'open' in port:
                    open_ports.add(port.split('/')[0])
    if skipped and 'netdiscover' in skipped:
        return open_ports, alive_targs
    else:
        return open_ports

#Run nmap
def run_nmap(ports, ips, skipped):
    open_ports = ','.join(ports)
    if skipped and 'netdiscover' in skipped:
        targs = []
        for ip in ips:
            targs.append(ip)
    else:
        targs = ips
    cmd = ['nmap', '-Pn', '-sV', '-p', open_ports, '-oX', '-']
    cmd.extend(targs)
    print('Running nmap on ' + str(ips) + ' and ' + str(ports))
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE)
    raw_nmap_out = proc.stdout.read()
    strings_nmap_out = raw_nmap_out.decode('utf-8')
    return strings_nmap_out


#Transform nmap output
def transform_nmap_out_html(xml_data, outfile):
    temppath = '/tmp/stage.xml'
    with open(temppath, 'w') as tempfile:
        for line in xml_data:
            tempfile.write(line)
        tempfile.close()
    proc = subprocess.Popen(['xsltproc', temppath, '-o', outfile], stdout=subprocess.PIPE)
    proc.communicate()
    proc2 = subprocess.Popen(['rm', '-f', '/tmp/stage.xml'])
    print('It seems like it was a successful run. Look for the outfile. If none exists, that sucks.')

#Main
if not parse_em.skip:
    #run all
    targets = run_netdiscover(parse_em.ips, parse_em.i)
    ports = run_portscan(parse_em.p, targets, parse_em.i, parse_em.skip)
    nmap_xml = run_nmap(ports, targets, parse_em.skip)
    transform_nmap_out_html(nmap_xml, parse_em.outfile)

elif len(parse_em.skip) == 1:
    if 'netdiscover' in parse_em.skip:
        #run portscan and nmap
        ports, targets = run_portscan(parse_em.p, parse_em.ips, parse_em.i, parse_em.skip)
        nmap_xml = run_nmap(ports, targets, parse_em.skip)
        transform_nmap_out_html(nmap_xml, parse_em.outfile)

    elif 'portscan' in parse_em.skip:
        #run netdiscover and nmap
        targets = run_netdiscover(parse_em.ips, parse_em.i)
        nmap_xml = run_nmap(parse_em.p, targets, parse_em.skip)
        transform_nmap_out_html(nmap_xml, parse_em.outfile)

    elif 'nmap' in parse_em.skip:
        #run netdiscover and portscan
        targets = run_netdiscover(parse_em.ips, parse_em.i)
        ports = run_portscan(parse_em.p, targets, parse_em.i, parse_em.skip)

elif len(parse_em.skip) == 2:
    if 'netdiscover' in parse_em.skip and 'portscan' in parse_em.skip:
        nmap_xml = run_nmap(parse_em.p, parse_em.ips, parse_em.skip)
        transform_nmap_out_html(nmap_xml, parse_em.outfile)
    
    elif 'netdiscover' in parse_em.skip and 'nmap' in parse_em.skip:
        ports, targets = run_portscan(parse_em.p, parse_em.ips, parse_em.i, parse_em.skip)
        print('Portscan finished and the following data was found:\n' + str(targets) + str(ports))

    elif 'portscan' in parse_em.skip and 'nmap' in parse_em.skip:
        targets = run_netdiscover(parse_em.ips, parse_em.i)

