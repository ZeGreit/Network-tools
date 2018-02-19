#!/opt/rh/rh-python35/root/usr/bin/python

import configparser
import pexpect
import re
import getopt
import sys
import subprocess
import ipaddress
import time
from netmiko import ConnectHandler

#---- MAIN FUNCTION ----#

def main():

    ##Common parameters
    basedir = '/opt/app/network/routes'
    workdir = '%s/collect' % basedir
    out_dir = '%s/import' % basedir
    conf_file = '%s/.cfg' % workdir

    ##Variables for get options
    opt_all = False
    opt_IOS = False
    opt_nexus = False
    opt_checkpoint = False
    opt_cp_vsx = False
    opt_srx = False
    opt_ns = False
    platform = None
    opt_device = None

    ##Script run with no arguments check
    if len(sys.argv) == 1:
        answer = input('Running the script with no options will process all the platforms. Are you sure? (yes/no) ')
        while answer.lower() != 'yes' and answer.lower() != 'no':
            answer = input('Type yes or no: ')

        if answer.lower() != 'yes':
            print('Cancelled\nUse -h for help')
            sys.exit()
        else:
            opt_all = True

    ##Get and check options
    long_opt_list = ['all', 'NXOS', 'CP', 'VSX', 'SRX', 'NS', 'IOS']
    try:
        options, arguments = getopt.getopt(sys.argv[1:], 'hd:', long_opt_list)
    except getopt.GetoptError as err:
        print(err)
        sys.exit(2)

    platform_count = 0
    for opt, arg in options:
        if opt == '-h':
            usage(long_opt_list)
        elif opt == '--all':
            opt_all = True
        elif opt == '--IOS':
            opt_IOS = True
            platform = 'IOS'
            platform_count += 1
        elif opt == '--NXOS':
            opt_nexus = True
            platform = 'NXOS'
            platform_count += 1
        elif opt == '--CP':
            opt_checkpoint = True
            platform = 'CP'
            platform_count += 1
        elif opt == '--VSX':
            opt_cp_vsx = True
            platform = 'VSX'
            platform_count += 1
        elif opt == '--SRX':
            opt_srx = True
            platform = 'SRX'
            platform_count += 1
        elif opt == '--NS':
            opt_ns = True
            platform = 'NS'
            platform_count += 1
        elif opt == '-d':
            opt_device = arg

    if platform_count > 1:
        print('Error: No more than 1 platform can be specified.')
        sys.exit(2)

    if platform_count == 1:
        out_file = '%s/%s-import' % (out_dir, platform)

    if opt_device:
        out_file = '%s/%s-import' % (out_dir, opt_device)
        if platform_count < 1:
            print('Error: no platform specified for device "%s".' % opt_device)
            sys.exit(2)

    if opt_all:
        out_file = '%s/routes-import' % out_dir
        opt_device = None
        platform = None

    ##Primary function call
    get_routes(conf_file, basedir, workdir, opt_device, out_file, platform, long_opt_list)


#---- END OF MAIN FUNCTION ----#


#-- Classes --#

class router(object):

    def __init__(misa, hostname, user, passw, platform):
        misa.hostname = hostname
        misa.user = user
        misa.passw = passw
        misa.platform = platform

    def routing_table(misa, command):
        if misa.platform == 'NXOS' or misa.platform == 'IOS':
            prompt = '%s#' % misa.hostname
            routes = get_info_nxos(misa.hostname, misa.user, misa.passw, command, misa.platform)
            routes = routes.split('\n')
            return routes
        elif misa.platform == 'CP':
            try:
                cmd_output = subprocess.check_output(command, shell=True)
                routes = str(cmd_output).split('\\n')
                return routes
            except:
                error = 'Error: %s' % sys.exc_info()[1]
                return error
        elif misa.platform == 'VSX':
            command, seq_nr = command.split('--')
            routes = get_info_cp_vsx(misa.hostname, misa.user, misa.passw, command, seq_nr)
            return routes
        elif misa.platform == 'SRX':
            prompt = '%s>' % misa.hostname
            routes = get_info_juniper(misa.hostname, misa.user, misa.passw, command, prompt)
            return routes
        elif misa.platform == 'NS':
            prompt = '.*->'
            command, vsys = command.split('--')
            routes = get_routes_netscreen(misa.hostname, misa.user, misa.passw, command, prompt, vsys)
            return routes


    def vrf_list(misa, command):
        prompt = '%s#' % misa.hostname
        if misa.platform == 'NXOS' or misa.platform == 'IOS':
            vrf_out = get_info_nxos(misa.hostname, misa.user, misa.passw, command, misa.platform)
            if re.search('^Error.*', str(vrf_out)):
                return str(vrf_out)
            vrfs = []
            vrf_out = vrf_out.split('\n')
            for line in vrf_out:
                if misa.platform == 'IOS':
                    if re.search('.*\d+\:\d+.*', line) or re.search('.*\<not set\>.*', line):
                        vrf = line.split()[0]
                        vrfs.append(vrf)
                else:
                    vrf = line.split()[0]
                    vrfs.append(vrf)
            return vrfs
        if misa.platform == 'SRX':
            prompt = '%s>' % misa.hostname
            vrf_out = get_info_juniper(misa.hostname, misa.user, misa.passw, command, prompt)
            if re.search('^Error.*', str(vrf_out)):
                return str(vrf_out)
            vrfs = []
            for line in vrf_out:
                if re.search('.*\.inet\.\d+.*', line):
                    vrf = line.split(':')[0]
                    vrfs.append(vrf)
            return vrfs
        if misa.platform == 'NS':
            prompt = '.*->'
            vrf_out = get_info_juniper(misa.hostname, misa.user, misa.passw, command, prompt)
            if re.search('^Error.*', str(vrf_out)):
                return str(vrf_out)
            if re.search('.*unknown\ keyword\ vsys.*', str(vrf_out)):
                return
            vrfs = []
            for line in vrf_out:
                if re.search('.*VsysDef~.+', line):
                    vrf = line.split()[0].rstrip()
                    vrfs.append(vrf)
            return vrfs

class route(object):

    def __init__(misa, route_type):
        misa.route_type = route_type

    ##Format for IOS, NXOS, SRX, NetScreen and Checkpoint standalone
    def format(misa, string):
        if misa.route_type == 'NXOS' or misa.route_type == 'IOS':
            string = string.replace('no route', 'NoRoute')
            string = string.replace('Attached', 'attached')
            route = '|'.join([word for word in string.split()])
            if len(re.findall('\|', route)) == 1:
                route = route + '|'
            return route
        if misa.route_type == 'CP':
            if re.search('.*\ via\ .*', string):
                ip = string.split()[1]
                next_hop = string.split()[3].rstrip(',')
                out_if = string.split()[4].rstrip(',')
                route = ('%s|%s|%s' % (ip, next_hop, out_if))
            elif re.search('.*directly\ connected.*', string):
                ip = string.split()[1]
                next_hop = 'attached'
                out_if = string.split()[5].rstrip(',')
                route = ('%s|%s|%s' % (ip, next_hop, out_if))
            return route
        if misa.route_type == 'SRX':
            if re.search('\ rslv\ ', string):
                next_hop = 'attached'
                out_if = string.split()[6]
            if re.search('user.*ucst', string):
                next_hop = string.split()[3]
                out_if = string.split()[7]
            ip = string.split()[0]
            route = ('%s|%s|%s' % (ip, next_hop, out_if))
            return route
        if misa.route_type == 'NS':
            ip = string.split()[2]
            next_hop = string.split()[4]
            out_if = string.split()[3]
            route = ('%s|%s|%s' % (ip, next_hop, out_if))
            return route

    ##Format for Checkpoint VSX
    def format_vsx(misa, string, conn_subnets):
        ip = string.split('|')[1].rstrip()
        next_hop = string.split('|')[2].rstrip()
        out_if = string.split('|')[3].rstrip()
        if next_hop == '':
            next_hop = 'attached'
            conn_subnets[ip] = out_if
        if out_if == '':
            for subnet, iface in conn_subnets.items():
                if ipaddress.ip_address(next_hop) in ipaddress.ip_network(subnet):
                    out_if = iface
                    break
        out_line = '%s|%s|%s' % (ip, next_hop, out_if)
        return (out_line, conn_subnets)


#-- Primmary function to get routes from all devices --#

def get_routes(conf_file, basedir, workdir, opt_device, out_file, platform, long_opt_list):

    if platform:
        device_lists = [ '%s/list%s' % (workdir, platform) ]
    else:
        device_lists = [ workdir+'/list'+p_name for p_name in long_opt_list if p_name != 'all' ]

    out_file = out_file + time.strftime('%Y%m%d-%H%M%S')
    try:
        output = open(out_file, 'a')
    except FileNotFoundError as err:
        print(err)
        sys.exit(1)

    for dev_list in device_lists:
        platform = dev_list.lstrip(workdir+'/list')

        try:
            with open(dev_list) as device_cm:
                if opt_device:
                    devices = [ dev.rstrip() for dev in device_cm if dev.rstrip().lower() == opt_device.lower() ]
                else:
                    devices = [ dev.rstrip() for dev in device_cm ]
        except FileNotFoundError as err:
            print(err)
            continue

        if len(devices) == 0:
            print('No matching devices found in %s' % dev_list)
            continue

        config = configparser.ConfigParser()
        config.read(conf_file)
        user = config.get('logins', 'user')
        passw = config.get('logins', 'passw')

        platform_route_count = 0
        for hostname in devices:

            if platform != 'VSX':
                device = router(hostname, user, passw, platform)

            if platform == 'IOS' or platform == 'NXOS':
                vrf_command = 'show ip vrf'
                if platform == 'NXOS':
                    vrf_command = 'show vrf'

                vrfs = device.vrf_list(vrf_command)
                if re.search('^Error.*', str(vrfs)):
                    print('%s - %s' % (hostname, vrfs))
                    continue

                for vrf in vrfs:
                    route_command = 'show ip cef vrf %s | Exclude receive' % vrf
                    if platform == 'NXOS':
                        route_command = 'show forwarding ipv4 route vrf %s module 1 | Exclude Receive | Exclude Drop' % vrf

                    for line in device.routing_table(route_command):
                        if re.search('^\*?\d+\.\d+\.\d+\.\d+.*', line):
                            line = re.sub('^\*', '', line)
                            route_entry = route(platform)
                            vrf = re.sub('^default$', '', vrf)
                            out_line = '%s||%s|%s\n' % (hostname, vrf, route_entry.format(line))
                            output.write(out_line)
                            platform_route_count += 1

            if platform == 'CP':
                cp_scr = '/opt/app/network/bin/chkp-search'
                route_command = '%s -cli %s "clish -c \\"show route\\""' % (cp_scr, hostname)

                routes = device.routing_table(route_command)
                if re.search('^Error.*', str(routes)):
                    print('%s - %s' % (hostname, str(routes)))
                    continue

                for line in routes:
                    if re.search('.*\ via\ .*', line) or re.search('.*directly\ connected.*', line):
                        route_entry = route(platform)
                        hostname = re.sub('fwri|fwst', 'fwpc', hostname)
                        hostname = re.sub('a$|b$', '', hostname)
                        out_line = '%s|||%s\n' % (hostname, route_entry.format(line))
                        output.write(out_line)
                        platform_route_count += 1

            if platform == 'VSX':
                cp_user = config.get('logins', 'cp_user')
                cp_passw = config.get('logins', 'cp_passw')
                cp_mgmt_srv = config.get('logins', 'cp_mgmt_srv')

                cluster = hostname.split('-')[0]
                device = router(cp_mgmt_srv, cp_user, cp_passw, platform)
                seq_nr = 0
                with open(dev_list) as temp_cm:
                    for line in temp_cm:
                        if line.startswith(hostname):
                            seq_nr += 1

                route_command = 'vsx_util view_vs_conf -c %s -u admin -s 127.0.0.1--%s' % (hostname, seq_nr)

                routes = device.routing_table(route_command)
                if re.search('^Error.*', str(routes)):
                    print('%s - %s' % (hostname, str(routes)))
                    continue

                conn_subnets = {}
                for line in routes:
                    if re.search('^\|\d+\.\d+\.\d+\.\d+', line):
                        route_entry = route(platform)
                        out_line = '%s|%s||%s\n' % (cluster, hostname, route_entry.format_vsx(line, conn_subnets)[0])
                        conn_subnets = route_entry.format_vsx(line, conn_subnets)[1]
                        output.write(out_line)
                        platform_route_count += 1

            if platform == 'SRX':
                vrf_command = 'show route summary'

                vrfs = device.vrf_list(vrf_command)
                if re.search('^Error.*', str(vrfs)):
                    print('%s - %s' % (hostname, vrfs))
                    continue

                for vrf in vrfs:
                    vrf = re.sub('\.inet\..*$', '', vrf)

                    route_command = 'show route forwarding-table family inet table %s' % vrf
                    route_def_command = 'show route 0/0 exact table %s' % vrf

                    for line in device.routing_table(route_command):
                        if re.search('\ rslv\ |user.*ucst', line) and re.search('^\d+\.\d+\.\d+\.\d+', line):
                            route_entry = route(platform)
                            out_line = '%s||%s|%s\n' % (hostname, vrf, route_entry.format(line))
                            output.write(out_line)
                            platform_route_count += 1
                    for line in device.routing_table(route_def_command):
                        if re.search('\>.*to.*via', line):
                            next_hop = line.split()[2]
                            out_if = line.split()[4]
                            out_line = '%s||%s|0.0.0.0/0|%s|%s\n' % (hostname, vrf, next_hop, out_if)
                            output.write(out_line)
                            platform_route_count += 1

            if platform == 'NS':
                vrf_command = 'get vsys | i VsysDef~'

                vrfs = device.vrf_list(vrf_command)
                if not vrfs:
                    vrfs = []
                    vrfs.append('Root')
                if re.search('^Error.*', str(vrfs)):
                    print('%s - %s' % (hostname, vrfs))
                    continue

                for vrf in vrfs:
                    route_command = 'get route--%s' % vrf
                    for line in device.routing_table(route_command):
                        line = re.sub('---\ more\ ---.*', '', re.sub('^b.*x08', '', line))
                        if re.search('^IPv4.*Routes\ for', line):
                            vr = line.split()[3].lstrip('<').rstrip('>')
                        if re.search('^\*', line):
                            route_entry = route(platform)
                            out_line = '%s|%s|%s|%s\n' % (hostname, vrf, vr, route_entry.format(line))
                            output.write(out_line)
                            platform_route_count += 1

        print('Total %s %s routes written to file %s' % (platform_route_count, platform, out_file))

    output.close()


#---- HELP FUNCTIONS ----#


#-- Connect and get routes from NetScreen devices --#

def get_routes_netscreen(device, user, passw, command, prompt, vsys):

    try:
        dev_cli = pexpect.spawn('ssh -l %s %s'%(user, device))
        dev_cli.setwinsize(10000, dev_cli.maxread)
        code = dev_cli.expect(['.*\(yes/no\)?.*', pexpect.TIMEOUT, '[Pp]assword:'])
        if code == 0:
            dev_cli.sendline('yes')
            dev_cli.expect('[Pp]assword:')
        if code == 1:
            out ='Error: connection timeout'
            return out
        dev_cli.sendline(passw)
        dev_cli.expect(prompt)
        dev_cli.sendline('enter vsys %s' % vsys)
        dev_cli.expect(prompt)
        dev_cli.sendline(command)
        code = dev_cli.expect([prompt, '.*\ more\ .*'])
        out = ''
        while code == 1:
            if out == '':
                out = str(dev_cli.after).split("\\r\\n")
            else:
                out += str(dev_cli.after).split("\\r\\n")
            dev_cli.sendline('')
            code = dev_cli.expect([prompt, '.*\ more\ .*'])
        out += str(dev_cli.after).split("\\r\\n")
        dev_cli.sendline('exit')
        return out
    except:
        out = 'Error: Something went bad %s' % str(dev_cli.before)
        return out


#-- Connect to checkpoint management server and get routes from VSX devices --#

def get_info_cp_vsx(device, user, passw, command, seq_nr):

    try:
        dev_cli = pexpect.spawn('ssh -l %s %s'%(user, device))
        dev_cli.setwinsize(10000, dev_cli.maxread)
        code = dev_cli.expect(['.*\(yes/no\)?.*', pexpect.TIMEOUT, '[Pp]assword:'])
        if code == 0:
            dev_cli.sendline('yes')
            dev_cli.expect('[Pp]assword:')
        if code == 1:
            out ='Error: connection timeout'
            return out
        dev_cli.sendline(passw)
        dev_cli.expect(['.*>', '.*#'])
        dev_cli.sendline(command)
        dev_cli.expect('.*Password:')
        dev_cli.sendline(passw)
        code = dev_cli.expect(['.*#', '.*>', '.*Select:'])
        if code == 2:
            dev_cli.sendline(str(seq_nr))
            dev_cli.expect(['.*>', '.*#'])
        out = str(dev_cli.after).split("\\r\\n")
        dev_cli.sendline('exit')
        return out
    except:
        out = 'Error: Something went bad %s' % str(dev_cli.before)
        return out


#-- Connect and get routes from Juniper devices --#

def get_info_juniper(device, user, passw, command, prompt):

    PROMPT = prompt.upper()
    try:
        dev_cli = pexpect.spawn('ssh -l %s %s'%(user, device))
        dev_cli.setwinsize(60000, dev_cli.maxread)
        code = dev_cli.expect(['.*\(yes/no\)?.*', pexpect.TIMEOUT, '[Pp]assword:'])
        if code == 0:
            dev_cli.sendline('yes')
            dev_cli.expect('[Pp]assword:')
        if code == 1:
            out ='Error: connection timeout'
            return out
        dev_cli.sendline(passw)
        dev_cli.expect([prompt,PROMPT])
        dev_cli.sendline('%s' % command)
        dev_cli.expect([prompt,PROMPT])
        out = str(dev_cli.before).split("\\r\\n")
        if len(out) <= 1:
            out = str(dev_cli.after).split("\\r\\n")
        dev_cli.sendline('exit')
        return out
    except:
        out = 'Error: Something went bad %s' % str(dev_cli.after)
        return out


#-- Connect and get routes from Cisco devices --#

def get_info_nxos(device, user, passw, command, platform):

    if platform == 'NXOS':
        dev_type = 'cisco_nxos'
    elif platform == 'IOS':
        dev_type = 'cisco_ios'

    try:
        dev = ConnectHandler(device_type = dev_type, ip = device, username = user, password = passw)
        out = dev.send_command(command)
        dev.disconnect()
    except:
        error = 'Error: %s' % sys.exc_info()[1]
        return error
    return out


def usage(options):
    print('\nusage: %s [ --all | --<platform> [ -d <device> ] ]\n' % sys.argv[0])
    print('  --all                              process all routes')
    print('  --<platform> [ -d <device> ]       process routes only for specific platform,')
    opt_list = ''
    for option in options:
        if option != 'all':
            opt_list += option + ', '
    print('                                     valid platforms names are: %s' % opt_list.rstrip(', '))
    print('                                     together with platform a device can be specified - this will process routes only for that device')
    print('\n Note! Only 1 platform can be specified at a time!\n')
    sys.exit()


#---- END OF HELP FUNCTIONS ----#


#---- MAIN FUNCTION CALL ----#

if __name__ == '__main__':
    main()
