#!/opt/rh/rh-python35/root/usr/bin/python

import configparser
import pexpect
import re
import getopt
import sys
import subprocess
import ipaddress
import requests
import urllib3
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

    ##Get and check options - Edit here to add new platforms!
    long_opt_list = ['all', 'CP', 'VSX', 'SRX', 'NS', 'IOS', 'NXOS']
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
        out_file = '%s/hosts-import' % out_dir
        opt_device = None
        platform = None

    ##Primary function call
    get_interfaces(conf_file, basedir, workdir, opt_device, out_file, platform, long_opt_list)


#---- END OF MAIN FUNCTION ----#


#-- Classes --#

class router(object):

    def __init__(misa, hostname, user, passw, platform):
        misa.hostname = hostname
        misa.user = user
        misa.passw = passw
        misa.platform = platform

    def iface_list(misa, command):
        prompt = '%s#' % misa.hostname

        if misa.platform == 'NXOS' or misa.platform == 'IOS':
            status = None
            urllib3.disable_warnings()
            dev_names = [ misa.hostname, misa.hostname + '.sebank.se' ]
            for dev_name in dev_names:
                url = '%s/data/ConfigVersions?deviceName=%s&isLast=True&.full=true' % (command, dev_name)
                out = requests.get(url, verify=False).text.split('\n')
                for line in out:
                    if re.search('.*fileId.*', line):
                        file_id = re.sub('<\/?fileId>', '', line).lstrip()
                        status = 'OK'
                        break
                if status:
                    break
            if not status:
                return 'Error:'
            else:
                url = '%s/op/configArchiveService/extractSanitizedFile?fileId=%s' % (command, file_id)
                out = requests.get(url, verify=False).text.split('\n')
                return out

        if misa.platform == 'CP':
            try:
                cmd_output = subprocess.check_output(command, shell=True)
                out = str(cmd_output).split('\\n')
                return out
            except:
                error = 'Error: %s' % sys.exc_info()[1]
                return error

        if misa.platform == 'VSX':
            command, seq_nr = command.split('--')
            out = get_info_cp_vsx(misa.hostname, misa.user, misa.passw, command, seq_nr)
            return out

        if misa.platform == 'SRX':
            prompt = '%s>' % misa.hostname
            out = get_info_srx(misa.hostname, misa.user, misa.passw, command, prompt)
            return out

        if misa.platform == 'NS':
            prompt = '.*->'
            out = get_info_netscreen(misa.hostname, misa.user, misa.passw, command, prompt)
            return out


#-- Primmary function to get routes from all devices --#

def get_interfaces(conf_file, basedir, workdir, opt_device, out_file, platform, long_opt_list):

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
        prime_user = config.get('logins', 'prime_user')
        prime_passw = config.get('logins', 'prime_passw')

        platform_iface_count = 0
        for hostname in devices:

            if platform != 'VSX':
                device = router(hostname, user, passw, platform)

            if platform == 'IOS' or platform == 'NXOS':
                url = 'https://%s:%s@172.17.123.84/webacs/api/v1' % (prime_user, prime_passw)

                interfaces = device.iface_list(url)
                if re.search('^Error.*', str(interfaces)):
                    print('Unable to get config from device %s' % hostname)
                    continue

                hsrp = ''
                for line in interfaces:
                    if re.search('^(hostname|switchname).*', line):
                        vdc = line.split()[1]
                        if vdc.upper() == 'BUP':
                            vdc = vdc.lower()
                            dev_name = hostname.split('-')[0]
                        else:
                            vdc = ''
                            dev_name = hostname

                    if re.search('^interface.*', line):
                        iface = line.split()[1]
                        vrf = ''

                    if re.search('^\ +(vrf\ member|vrf\ forwarding).*', line):
                        vrf = line.split()[2]

                    if re.search('^\ +ip\ vrf\ forwarding.+', line):
                        vrf = line.split()[3]

                    if re.search('^\ +ip\ address.*', line):
                        ipaddr = re.sub('/.*$', '', line.split()[2])
                        out_line = ipaddr + '|' + dev_name + '|' + vdc + '|' + vrf + '|' + iface + '|\n'
                        output.write(out_line)
                        platform_iface_count += 1

                    if re.search('^\ +standby.*ip.*', line):
                        if len(line.split()) == 3:
                            ipaddr = line.split()[2]
                            group = '0'
                        else:
                            ipaddr = line.split()[3]
                            group = line.split()[1]
                        out_line = ipaddr + '|' + dev_name + '|' + vdc + '|' + vrf + '|' + iface + '|' + 'hsrp-' + group + '\n'
                        output.write(out_line)
                        platform_iface_count += 1

                    if re.search('.*hsrp\ \d+.*', line):
                        group = line.split()[1]
                        hsrp = 'on'

                    if re.search('^\ +ip\ \d+.*', line) and hsrp == 'on':
                        ipaddr = line.split()[1]
                        out_line = ipaddr + '|' + dev_name + '|' + vdc + '|' + vrf + '|' + iface + '|' + 'hsrp-' + group + '\n'
                        output.write(out_line)
                        platform_iface_count += 1
                        hsrp = ''

            if platform == 'CP':
                cp_scr = '/opt/app/network/bin/chkp-search'
                command = '%s -gw %s' % (cp_scr, hostname)

                interfaces = device.iface_list(command)
                if re.search('^Error.*', str(interfaces)):
                    print('%s - %s' % (hostname, str(interfaces)))
                    continue

                switch = 'off'
                for line in interfaces:
                    if re.search('.*\|\d+\.\d+\.\d+\.\d+\|.*', line):
                        ipaddr = line.split('|')[1]
                        iface = line.split('|')[0].lstrip()
                        out_line = ipaddr + '|' + hostname + '|||' + iface + '|\n'
                        output.write(out_line)
                        platform_iface_count += 1

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

                command = 'vsx_util view_vs_conf -c %s -u admin -s 127.0.0.1--%s' % (hostname, seq_nr)

                interfaces = device.iface_list(command)
                if re.search('^Error.*', str(interfaces)):
                    print('%s - %s' % (hostname, str(interfaces)))
                    continue

                for line in interfaces:
                    if re.search('^\|.*IPv4.*', line):
                        iface = re.sub('\ IPv4', '', line.split('|')[1]).rstrip()
                        ipaddr = re.sub('/\d+$', '', line.split('|')[2].rstrip())
                        out_line = ipaddr + '|' + cluster + '|' + hostname + '||' + iface + '|\n'
                        if ipaddr != '0.0.0.0':
                            output.write(out_line)
                            platform_iface_count += 1

            if platform == 'SRX':
                command = 'show interfaces routing-instance all | display xml | no-more'

                interfaces = device.iface_list(command)
                if re.search('^Error.*', str(interfaces)):
                    print('%s - %s' % (hostname, str(interfaces)))
                    continue

                for line in interfaces:
                    if re.search('.*<name>.*', line):
                        iface = re.sub('<\/?name>', '', line).lstrip()
                    if re.search('.*logical-interface-zone.*', line):
                        zone = re.sub('<\/?logical-interface-zone-name>', '', line).lstrip()
                    if re.search('.*ifa-local.*', line):
                        ipaddr = re.sub('<\/?ifa-local>', '', line).lstrip()
                        if re.search('^\d+\.\d+\.\d+\.\d+$', ipaddr):
                            out_line = ipaddr + '|' + hostname + '||' + zone + '|' + iface + '|\n'
                            output.write(out_line)
                            platform_iface_count += 1

            if platform == 'NS':
                command = 'get vrouter all interface'

                interfaces = device.iface_list(command)
                if re.search('^Error.*', str(interfaces)):
                    print('%s - %s' % (hostname, interfaces))
                    continue

                vr = None
                iface_dict = {}
                for line in interfaces:
                    line = re.sub('^b.*x08', '', line)
                    if re.search('.*\(\d+\):$', line):
                        vr = re.sub('\(\d+\):', '', line)
                        continue
                    if vr:
                        if not re.search('^%s.*' % hostname, line):
                            ifaces = re.sub(r'^\\t?', '', line).split(',')
                            for iface in ifaces:
                                iface = iface.lstrip()
                                iface = re.sub('ethernet', 'eth', iface)
                                iface = re.sub('tunnel', 'tun', iface)
                                iface_dict[iface] = vr

                command = 'get interface all'

                interfaces = device.iface_list(command)

                for line in interfaces:
                    line = re.sub('^b.*x08', '', line)
                    if re.search('.*\d+\.\d+\.\d+\.\d+/\d+.*U.*', line) and not re.search('.*0\.0\.0\.0/0.*U.*', line):
                        iface = line.split()[0]
                        try:
                            vsys = line.split()[7]
                        except IndexError:
                            vsys = 'Root'
                        ipaddr = re.sub('/.*$', '', line.split()[1])
                        vr = iface_dict[iface]
                        out_line = ipaddr + '|' + hostname + '|' + vsys + '|' + vr + '|' + iface + '|\n'
                        output.write(out_line)
                        platform_iface_count += 1


        print('Total %s %s interfaces written to file %s' % (platform_iface_count, platform, out_file))

    output.close()


#---- HELP FUNCTIONS ----#


#-- Connect and get routes from NetScreen devices --#

def get_info_netscreen(device, user, passw, command, prompt):

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
        dev_cli.sendline(command)
        code = dev_cli.expect([prompt, '.*\ more\ .*'])
        out = ''
        try:
            while code == 1:
                if out == '':
                    out = str(dev_cli.after).split("\\r\\n")
                else:
                    out += str(dev_cli.after).split("\\r\\n")
                dev_cli.sendline('')
                code = dev_cli.expect([prompt, '.*\ more\ .*'])
            out += str(dev_cli.after).split("\\r\\n")
            dev_cli.sendline('exit')
        except:
            out = str(dev_cli.after).split("\\r\\n")
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

def get_info_srx(device, user, passw, command, prompt):

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
