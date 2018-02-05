#!/opt/rh/rh-python35/root/usr/bin/python

import sys
import re
from f5.bigip import ManagementRoot

def usage():
    print('\nusage: %s <mode> [ <environment> ] [ <ip> | <pattern> ]' % sys.argv[0])
    print('\n Modes:')
    print('\n  -n               node mode: the lookup is done by all nodes (or specified by IP address) and finds all virtuals servers that use the node(s) in the backend.')
    print('\n  -vs              VIP mode: the lookup is done by virtual server and lists all the nodes for all (or specified by pattern or IP address) virtual servers.')
    print('\n Environments:')
    print('\n                   Valid environments are prod, prod-b and appver. If no environment is specified - by default it is appver.\n')
    sys.exit(0)

env = 'appver'
ip = None
vs = None

options = [ opt for opt in sys.argv[1:] if opt != '-n' and opt != '-vs' ]
mode_list = [ opt for opt in sys.argv[1:] if opt == '-n' or opt == '-vs' ]

if len(options) > 2:
    print('Too many options')
    usage()
    sys.exit(2)

if len(options) > 0:
    for opt in options:
        if opt.lower() == 'prod' or opt.lower() == 'prod-b' or opt.lower() == 'appver':
            env = opt.lower()
        elif re.search('^\d+\.\d+\.\d+\.\d+$', opt):
            ip = opt
        elif opt.lower() == '-h':
            usage()
        else:
            vs = str(opt)

if len(mode_list) != 1:
    print('\n1 mode must be specified: "-n" - for node lookup, "-vs" for VIP lookup')
    usage()
    sys.exit(2)

mode = mode_list[0]

if env == 'appver':
    server = 'servername'
elif env == 'prod':
    server = 'servername'
elif env == 'prod-b':
    server = 'servername'

mgmt = ManagementRoot(server, 'user', 'password')

virtuals = mgmt.tm.ltm.virtuals.get_collection()

if mode == '-vs':
    print('\nEnvironment: ' + env + '\n')
results = {}
for virt in virtuals:
    partition = virt.partition
    try:
        pool_name = virt.pool.split('/')[2]
        pool = mgmt.tm.ltm.pools.pool.load(name = pool_name, partition = partition)
        members = pool.members_s.get_collection()
        if mode == '-vs':
            if vs:
                if re.search('.*%s.*' % vs.lower(), virt.name.lower()):
                    print('\n' + virt.name + ' (' + virt.destination.split('/')[2] + ')')
            elif ip:
                if re.search('^' + ip + '%.*', virt.destination.split('/')[2]):
                    print('\n' + virt.name + ' (' + virt.destination.split('/')[2] + ')')
            else:
                print('\n' + virt.name + ' (' + virt.destination.split('/')[2] + ')')
        for member in members:
            if mode == '-n':
                try:
                    results[member.name.split('%')[0]].append( virt.name + ' (' + virt.destination.split('/')[2] + ')' )
                except KeyError:
                    results[member.name.split('%')[0]] = [ virt.name + ' (' + virt.destination.split('/')[2] + ')' ]
                    continue
            if mode == '-vs':
                if vs:
                    if re.search('.*%s.*' % vs.lower(), virt.name.lower()):
                        print(' ' + member.name.split('%')[0])
                elif ip:
                    if re.search('^' + ip + '%.*', virt.destination.split('/')[2]):
                        print(' ' + member.name.split('%')[0])
                else:
                    print(' ' + member.name.split('%')[0])
    except:
        continue

if mode == '-vs':
    sys.exit()

print('\nEnvironment: ' + env + '\n')
for ke,va in results.items():
    if ip:
        if ip == ke:
            print(ke + ':')
            for vs in va:
                print(' ' + vs)
    else:
        print('\n' + ke + ':')
        for vs in va:
            print(' ' + vs)
