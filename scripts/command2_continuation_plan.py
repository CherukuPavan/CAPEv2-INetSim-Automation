#!/usr/bin/env python3
"""Read-only Command 2 total-count continuation plan (never stage VMs).

Count 5 means TOTAL win11_1..win11_5, preserving accepted win11_1.
This SSL-55 adapter makes no libvirt or filesystem changes.
"""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import sys
import xml.etree.ElementTree as ET
import command2_cold_checkpoint as cold

GiB = 1024 ** 3
MAX = 16

def require(ok, message):
    if not ok: raise cold.Blocked(message)

def classify(total, inventory, occupied_paths, free):
    require(isinstance(total, int) and 1 <= total <= MAX, 'Clone total must be in [1,16]')
    require('win11_1' in inventory, 'Expected verified win11_1 clone is missing')
    names = [f'win11_{n}' for n in range(1,total+1)]
    blockers = []
    missing = []
    for index,name in enumerate(names, 1):
        disk = cold.DISK.parent / (name+'.command2.qcow2')
        nvram = cold.NVRAM.parent / (name+'.command2_VARS.fd')
        if index == 1:
            continue
        if name in inventory:
            blockers.append('Existing unverified domain: '+name)
        elif disk in occupied_paths or nvram in occupied_paths:
            blockers.append('Occupied clone artifact: '+name)
        else:
            missing.append({'name':name,'hostname':'WIN11-'+str(index),
                 'future_ipv4':f'192.168.240.{100+index}',
                 'network_attached':False,'disk':str(disk),'nvram':str(nvram)})
    needed = len(missing)*64+30
    return {'result':'COMMAND2_TOTAL_COUNT_PLAN_ONLY',
            'target_total':total,'existing_accepted':['win11_1'],
            'missing':missing,'blockers':blockers,
            'needed_conservative_gib':needed,
            'free_gib':round(free/GiB,2),
            'storage_nominally_sufficient':free>=needed*GiB,
            'capture_and_network_not_authorized':True,
            'staging_not_authorized':True,
            'no_vm_created':True,
            'note':'Existing win11_1 validated only; others cannot be blindly reused'}

def current_inventory():
    names = set(cold.virsh('list','--all','--name').splitlines())
    require('win11_1' in names, 'Previously verified win11_1 domain disappeared')
    # This includes the protected-master, trial, swtpm/NVRAM, and zero-NIC checks.
    cold.guards('plan')
    return names

def perform(total):
    require(os.geteuid()==0,'Run with sudo/root')
    inventory=current_inventory()
    occupied=set()
    for i in range(2,total+1):
        name=f'win11_{i}'
        for path in (cold.DISK.parent/(name+'.command2.qcow2'),
                     cold.NVRAM.parent/(name+'.command2_VARS.fd')):
            if path.exists() or path.is_symlink():
                occupied.add(path)
    return classify(total,inventory,occupied,cold.free_bytes())

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--count',type=int)
    args=parser.parse_args()
    count=args.count
    try:
        if count is None:
            require(sys.stdin.isatty(),'Interactive terminal or --count is required')
            count=int(input('TOTAL Windows clone count [1-16]: '))
        result=perform(count)
        print(json.dumps(result,indent=2,sort_keys=True))
        return 0 if not result['blockers'] else 2
    except (cold.Blocked,ValueError,OSError,ET.ParseError) as e:
        print('BLOCKED: '+str(e),file=sys.stderr)
        return 2
if __name__=='__main__':raise SystemExit(main())
