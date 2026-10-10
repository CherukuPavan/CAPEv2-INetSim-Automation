#!/usr/bin/env python3
"""Offline synthetic Windows SYSTEM hive tests. No libvirt or disk access."""
import unittest
import inspect_standalone_windows_hive as hive

GUID="{AABBCCDD-1234-1234-1234-123456789ABC}"
GUID2="{FFBBCCDD-1234-1234-1234-123456789ABC}"
IP="192.0.2.105"

class FakeHive:
    def __init__(self, extra_ip=False, dhcp=0, duplicate=False):
        self.names={1:"ROOT",2:"Select",3:"ControlSet001",4:"Services",
                    5:"Tcpip",6:"Parameters",7:"Interfaces",8:GUID}
        self.edges={(1,"Select"):2,(1,"ControlSet001"):3,
            (3,"Services"):4,(4,"Tcpip"):5,(5,"Parameters"):6,
            (6,"Interfaces"):7}
        self.child_nodes={7:[8]}
        self.values={
            (2,"Current"):(hive.REG_DWORD,(1).to_bytes(4,"little")),
            (8,"IPAddress"):(hive.REG_MULTI_SZ, multisz([IP])),
            (8,"EnableDHCP"):(hive.REG_DWORD,dhcp.to_bytes(4,"little")),
            (8,"SubnetMask"):(hive.REG_MULTI_SZ,multisz(["255.255.255.0"])),
        }
        if extra_ip:
            self.values[(8,"IPAddress")]=(hive.REG_MULTI_SZ,multisz([IP,"192.0.2.106"]))
        if duplicate:
            self.names[9]=GUID2
            self.child_nodes[7].append(9)
            for (handle,key),data in list(self.values.items()):
                if handle==8:
                    self.values[(9,key)]=data
        self.handles={key:idx+1000 for idx,key in enumerate(self.values)}
        self.reverse={v:self.values[k] for k,v in self.handles.items()}
    def root(self):return 1
    def node_get_child(self,node,name):return self.edges.get((node,name))
    def node_children(self,node):return self.child_nodes.get(node,[])
    def node_name(self,node):return self.names[node]
    def node_get_value(self,node,name):
        # Mirror Ubuntu Hivex: missing values may raise RuntimeError("Success")
        # instead of returning zero, so production must not call this method.
        raise RuntimeError("Success")
    def node_values(self,node):
        return [handle for (n,_),handle in self.handles.items() if n==node]
    def value_key(self,handle):
        return next(name for (n,name),value in self.handles.items()
                    if value==handle)
    def value_value(self,handle):return self.reverse[handle]

def multisz(values):
    return ("\x00".join(values)+"\x00\x00").encode("utf-16le")

class Tests(unittest.TestCase):
    def test_exact_static_ip_selected(self):
        result=hive.inspect(FakeHive(),expected_ip=IP)
        self.assertEqual(result["controlset"],1)
        self.assertEqual(len(result["matched_static_interfaces"]),1)
        self.assertEqual(result["matched_static_interfaces"][0]["static_ipv4"],IP)
        self.assertFalse(result["write_implemented"])

    def test_duplicate_ip_refused(self):
        with self.assertRaisesRegex(hive.HiveReadError,"unique NIC"):
            hive.inspect(FakeHive(duplicate=True),expected_ip=IP)

    def test_multiple_ips_in_one_interface_refused(self):
        with self.assertRaisesRegex(hive.HiveReadError,"multiple static IP"):
            hive.inspect(FakeHive(extra_ip=True),expected_ip=IP)

    def test_dhcp_interface_refused(self):
        with self.assertRaisesRegex(hive.HiveReadError,"not statically"):
            hive.inspect(FakeHive(dhcp=1),expected_ip=IP)

    def test_optional_registry_value_absent_without_runtime_error(self):
        fake=FakeHive()
        fake.values.pop((8,"IPAddress"))
        fake.handles.pop((8,"IPAddress"))
        result=hive.inspect(fake,expected_ip=None)
        self.assertEqual(result["matched_static_interfaces"],[])

    def test_required_registry_value_missing_is_explained(self):
        fake=FakeHive()
        fake.values.pop((2,"Current"))
        fake.handles.pop((2,"Current"))
        with self.assertRaisesRegex(hive.HiveReadError,"absent: Current"):
            hive.inspect(fake,expected_ip=None)

    def test_missing_expected_ip_refused(self):
        with self.assertRaisesRegex(hive.HiveReadError,"found 0"):
            hive.inspect(FakeHive(),expected_ip="192.0.2.19")

    def test_bad_multisz_termination_rejected(self):
        with self.assertRaisesRegex(hive.HiveReadError,"termination"):
            hive.as_multisz("hello".encode("utf-16le"),"Test")

    def test_bad_dword_rejected(self):
        with self.assertRaisesRegex(hive.HiveReadError,"DWORD"):
            hive.as_dword(b"\x01\x02","Current")

    def test_invalid_controlset_rejected(self):
        data=FakeHive()
        data.values[(2,"Current")]=(hive.REG_DWORD,(1000).to_bytes(4,"little"))
        data.reverse[data.handles[(2,"Current")]]=data.values[(2,"Current")]
        with self.assertRaisesRegex(hive.HiveReadError,"ControlSet"):
            hive.inspect(data,expected_ip=IP)

if __name__=="__main__":
    unittest.main()
