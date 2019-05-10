#!/usr/bin/env python3

import operator
import random

from typing import Dict, List, Tuple

import snippet as sn

# Protocol type definition
ProtoType = int
TCP = 100
UDP = 200
ProtoNameMap = {TCP : "tcp", UDP: "udp"}

# Network Function type definition
NFType = int
HH   = 10
DDoS = 20
SS   = 30

HH_COUNTER_LEN = 1024
DDoS_SRC_HOSTS = 1024
DDoS_DST_HOSTS = 32
SS_SRC_HOSTS   = 32
SS_DST_HOSTS   = 1024

OperatorMap = {
                "<=" : operator.le,
                "<"  : operator.lt,
                "==" : operator.eq,
                "!=" : operator.ne,
                ">=" : operator.ge,
                ">"  : operator.gt
              }

# Action type definition
ActionType = int
FWD  = 140
DROP = 150
ActionNameMap = {FWD : "fwd", DROP: "drop"}

# Salt assortiment for hashing
HASH_SALT1 = 84192
HASH_SALT2 = 94282
HASH_SALT3 = 36715

# Max IPv4 address in integer
MAX_IP_ADDR = 4294967295
# Max TCP/UDP port number in integer
MAX_PORT_NUM = 65535

# Print debugging logs?
DEBUG = False


def int_to_ip(val: int) -> str:
    octets = [str(int(val/256**idx)%256) for idx in reversed(range(4))]
    return '.'.join(octets)


class IPAddress:
    def __init__(self, addr: str) -> None:
        self.addr = addr
        self.octets = [int(nums) for nums in addr.split(".")]
        assert len(self.octets) == 4, "IP address should have 4 octets!"
        self.int_rep = 0
        for idx in range(len(self.octets)):
            self.int_rep += 256**(3-idx) * self.octets[idx]

    def __int__(self):
        return self.int_rep

    def __str__(self):
        return self.addr

    def __eq__(self, other):
        return self.int_rep == other.int_rep


class Packet:
    def __init__(self, src_ip: str, dst_ip: str, l4_proto: ProtoType,
                    l4_src_port: int, l4_dst_port: int) -> None:
        self._src_ip = IPAddress(src_ip)
        self._dst_ip = IPAddress(dst_ip)
        self._l4_proto = l4_proto
        self._l4_src_port = l4_src_port
        self._l4_dst_port = l4_dst_port

    def __str__(self):
        proto = ""
        if self._l4_proto == TCP:
            proto = "tcp"
        elif self._l4_proto == UDP:
            proto = "udp"
        return (f"{proto}, {self._src_ip}:{self._l4_src_port} -> "
                f"{self._dst_ip}:{self._l4_dst_port}")

    @property
    def src_ip(self) -> IPAddress:
        return self._src_ip

    @property
    def dst_ip(self) -> IPAddress:
        return self._dst_ip

    @property
    def l4_proto(self) -> ProtoType:
        return self._l4_proto

    @property
    def l4_src_port(self) -> int:
        return self._l4_src_port

    @property
    def l4_dst_port(self) -> int:
        return self._l4_dst_port


class NetworkFunction:
    def __init__(self, type: NFType, op: str, limit: int) -> None:
        self._type = type
        self._op = op
        self._limit = limit
        if type == HH:
            self._hh_counters = [0] * HH_COUNTER_LEN
        elif type == DDoS:
            self._ddos_counters = [[0] * DDoS_SRC_HOSTS] * DDoS_DST_HOSTS
            self._ddos_counters_n = [0] * DDoS_DST_HOSTS
        elif type == SS:
            self._ss_counters = [[0] * SS_DST_HOSTS] * SS_SRC_HOSTS
            self._ss_counters_n = [0] * SS_SRC_HOSTS

    def get_action(self, pkt: Packet) -> ActionType:
        out = FWD

        if self._type == HH:
            out = self.get_action_hh(pkt)
        elif self._type == DDoS:
            out = self.get_action_ddos(pkt)
        elif self._type == SS:
            out = self.get_action_ss(pkt)

        return out

    def _hash_hh(self, salt: int, pkt: Packet) -> int:
        return hash((salt, int(pkt.src_ip), int(pkt.dst_ip), pkt.l4_proto,
                        pkt.l4_src_port, pkt.l4_dst_port)) % HH_COUNTER_LEN

    def get_action_hh(self, pkt: Packet) -> ActionType:
        out = FWD

        hash1 = self._hash_hh(HASH_SALT1, pkt)
        hash2 = self._hash_hh(HASH_SALT2, pkt)
        hash3 = self._hash_hh(HASH_SALT3, pkt)

        self._hh_counters[hash1] += 1
        self._hh_counters[hash2] += 1
        self._hh_counters[hash3] += 1

        min_val = min(
                        self._hh_counters[hash1],
                        self._hh_counters[hash2],
                        self._hh_counters[hash3]
                    )

        if OperatorMap[self._op](min_val, self._limit):
            out = DROP

        return out

    def get_action_ddos(self, pkt: Packet) -> ActionType:
        out = FWD

        src_hash = hash((int(pkt.src_ip))) % DDoS_SRC_HOSTS
        dst_hash = hash((int(pkt.dst_ip))) % DDoS_DST_HOSTS

        if self._ddos_counters[dst_hash][src_hash] == 0:
            self._ddos_counters[dst_hash][src_hash] = 1
            self._ddos_counters_n[dst_hash] += 1

        if OperatorMap[self._op](self._ddos_counters_n[dst_hash], self._limit):
            out = DROP

        return out

    def get_action_ss(self, pkt: Packet) -> ActionType:
        out = FWD

        src_hash = hash((int(pkt.src_ip))) % SS_SRC_HOSTS
        dst_hash = hash((int(pkt.dst_ip))) % SS_DST_HOSTS

        if self._ss_counters[src_hash][dst_hash] == 0:
            self._ss_counters[src_hash][dst_hash] = 1
            self._ss_counters_n[src_hash] += 1

        if OperatorMap[self._op](self._ss_counters_n[src_hash], self._limit):
            out = DROP

        return out

class PacketGenerator:
    def __init__(self, n_seed: int = 10) -> None:
        self._n_seed = n_seed
        self._src_ips = []
        self._dst_ips = []
        self._src_ports = []
        self._dst_ports = []

    def generate(self, n_pkt: int) -> List[Packet]:
        packets = []

        for _ in range(self._n_seed):
            src_ip = int_to_ip(random.randint(0, MAX_IP_ADDR)-1)
            dst_ip = int_to_ip(random.randint(0, MAX_IP_ADDR)-1)
            src_port = random.randint(0, MAX_PORT_NUM)-1
            dst_port = random.randint(0, MAX_PORT_NUM)-1
            self._src_ips.append(src_ip)
            self._dst_ips.append(dst_ip)
            self._src_ports.append(src_port)
            self._dst_ports.append(dst_port)

        for _ in range(n_pkt):
            src_ip = self._src_ips[random.randint(0, self._n_seed)-1]
            dst_ip = self._dst_ips[random.randint(0, self._n_seed)-1]
            proto = TCP
            if random.randint(0, self._n_seed) % 2 == 1:
                proto = UDP
            src_port = self._src_ports[random.randint(0, self._n_seed)-1]
            dst_port = self._dst_ports[random.randint(0, self._n_seed)-1]

            pkt = Packet(src_ip, dst_ip, proto, src_port, dst_port)
            packets.append(pkt)

        return packets


class IntentMachine:
    def __init__(self, intent: str) -> None:
        self._intent = intent
        self._nfs = []

    @property
    def intent(self) -> str:
        return self._intent

    def add_network_function(self, nf: NetworkFunction) -> None:
        self._nfs.append(nf)

    def get_action(self, pkt: Packet) -> ActionType:
        out = FWD
        for nf in self._nfs:
            if nf.get_action(pkt) == DROP:
                out = DROP
                break
        return out


class SwitchSimulator:
    def __init__(self, snippets: List[sn.Snippet]) -> None:
        self._snippets = snippets
        self._metas = {
                        "minRegVal"            : 0,
                        "uniqueSrcCounterDdos" : 0,
                        "uniqueDstCounterSs"   : 0
                      }

        # initiate switch registers
        self._hh_counters = [0] * HH_COUNTER_LEN
        self._ddos_counters = [[0] * DDoS_SRC_HOSTS] * DDoS_DST_HOSTS
        self._ddos_counters_n = [0] * DDoS_DST_HOSTS
        self._ss_counters = [[0] * SS_DST_HOSTS] * SS_SRC_HOSTS
        self._ss_counters_n = [0] * SS_SRC_HOSTS

        # temporary hard-coded operator and limits,
        # it should be read from the intent directly
        self._params = {
                            "hh_op"      : ">",
                            "hh_limit"   : 20,
                            "ddos_op"    : ">",
                            "ddos_limit" : 5,
                            "ss_op"      : ">",
                            "ss_limit"   : 5
                       }

    def _hash_hh(self, salt: int, pkt: Packet) -> int:
        return hash((salt, int(pkt.src_ip), int(pkt.dst_ip), pkt.l4_proto,
                        pkt.l4_src_port, pkt.l4_dst_port)) % HH_COUNTER_LEN

    def get_action(self, pkt: Packet) -> ActionType:
        action = FWD

        for snippet in self._snippets:
            if snippet.nf_code == sn.HH1:
                hash1 = self._hash_hh(HASH_SALT1, pkt)
                hash2 = self._hash_hh(HASH_SALT2, pkt)
                hash3 = self._hash_hh(HASH_SALT3, pkt)

                self._hh_counters[hash1] += 1
                self._hh_counters[hash2] += 1
                self._hh_counters[hash3] += 1

                min_val = min(
                                self._hh_counters[hash1],
                                self._hh_counters[hash2],
                                self._hh_counters[hash3]
                            )
                self._metas["minRegVal"] = min_val

            elif snippet.nf_code == sn.HH2:
                op = OperatorMap[self._params["hh_op"]]
                if op(self._metas["minRegVal"], self._params["hh_limit"]):
                    action = DROP
                    break

            elif snippet.nf_code == sn.DDoS1:
                src_hash = hash((int(pkt.src_ip))) % DDoS_SRC_HOSTS
                dst_hash = hash((int(pkt.dst_ip))) % DDoS_DST_HOSTS

                if self._ddos_counters[dst_hash][src_hash] == 0:
                    self._ddos_counters[dst_hash][src_hash] = 1
                    self._ddos_counters_n[dst_hash] += 1

                self._metas["uniqueSrcCounterDdos"] = self._ddos_counters_n[dst_hash]

            elif snippet.nf_code == sn.DDoS2:
                op = OperatorMap[self._params["ddos_op"]]
                if op(self._metas["uniqueSrcCounterDdos"], self._params["ddos_limit"]):
                    action = DROP
                    break

            elif snippet.nf_code == sn.SS1:
                src_hash = hash((int(pkt.src_ip))) % SS_SRC_HOSTS
                dst_hash = hash((int(pkt.dst_ip))) % SS_DST_HOSTS

                if self._ss_counters[src_hash][dst_hash] == 0:
                    self._ss_counters[src_hash][dst_hash] = 1
                    self._ss_counters_n[src_hash] += 1

                self._metas["uniqueDstCounterSs"] = self._ss_counters_n[src_hash]

            elif snippet.nf_code == sn.SS2:
                op = OperatorMap[self._params["ss_op"]]
                if op(self._metas["uniqueDstCounterSs"], self._params["ss_limit"]):
                    action = DROP
                    break

        return action
