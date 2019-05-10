#!/usr/bin/env python3

from typing import Dict, List

import json

import cgp

DEBUG = False

RPS = 1000 # how many Rounds Per Second
N_ROUNDS = 1000
IP_ADDR_HASH_RANGE = 1024


def print_pkt_in(curr_time, dev_name, in_port, pkt, spotlight = False):
    if DEBUG:
        prefix = afix = ""
        if spotlight:
            prefix = "> "
            afix = " <"
        print(f"{prefix}t{curr_time:04d}: {dev_name}: "
              f"pkt in p{in_port}: {pkt}{afix}")


class SwitchP4CodeStore:
    def __init__(self, codes: Dict[str, List[str]]) -> None:
        self.codes = codes

    def get_code(self, sw_name: str) -> List[str]:
        return self.codes[sw_name]


class Packet:
    def __init__(self, src_ip: str, dst_ip: str, dscp: int) -> None:
        self.src_ip = IPAddress(src_ip)
        self.dst_ip = IPAddress(dst_ip)
        self.dscp = dscp
        self.delay_traces = []

    def __str__(self):
        return f"{self.src_ip} -> {self.dst_ip}, dscp:{self.dscp}"

    def get_src_ip(self):
        return self.src_ip

    def get_dst_ip(self):
        return self.dst_ip

    def get_src_ip_str(self):
        return str(self.src_ip)

    def get_dst_ip_str(self):
        return str(self.dst_ip)

    def get_dscp(self):
        return self.dscp

    def stamp_delay(self, delay):
        self.delay_traces.append(delay)

    def get_total_delay(self):
        result = 0
        for delay in self.delay_traces:
            result += delay
        return result


class InternalPacket:
    def __init__(self, packet: Packet, in_port: int, curr_time: int) -> None:
        self.packet = packet
        self.in_port = in_port
        self.out_port = None
        self.in_time = curr_time

    def get_packet(self):
        return self.packet

    def get_in_port(self):
        return self.in_port

    def get_out_port(self):
        return self.out_port

    def set_out_port(self, out_port: int) -> None:
        self.out_port = out_port


class TimedItem:
    def __init__(self, item, timer):
        self.item = item
        self.timer = timer

    def tick(self):
        if self.timer > 0:
            self.timer -= 1

    def is_finished(self):
        return self.timer == 0

    def get_item(self):
        return self.item


class TimedList:
    def __init__(self):
        self.items = []

    def put_item(self, item, timer):
        self.items.append(TimedItem(item, timer))

    def pop_items(self):
        out = []
        new_items = []

        for item in self.items:
            if item.is_finished():
                out.append(item.get_item())
            else:
                new_items.append(item)
        self.items = new_items

        return out

    def tick(self):
        for item in self.items:
            item.tick()


class IPAddress:
    def __init__(self, addr: str) -> None:
        self.addr = addr
        self.octet = []
        for nums in addr.split("."):
            self.octet.append(int(nums))
        assert len(self.octet) == 4
        self.int_rep = 0
        for idx in range(len(self.octet)):
            self.int_rep += 256**(3-idx) * self.octet[idx]

    def __int__(self):
        return self.int_rep

    def __str__(self):
        return self.addr

    def __eq__(self, other):
        return self.int_rep == other.int_rep


class NetworkDevice:
    def __init__(self, name: str, delay: int) -> None:
        self.name = name
        self.delay = delay
        self.queue = TimedList()
        self.iclock = 0

    def get_name(self):
        return self.name

    def get_delay(self):
        return self.delay

    def admit_pkts(self, pkts, in_port, curr_time):
        for pkt in pkts:
            print_pkt_in(curr_time, self.name, in_port, pkt)
            pkt.stamp_delay(self.delay)
            ipkt = InternalPacket(pkt, in_port, curr_time)
            ipkt.set_out_port(self.compute_out_port(ipkt))
            self.queue.put_item(ipkt, self.delay)

    def pop_pkts(self):
        return [(ipkt.get_packet(), ipkt.get_out_port())
                    for ipkt in self.queue.pop_items()]

    def tick(self):
        self.queue.tick()
        self.iclock += 1

    def compute_out_port(self, ipkt):
        pass


class Switch(NetworkDevice):
    def __init__(self, name: str, delay: int, phenotype: cgp.Phenotype):
        super().__init__(name, delay)
        self.n_ports = 0
        self.phenotype = phenotype
        self.sw_id = int(name.replace("s", ""))

    def set_n_ports(self, n_ports):
        self.n_ports = n_ports

    def compute_out_port(self, ipkt):
        in_port = ipkt.get_in_port()
        src_ip = hash(int(ipkt.get_packet().get_src_ip())) % IP_ADDR_HASH_RANGE
        dst_ip = hash(int(ipkt.get_packet().get_dst_ip())) % IP_ADDR_HASH_RANGE
        dscp = ipkt.get_packet().get_dscp()

        outs = self.phenotype.eval(self.sw_id, in_port, src_ip, dst_ip, dscp)
        if DEBUG:
            print(f"f({self.sw_id}, {in_port}, {src_ip}, {dst_ip}, {dscp}) -> "
                  f"{outs} -> {outs[self.sw_id-1] % self.n_ports}")
        return outs[self.sw_id-1] % self.n_ports


class Link(NetworkDevice):
    def __init__(self, name: str, delay: int, endpoints: List[str]) -> None:
        super().__init__(name, delay)
        self.endpoints = endpoints

    def compute_out_port(self, ipkt):
        if ipkt.get_in_port() == 0:
            return 1
        else:
            return 0


class Host:
    def __init__(self, name: str, ip_addr: str) -> None:
        self.name = name
        self.ip_addr = IPAddress(ip_addr)
        self.targets = []
        self.divisors = []

    def get_name(self):
        return self.name

    def get_ip_addr(self):
        return self.ip_addr

    def add_target(self, name: str, pps_rate: int) -> None:
        divisor = int(RPS/pps_rate)
        self.divisors.append(divisor)
        self.targets.append({
                                "dst_addr": name,
                                "pps_rate": pps_rate,
                                "divisor": divisor
                             })

    def is_action_needed(self, curr_time):
        action_flag = False
        for divisor in self.divisors:
            if curr_time % divisor == 0:
                action_flag = True
                break
        return action_flag

    def generate_packets(self, curr_time):
        out = []
        for target in self.targets:
            if curr_time % target["divisor"] == 0:
                out.append(Packet(str(self.ip_addr), target["dst_addr"], 32))
        return out

    def admit_pkts(self, pkts, in_port, curr_time):
        for pkt in pkts:
            print_pkt_in(curr_time, self.get_name(), in_port, pkt, spotlight=True)


class NetworkSimulator:
    def __init__(self, topology_filename: str, phenotype: cgp.Phenotype) -> None:
        self.hosts = {}
        self.switches = {}
        self.links = {}
        self.port_map = {}
        self.port_idx = {}
        self.sent_pkt_counter = 0
        self.rcvd_pkt_counter = 0
        self.phenotype = phenotype

        self.build_topology(topology_filename)
        self.update_switches_port_count()

    def get_packet_counters(self):
        return (self.sent_pkt_counter, self.rcvd_pkt_counter)

    def get_fitness_value(self):
        return self.rcvd_pkt_counter

    def get_next_dev_port(self, curr_dev, curr_port):
        return self.port_map[(curr_dev, curr_port)]

    def build_hosts(self) -> None:
        for name, details in self.topo["hosts"].items():
            self.port_idx[name] = 0
            host = Host(name, details["ip_addr"])
            for target in details["targets"]:
                host.add_target(target["dst_addr"], target["pps_rate"])
            self.hosts[name] = host

    def build_switches(self) -> None:
        for name, details in self.topo["switches"].items():
            self.port_idx[name] = 0
            self.switches[name] = Switch(name, details["delay"], self.phenotype)

    def build_links(self) -> None:
        for name, details in self.topo["links"].items():
            self.links[name] = Link(name, details["delay"], details["endpoints"])

            ep_idx = 0
            for endpoint in details["endpoints"]:
                self.port_map[(endpoint, self.port_idx[endpoint])] = (name, ep_idx)
                self.port_map[(name, ep_idx)] = (endpoint, self.port_idx[endpoint])
                ep_idx += 1
            self.port_idx[name] = ep_idx

            for endpoint in details["endpoints"]:
                self.port_idx[endpoint] += 1

    def update_switches_port_count(self):
        for sw_name, sw in self.switches.items():
            sw.set_n_ports(self.port_idx[sw_name])

    def build_topology(self, topology_filename: str) -> None:
        with open(topology_filename, 'r') as fh:
            self.topo = json.load(fh)

        self.build_hosts()
        self.build_switches()
        self.build_links()

        if DEBUG:
            print(self.port_map)

    def run_hosts(self, curr_time: int) -> None:
        for hname, host in self.hosts.items():
            if host.is_action_needed(curr_time):
                # assume that host always has 1 port
                next_dev, next_port = self.get_next_dev_port(hname, 0)
                pkts = host.generate_packets(curr_time)
                self.links[next_dev].admit_pkts(pkts, next_port, curr_time)
                self.sent_pkt_counter += len(pkts)

    def check_against_constraints(self, pkt, next_dev):
        # packet is not destined to the host
        if pkt.get_dst_ip() != self.hosts[next_dev].get_ip_addr():
            return False

        # write rules here
        # Rule 1: from h1 to h4 delay <= 80 ms
        if (pkt.get_src_ip_str() == "192.168.1.1" and
            pkt.get_dst_ip_str() == "192.168.4.4" and
            pkt.get_total_delay() > 80):
                return False

        # Rule 2: from h2 to h1 delay <= 100 ms
        if (pkt.get_src_ip_str() == "192.168.2.2" and
            pkt.get_dst_ip_str() == "192.168.1.1" and
            pkt.get_total_delay() > 100):
                return False

        return True

    def run_links(self, curr_time: int) -> None:
        for lname, link in self.links.items():
            link.tick()
            pktports = link.pop_pkts()
            for pktport in pktports:
                pkt, curr_port = pktport
                next_dev, next_port = self.get_next_dev_port(lname, curr_port)
                if next_dev[0] == 'h':
                    self.hosts[next_dev].admit_pkts([pkt], next_port, curr_time)
                    if self.check_against_constraints(pkt, next_dev):
                        self.rcvd_pkt_counter += 1
                elif next_dev[0] == 's':
                    self.switches[next_dev].admit_pkts([pkt], next_port, curr_time)

    def run_switches(self, curr_time: int) -> None:
        for swname, switch in self.switches.items():
            switch.tick()
            pktports = switch.pop_pkts()
            for pktport in pktports:
                pkt, curr_port = pktport
                next_dev, next_port = self.get_next_dev_port(swname, curr_port)
                self.links[next_dev].admit_pkts([pkt], next_port, curr_time)

    def run(self, runtime: int = N_ROUNDS) -> None:
        for curr_time in range(runtime):
            self.run_hosts(curr_time)
            self.run_links(curr_time)
            self.run_switches(curr_time)


class CGPSimulator:
    def __init__(self, n_phenotypes: int) -> None:
        self.phenotypes = cgp.create_phenotypes(n_phenotypes)
        self.max_value = 0

    def evaluate_generation(self) -> None:
        for ind in self.phenotypes:
            netsim = NetworkSimulator("topology.json", ind)
            netsim.run()
            max_value, fitness_value = netsim.get_packet_counters()

            if max_value > self.max_value:
                self.max_value = max_value

            ind.set_fitness(fitness_value)

    def evolve_generations(self, n_generations: int) -> None:
        for gen_idx in range(n_generations):
            self.evaluate_generation()

            f_vals = [ind.fitness for ind in self.phenotypes]
            print(f"Gen {gen_idx+1}: {f_vals}")

            self.phenotypes = cgp.evolve(self.phenotypes,
                                            cgp.MUT_PB,
                                            cgp.MU,
                                            cgp.LAMBDA)

        # evaluate for the last time
        self.evaluate_generation()

    def print_fittest_phenotype(self):
        inds = sorted(self.phenotypes, key=lambda ind: ind.fitness)
        fittest_phenotype = inds[-1]
        p4_code = str(fittest_phenotype)

        print("\nFinal P4 code (fitness value "
                f"f={fittest_phenotype.fitness}/{self.max_value},"
                f" code length l={len(p4_code.splitlines())}):\n")
        print(fittest_phenotype)
        print()
