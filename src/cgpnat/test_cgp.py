#!/usr/bin/env python3

import cgp

import unittest
from unittest.mock import Mock

# ps = [
#         Primitive(cgp.PRI_IFEQ,     2),
#         Primitive(cgp.PRI_ENDIF,    0),
#         Primitive(cgp.PRI_ASSIGN,   2),
#     ]

# # acts as a register
# value_map = {
#     0 : input_port,
#     1 : src_ip,
#     2 : dst_ip,
#     3 : nat_src_inside_ip,
#     4 : nat_src_outside_ip,
#     5 : nat_port_num_inside,
#     6 : nat_port_num_outside,
# }

INPUT_TXT_HH = {
                0 : "src_ip",
                1 : "dst_ip",
                2 : "n_seen",
                3 : "limit",
}

INPUT_PORT           = 0
SRC_IP               = 1
DST_IP               = 2
NAT_SRC_INSIDE_IP    = 3
NAT_SRC_OUTSIDE_IP   = 4
NAT_PORT_NUM_INSIDE  = 5
NAT_PORT_NUM_OUTSIDE = 6

SRC_IP_HH = 0
DST_IP_HH = 1
N_SEEN    = 2
LIMIT     = 3

class CGPTest(unittest.TestCase):
    def test_nat(self):
        cgp.NF_MODE = cgp.MODE_NAT

        fake_node1 = Mock()
        fake_node1.i_pri = cgp.PRI_IFEQ
        fake_node1.i_inputs = [INPUT_PORT, NAT_PORT_NUM_INSIDE]

        fake_node2 = Mock()
        fake_node2.i_pri = cgp.PRI_IFEQ
        fake_node2.i_inputs = [SRC_IP, NAT_SRC_INSIDE_IP]

        fake_node3 = Mock()
        fake_node3.i_pri = cgp.PRI_ASSIGN
        fake_node3.i_inputs = [SRC_IP, NAT_SRC_OUTSIDE_IP]

        fake_node4 = Mock()
        fake_node4.i_pri = cgp.PRI_ENDIF
        fake_node4.i_inputs = []

        fake_node5 = Mock()
        fake_node5.i_pri = cgp.PRI_ENDIF
        fake_node5.i_inputs = []

        fake_node6 = Mock()
        fake_node6.i_pri = cgp.PRI_IFEQ
        fake_node6.i_inputs = [INPUT_PORT, NAT_PORT_NUM_OUTSIDE]

        fake_node7 = Mock()
        fake_node7.i_pri = cgp.PRI_IFEQ
        fake_node7.i_inputs = [DST_IP, NAT_SRC_OUTSIDE_IP]

        fake_node8 = Mock()
        fake_node8.i_pri = cgp.PRI_ASSIGN
        fake_node8.i_inputs = [DST_IP, NAT_SRC_INSIDE_IP]

        fake_node9 = Mock()
        fake_node9.i_pri = cgp.PRI_ENDIF
        fake_node9.i_inputs = []

        fake_node10 = Mock()
        fake_node10.i_pri = cgp.PRI_ENDIF
        fake_node10.i_inputs = []

        fake_nodes = [fake_node1, fake_node2, fake_node3, fake_node4, fake_node5,
                      fake_node6, fake_node7, fake_node8, fake_node9, fake_node10]

        sw_sim = cgp.SwitchSimulator(fake_nodes)
        exam_mgr = cgp.ExamplesManager("ex_nat.json")

        fitness_value = 0
        for ex_pair in exam_mgr.example_pairs:
            ex_in, ex_out = ex_pair
            if sw_sim.get_output(ex_in) == ex_out:
                fitness_value += 10

        print(f"NAT testcase fitness value: {fitness_value}")
        self.assertEqual(fitness_value, (len(exam_mgr.example_pairs)*10))

    def test_hh(self):
        cgp.NF_MODE = cgp.MODE_HH

        fake_node1 = Mock()
        fake_node1.i_pri = 0
        fake_node1.i_inputs = [N_SEEN, LIMIT]

        fake_node2 = Mock()
        fake_node2.i_pri = 2
        fake_node2.i_inputs = []

        fake_node3 = Mock()
        fake_node3.i_pri = 1
        fake_node3.i_inputs = []

        fake_nodes = [fake_node1, fake_node2, fake_node3]

        sw_sim = cgp.SwitchSimulator(fake_nodes)
        exam_mgr = cgp.ExamplesManager("ex_hh.json")

        fitness_value = 0
        for ex_pair in exam_mgr.example_pairs:
            ex_in, ex_out = ex_pair
            if sw_sim.get_output(ex_in) == ex_out:
                fitness_value += 10

        print(f"HH testcase fitness value: {fitness_value}")
        # self.assertEqual(fitness_value, (len(exam_mgr.example_pairs)*10))


if __name__ == '__main__':
    unittest.main()
