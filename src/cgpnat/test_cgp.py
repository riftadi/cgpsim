#!/usr/bin/env python3

import cgp
from unittest.mock import Mock

# ps = [
#         Primitive(cgp.PRI_IFEQ,     2), -> 0
#         Primitive(cgp.PRI_ENDIF,    0), -> 1
#         Primitive(cgp.PRI_ASSIGN,   2), -> 2
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

fake_node1 = Mock()
fake_node1.i_pri = cgp.PRI_IFEQ
fake_node1.i_inputs = [0, 5]

fake_node2 = Mock()
fake_node2.i_pri = cgp.PRI_IFEQ
fake_node2.i_inputs = [1, 3]

fake_node3 = Mock()
fake_node3.i_pri = cgp.PRI_ASSIGN
fake_node3.i_inputs = [1, 4]

fake_node4 = Mock()
fake_node4.i_pri = cgp.PRI_ENDIF
fake_node4.i_inputs = []

fake_node5 = Mock()
fake_node5.i_pri = cgp.PRI_ENDIF
fake_node5.i_inputs = []

fake_node6 = Mock()
fake_node6.i_pri = cgp.PRI_IFEQ
fake_node6.i_inputs = [0, 6]

fake_node7 = Mock()
fake_node7.i_pri = cgp.PRI_IFEQ
fake_node7.i_inputs = [2, 4]

fake_node8 = Mock()
fake_node8.i_pri = cgp.PRI_ASSIGN
fake_node8.i_inputs = [2, 3]

fake_node9 = Mock()
fake_node9.i_pri = cgp.PRI_ENDIF
fake_node9.i_inputs = []

fake_node10 = Mock()
fake_node10.i_pri = cgp.PRI_ENDIF
fake_node10.i_inputs = []

fake_nodes = [fake_node1, fake_node2, fake_node3, fake_node4, fake_node5,
              fake_node6, fake_node7, fake_node8, fake_node9, fake_node10]

sw_sim = cgp.SwitchSimulator(fake_nodes)
print(sw_sim.passed_if_analysis())
out = sw_sim.get_output(cgp.ExamInput(0, 1, 20))
print(out.port_num, out.src_ip, out.dst_ip)
