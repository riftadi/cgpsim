#!/usr/bin/env python3

HH1   = 10
HH2   = 20
DDoS1 = 30
DDoS2 = 40
SS1   = 50
SS2   = 60

code_hh_compute = """            if (hdr.tcp.isValid()) {
                compute_tcp_reg_index();
            } else if (hdr.udp.isValid()) {
                compute_udp_reg_index();
            } else {
                compute_ipv4_reg_index();
            }

            update_register();
"""

code_hh_determine = """            if (meta.minRegVal > HH_THRESHOLD) {
                drop();
                return;
            }
"""

code_ddos_compute = """            compute_ipv4_dst_hash_index_ddos();
            compute_ipv4_src_hash_index_ddos();

            regSketchBitmapDdos.read(tmpBitDdos, meta.dstHashIdxDdos*8 + meta.srcHashIdxDdos);
            if (tmpBitDdos == 0) {
                process_new_flow_ddos();
            }

            regUniqueSrcDdos.read(meta.uniqueSrcCounterDdos, meta.dstHashIdxDdos);
"""

code_ddos_determine = """            if (meta.uniqueSrcCounterDdos > DDOS_THRESHOLD) {
                drop();
                return;
            }
"""

code_ss_compute = """            compute_ipv4_src_hash_index_ss();
            compute_ipv4_dst_hash_index_ss();

            regSketchBitmapSs.read(tmpBitSs, meta.srcHashIdxSs*8 + meta.dstHashIdxSs);
            if (tmpBitSs == 0) {
                process_new_flow_ss();
            }

            regUniqueDstSs.read(meta.uniqueDstCounterSs, meta.srcHashIdxSs);
"""

code_ss_determine = """            if (meta.uniqueDstCounterSs > SS_THRESHOLD) {
                drop();
                return;
            }
"""

snippet_map = {
                    HH1   : code_hh_compute,
                    HH2   : code_hh_determine,
                    DDoS1 : code_ddos_compute,
                    DDoS2 : code_ddos_determine,
                    SS1   : code_ss_compute,
                    SS2   : code_ss_determine
              }

snippet_code_txt = {
                        HH1   : "HH1",
                        HH2   : "HH2",
                        DDoS1 : "DDoS1",
                        DDoS2 : "DDoS2",
                        SS1   : "SS1",
                        SS2   : "SS2"
                   }

class Snippet:
    def __init__(self, nf_code, arity):
        self.nf_code = nf_code
        self.lines = snippet_map[nf_code].split()
        self.code_length = 0
        for line in self.lines:
            if not line.isspace():
                self.code_length += 1
        self.arity = arity
