#!/usr/bin/env python3

# import sys

import cgp
import netsim

def main():
    # if len(sys.argv) == 1:
    #     emu = emulator.Emulator(10, "ddos.csv")
    # else:

    cg_sim = netsim.CGPSimulator(10)
    cg_sim.evolve_generations(10)
    cg_sim.print_fittest_phenotype()


if __name__ == '__main__':
    main()
