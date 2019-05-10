#!/usr/bin/env python3

import cgp
import netsim


def main():
    cg_sim = netsim.CGPSimulator(10)
    cg_sim.evolve_generations(20)
    cg_sim.print_fittest_phenotype()


if __name__ == '__main__':
    main()
