#!/usr/bin/env python3

import cgp


def main():
    cg_sim = cgp.CGPSimulator(10)
    cg_sim.evolve_generations(100)
    cg_sim.print_fittest_phenotype()


if __name__ == '__main__':
    main()
