#!/usr/bin/env python3

import cgp


def main():
    cg_sim = cgp.DNCCGPSimulator(40)
    cg_sim.evolve_generations(200)
    cg_sim.print_fittest_phenotype()


if __name__ == '__main__':
    main()
