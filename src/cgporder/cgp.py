#!/usr/bin/env python3

"""
Cartesian genetic programming
"""
import operator as op
import random
import copy
import math

import p4sim
import snippet as sn

VERBOSE = False
MAX_ARITY = 1

CLEN_PENALTY_MULT = 5

# parameters of cartesian genetic programming
# MUT_PB = 0.015  # mutate probability
MUT_PB = 0.03

N_COLS = 500   # number of cols (nodes) in a single-row CGP
LEVEL_BACK = 500  # how many levels back are allowed for inputs in CGP

# parameters of evolutionary strategy: MU+LAMBDA
MU = 2
LAMBDA = 8
N_GEN = 100  # max number of generations

def to_str(el):
    if isinstance(el, int):
        if el >= 0:
            return f"var{str(el)}"
        else:
            return f"in{str(-el - 1)}"
    else:
        return "*"


class Function:
    """
    A general function
    """
    def __init__(self, f, arity):
        self.f = f
        self.arity = arity

    def __call__(self, *args, **kwargs):
        return self.f(*args, **kwargs)


class Node:
    """
    A node in CGP graph
    """
    def __init__(self, max_arity):
        """
        Initialize this node randomly
        """
        self.i_func = None
        self.i_inputs = [None] * max_arity
        self.i_output = None
        self.output = None
        self.active = False


class Phenotype:
    """
    A phenotype (chromosome, genotype, etc.) in evolution
    """
    function_set = None
    max_arity = MAX_ARITY
    n_inputs = 1
    n_outputs = 1
    n_cols = N_COLS
    level_back = LEVEL_BACK

    def __init__(self, packets, intent):
        self.nodes = []
        self.node_names = []
        j = 0
        for pos in range(self.n_cols):
            self.nodes.append(self._create_random_node(pos))
            self.node_names.append(f"var{j}")
            j += 1
        k = self.n_outputs
        for i in range(1, self.n_outputs + 1):
            self.nodes[-i].active = True
            self.node_names[-i] = f"out{k-1}"
            k -= 1
        self.fitness = None
        self._active_determined = False
        self.packets = packets
        self.intent = intent

    def __str__(self):
        sn_codes = []
        if not self._active_determined:
            self._determine_active_nodes()
            self._active_determined = True
        # forward pass: evaluate

        for node in self.nodes:
            if node.active:
                nf_code = fs[node.i_func].nf_code
                sn_codes.append(sn.snippet_code_txt[nf_code])
        series = ", ".join(sn_codes)

        return f"({series})"

    def set_fitness(self, fitness_value: int) -> None:
        self.fitness = fitness_value

    def _create_random_node(self, pos):
        node = Node(self.max_arity)
        node.i_func = random.randint(0, len(self.function_set) - 1)
        for i in range(self.function_set[node.i_func].arity):
            node.i_inputs[i] = random.randint(max(pos - self.level_back,
                                                  -self.n_inputs), pos - 1)
        node.i_output = pos

        return node

    def _determine_active_nodes(self):
        """
        Determine which nodes in the CGP graph are active
        """
        # check each node in reverse order
        n_active = 0
        for node in reversed(self.nodes):
            if node.active:
                n_active += 1
                for i in range(self.function_set[node.i_func].arity):
                    i_input = node.i_inputs[i]
                    if i_input >= 0:  # a node (not an input)
                        self.nodes[i_input].active = True
        if VERBOSE:
            print("# active genes: ", n_active)

    def eval(self, *args):
        """
        Given inputs, evaluate the output of this CGP phenotype.
        :return the final output value
        """
        fitness_value = 0

        if not self._active_determined:
            self._determine_active_nodes()
            self._active_determined = True

        imach = p4sim.IntentMachine(self.intent)
        # should be read directly from intent
        imach.add_network_function(p4sim.NetworkFunction(p4sim.HH, ">", 20))
        imach.add_network_function(p4sim.NetworkFunction(p4sim.DDoS, ">", 5))
        imach.add_network_function(p4sim.NetworkFunction(p4sim.SS, ">", 5))

        snippets = []
        for node in self.nodes:
            if node.active:
                snippets.append(fs[node.i_func])
                fitness_value -= CLEN_PENALTY_MULT*(fs[node.i_func].code_length)
        sim = p4sim.SwitchSimulator(snippets)

        for pkt in self.packets:
            if sim.get_action(pkt) == imach.get_action(pkt):
                fitness_value += 1

        return fitness_value

        # forward pass: evaluate
                # inputs = []
                # for i in range(self.function_set[node.i_func].arity):
                #     i_input = node.i_inputs[i]
                #     if i_input < 0:
                #         inputs.append(args[-i_input - 1])
                #     else:
                #         inputs.append(self.nodes[i_input].output)
                # node.output = self.function_set[node.i_func](*inputs)

        # return self.nodes[-self.n_outputs:].output
        # return [node.output for node in self.nodes[-self.n_outputs:]]

    def mutate(self, mut_rate=0.01):
        """
        Mutate this phenotype. Each gene is varied with probability *mut_rate*.
        :param mut_rate: mutation probability
        :return a child after mutation
        """
        child = copy.deepcopy(self)
        for pos, node in enumerate(child.nodes):
            # mutate the function gene
            if random.random() < mut_rate:
                node.i_func = random.choice(range(len(self.function_set)))
            # mutate the input genes (connection genes)
            arity = self.function_set[node.i_func].arity
            for i in range(arity):
                if node.i_inputs[i] is None or random.random() < mut_rate:
                    node.i_inputs[i] = random.randint(max(pos - self.level_back,
                                                      -self.n_inputs), pos - 1)
            # initially an phenotype is not active except hte last output node
            node.active = False
        for i in range(1, self.n_outputs + 1):
            child.nodes[-i].active = True
        child.fitness = None
        child._active_determined = False
        return child


# function set
def protected_div(a, b):
    if abs(b) < 1e-6:
        return a
    return a / b


def protected_mod(a, b):
    if abs(b) < 1e-6:
        return a
    return a % b


def _and(a, b):
    return a > 0 and b > 0


def _or(a, b):
    return a > 0 or b > 0


def _not(a):
    return not a > 0


def square(a):
    return a ** 2


def sqrt(a):
    return math.sqrt(abs(a))


def relu(a):
    return max(0, a)


def neg(a):
    return 0 - a


def hash32(a:int, b:int) -> int:
    return hash((a, b)) % 32


# fs = [
#         Function(op.add, 2),
#         Function(op.sub, 2),
#         Function(op.mul, 2),
#         Function(protected_mod, 2),
#         Function(hash32, 2),
#     ]
fs = [
        sn.Snippet(sn.HH1, 1),
        sn.Snippet(sn.HH2, 1),
        sn.Snippet(sn.DDoS1, 1),
        sn.Snippet(sn.DDoS2, 1),
        sn.Snippet(sn.SS1, 1),
        sn.Snippet(sn.SS2, 1),
     ]
Phenotype.function_set = fs
Phenotype.max_arity = max(f.arity for f in fs)


def evolve(pop, mut_rate, mu, lambda_):
    """
    Evolve the population *pop* using the mu + lambda evolutionary strategy

    :param pop: a list of phenotypes, whose size is mu + lambda.
                The first mu ones are previous parents.
    :param mut_rate: mutation rate
    :return: a new generation of phenotypes of the same size
    """
    pop = sorted(pop, key=lambda ind: ind.fitness)  # stable sorting
    parents = pop[-mu:]
    fit = [str(ind.fitness) for ind in parents]
    print("  Next generation parents: " + ", ".join(fit))
    # generate lambda new children via mutation
    offspring = []
    for _ in range(lambda_):
        parent = random.choice(parents)
        offspring.append(parent.mutate(mut_rate))
    return parents + offspring


def create_phenotypes(n, packets, intent):
    """
    Create a random population composed of n phenotypes.
    """
    return [Phenotype(packets, intent) for _ in range(n)]


class CGPSimulator:
    def __init__(self, n_phenotypes: int) -> None:
        self.packets = p4sim.PacketGenerator().generate(10000)
        self.phenotypes = create_phenotypes(n_phenotypes,
                                                self.packets,
                                                "blabla")

    def evaluate_generation(self) -> None:
        for ind in self.phenotypes:
            fitness_value = ind.eval(77)
            ind.set_fitness(fitness_value)

    def evolve_generations(self, n_generations: int) -> None:
        for gen_idx in range(n_generations):
            self.evaluate_generation()

            f_vals = [ind.fitness for ind in self.phenotypes]
            print(f"Gen {gen_idx+1}: {f_vals}")

            self.phenotypes = evolve(self.phenotypes,
                                     MUT_PB,
                                     MU,
                                     LAMBDA)

        # evaluate for the last time
        self.evaluate_generation()

    def print_fittest_phenotype(self):
        inds = sorted(self.phenotypes, key=lambda ind: ind.fitness)
        fittest_phenotype = inds[-1]

        print("\nFinal P4 code (fitness value "
                f"f={fittest_phenotype.fitness}):\n")
        print(fittest_phenotype)
        print()
