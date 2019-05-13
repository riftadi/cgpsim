#!/usr/bin/env python3

"""
Cartesian genetic programming
"""
import operator as op
import random
import copy
import math
import json

VERBOSE = False
MAX_ARITY = 2

# parameters of cartesian genetic programming
# MUT_PB = 0.015  # mutate probability
MUT_PB = 0.03

N_COLS = 500   # number of cols (nodes) in a single-row CGP
LEVEL_BACK = 500  # how many levels back are allowed for inputs in CGP

# parameters of evolutionary strategy: MU+LAMBDA
MU = 2
LAMBDA = 8
N_GEN = 1000  # max number of generations

def to_str(el):
    if isinstance(el, int):
        if el >= 0:
            return f"var{str(el)}"
        else:
            return f"in{str(-el - 1)}"
    else:
        return "*"

# Primitives
# if_equal(a, b)
# else_if_equal(a, b)
# endif
# assign(a, b)

# primitive code (pcode)
PRI_IFEQ      = 0
PRI_ENDIF     = 1
PRI_ASSIGN    = 2

PCODE_TXT = {
                PRI_IFEQ : "if_equal",
                PRI_ENDIF : "endif",
                PRI_ASSIGN : "assign",
}

INPUT_TXT = {
                0 : "input_port",
                1 : "src_ip",
                2 : "dst_ip",
                3 : "nat_src_inside_ip",
                4 : "nat_src_outside_ip",
                5 : "nat_port_num_inside",
                6 : "nat_port_num_outside",
}

EXTRA_INPUTS = {
                    "nat_src_inside_ip"    : 100,
                    "nat_src_outside_ip"   : 111,
                    "nat_port_num_inside"  : 0,
                    "nat_port_num_outside" : 1,
               }

class Primitive:
    """
    A general primitive
    """
    def __init__(self, pcode, arity):
        self.pcode = pcode
        self.arity = arity


class ExamElement:
    def __init__(self, src_ip, dst_ip):
        self.src_ip = src_ip
        self.dst_ip = dst_ip


class ExamInput(ExamElement):
    def __init__(self, port_num, src_ip, dst_ip):
        super().__init__(src_ip, dst_ip)
        self.port_num = port_num


class ExamOutput(ExamElement):
    def __init__(self, src_ip, dst_ip):
        super().__init__(src_ip, dst_ip)

    def __eq__(self, other):
        return (
                    self.src_ip == other.src_ip and
                    self.dst_ip == other.dst_ip
               )

class ExamplesManager:
    def __init__(self, fname):
        self.example_pairs = []
        with open(fname, 'r') as fh:
            exams = json.load(fh)["examples"]
        for exam in exams:
            i1, i2, i3, o1, o2 = exam
            self.example_pairs.append(
                                        (
                                            ExamInput(i1, i2, i3),
                                            ExamOutput(o1, o2)
                                        )
                                     )


class SwitchSimulator:
    def __init__(self, nodes):
        self.nodes = nodes
        self.primitives = [ps[node.i_pri] for node in nodes]

    def passed_if_analysis(self):
        passed = True

        level = 0
        for prim in self.primitives:
            if prim.pcode == PRI_IFEQ:
                level += 1
            elif prim.pcode == PRI_ENDIF:
                if level == 0:
                    passed = False
                    break
                else:
                    level -= 1

        if level != 0:
            passed = False

        return passed

    def get_output(self, exam_in):
        input_port = exam_in.port_num
        src_ip = exam_in.src_ip
        dst_ip = exam_in.dst_ip
        nat_src_inside_ip = EXTRA_INPUTS["nat_src_inside_ip"]
        nat_src_outside_ip = EXTRA_INPUTS["nat_src_outside_ip"]
        nat_port_num_inside = EXTRA_INPUTS["nat_port_num_inside"]
        nat_port_num_outside = EXTRA_INPUTS["nat_port_num_outside"]

        # acts as a register
        value_map = {
            0 : input_port,
            1 : src_ip,
            2 : dst_ip,
            3 : nat_src_inside_ip,
            4 : nat_src_outside_ip,
            5 : nat_port_num_inside,
            6 : nat_port_num_outside
        }

        iter = 0
        while iter < len(self.nodes):
            if self.primitives[iter].pcode == PRI_ASSIGN:
                lidx = self.nodes[iter].i_inputs[0]
                ridx = self.nodes[iter].i_inputs[1]
                value_map[lidx] = value_map[ridx]
            elif self.primitives[iter].pcode == PRI_IFEQ:
                lidx = self.nodes[iter].i_inputs[0]
                ridx = self.nodes[iter].i_inputs[1]
                if value_map[lidx] != value_map[ridx]:
                    # if the condition is not met
                    level = 0
                    iter += 1
                    while self.primitives[iter].pcode != PRI_ENDIF or level != 0:
                        if self.primitives[iter].pcode == PRI_IFEQ:
                            level += 1
                        elif level > 0 and self.primitives[iter].pcode == PRI_ENDIF:
                            level -= 1
                        iter += 1
            if iter < len(self.nodes):
                iter += 1

        return ExamOutput(value_map[1], value_map[2])


class Node:
    """
    A node in CGP graph
    """
    def __init__(self, max_arity):
        """
        Initialize this node randomly
        """
        self.i_pri = None
        self.i_inputs = [None] * max_arity
        self.i_output = None
        self.output = None
        self.active = False


class Phenotype:
    """
    A phenotype (chromosome, genotype, etc.) in evolution
    """
    primitive_set = None
    max_arity = MAX_ARITY
    n_inputs = 7
    n_outputs = 1
    n_cols = N_COLS
    level_back = LEVEL_BACK

    def __init__(self, exam_mgr):
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
        self.exam_mgr = exam_mgr

    def __str__(self):
        pr_codes = []
        if not self._active_determined:
            self._determine_active_nodes()
            self._active_determined = True
        # forward pass: evaluate

        for node in self.nodes:
            if node.active:
                prim = ps[node.i_pri]
                pcode = prim.pcode
                params = []
                for idx in range(prim.arity):
                    params.append(INPUT_TXT[node.i_inputs[idx]])
                param_txt = ", ".join(params)
                pr_codes.append(f"{PCODE_TXT[pcode]}({param_txt})")
        series = "\n".join(pr_codes)

        return series

    def set_fitness(self, fitness_value: int) -> None:
        self.fitness = fitness_value

    def _create_random_node(self, pos):
        node = Node(self.max_arity)
        node.i_pri = random.randint(0, len(self.primitive_set) - 1)
        for i in range(self.primitive_set[node.i_pri].arity):
            node.i_inputs[i] = random.randint(0, self.n_inputs - 1)
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
                for i in range(self.primitive_set[node.i_pri].arity):
                    i_input = node.i_inputs[i]
                    if i_input >= 0:  # a node (not an input)
                        self.nodes[i_input].active = True
        if VERBOSE:
            print("# active genes: ", n_active)

    def eval(self):
        """
        Evaluate the output of this CGP phenotype.
        :return the final output value
        """
        fitness_value = 0

        if not self._active_determined:
            self._determine_active_nodes()
            self._active_determined = True

        nodes = []
        for node in self.nodes:
            if node.active:
                nodes.append(node)

        sim = SwitchSimulator(nodes)

        if not sim.passed_if_analysis():
            return -9

        for ex_pair in self.exam_mgr.example_pairs:
            ex_in, ex_out = ex_pair
            if sim.get_output(ex_in) == ex_out:
                fitness_value += 10

        return fitness_value

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
                node.i_pri = random.choice(range(len(self.primitive_set)))
            # mutate the input genes (connection genes)
            arity = self.primitive_set[node.i_pri].arity
            for i in range(arity):
                if node.i_inputs[i] is None or random.random() < mut_rate:
                    node.i_inputs[i] = random.randint(0, self.n_inputs - 1)
            # initially an phenotype is not active except hte last output node
            node.active = False
        for i in range(1, self.n_outputs + 1):
            child.nodes[-i].active = True
        child.fitness = None
        child._active_determined = False
        return child

ps = [
        Primitive(PRI_IFEQ,     2),
        Primitive(PRI_ENDIF,    0),
        Primitive(PRI_ASSIGN,   2),
    ]
Phenotype.primitive_set = ps
Phenotype.max_arity = max(p.arity for p in ps)


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


def create_phenotypes(n, exam_mgr):
    """
    Create a random population composed of n phenotypes.
    """
    return [Phenotype(exam_mgr) for _ in range(n)]


class CGPSimulator:
    def __init__(self, n_phenotypes: int,
                 exam_fname: str = "examples.json") -> None:
        self.exam_mgr = ExamplesManager(exam_fname)
        self.phenotypes = create_phenotypes(n_phenotypes, self.exam_mgr)


    def evaluate_generation(self) -> None:
        for ind in self.phenotypes:
            fitness_value = ind.eval()
            ind.set_fitness(fitness_value)

    def evolve_generations(self, n_generations: int) -> None:
        for gen_idx in range(n_generations):
            self.evaluate_generation()

            f_vals = [ind.fitness for ind in self.phenotypes]
            print(f"Gen {gen_idx+1}: {f_vals}")

            # evolve if not the last generation
            if gen_idx < (n_generations - 1):
                self.phenotypes = evolve(self.phenotypes,
                                         MUT_PB,
                                         MU,
                                         LAMBDA)


    def print_fittest_phenotype(self):
        inds = sorted(self.phenotypes, key=lambda ind: ind.fitness)
        fittest_phenotype = inds[-1]

        print("\nFinal P4 code (fitness value "
                f"f={fittest_phenotype.fitness}):\n")
        print(fittest_phenotype)
        print()
