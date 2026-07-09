# File: learning/genetic_engine.py
import random
import string

class GeneticPasswordEngine:
    """
    Experimental engine that evolves password candidates based on successful patterns
    """
    def __init__(self, population_size=100, mutation_rate=0.1):
        self.population_size = population_size
        self.mutation_rate = mutation_rate
        self.population = []

    def initialize_population(self, seed_patterns=None):
        """Initialize population with random or seed patterns"""
        if seed_patterns:
            self.population = [self._mutate(random.choice(seed_patterns)) for _ in range(self.population_size)]
        else:
            self.population = [self._generate_random_candidate() for _ in range(self.population_size)]

    def _generate_random_candidate(self, length=8):
        chars = string.ascii_letters + string.digits
        return "".join(random.choice(chars) for _ in range(length))

    def _mutate(self, candidate):
        """Apply random mutations to a candidate"""
        if random.random() > self.mutation_rate:
            return candidate
            
        candidate_list = list(candidate)
        idx = random.randint(0, len(candidate_list) - 1)
        candidate_list[idx] = random.choice(string.ascii_letters + string.digits + "!@#$%")
        return "".join(candidate_list)

    def evolve(self, fitness_scores):
        """
        Evolve the population to the next generation
        fitness_scores: list of (candidate, score)
        """
        # Sort by score descending
        fitness_scores.sort(key=lambda x: x[1], reverse=True)
        
        # Select elite (top 10%)
        elite_count = max(1, self.population_size // 10)
        new_population = [c for c, s in fitness_scores[:elite_count]]
        
        # Fill remaining with offspring
        while len(new_population) < self.population_size:
            parent1 = self._weighted_choice(fitness_scores)
            parent2 = self._weighted_choice(fitness_scores)
            child = self._crossover(parent1, parent2)
            new_population.append(self._mutate(child))
            
        self.population = new_population
        return self.population

    def _crossover(self, p1, p2):
        """Combine two parents to create a child"""
        split = random.randint(1, min(len(p1), len(p2)) - 1)
        return p1[:split] + p2[split:]

    def _weighted_choice(self, fitness_scores):
        """Pick a candidate based on fitness score weight"""
        total_fitness = sum(s for c, s in fitness_scores)
        if total_fitness == 0:
            return random.choice(fitness_scores)[0]
            
        pick = random.uniform(0, total_fitness)
        current = 0
        for candidate, score in fitness_scores:
            current += score
            if current > pick:
                return candidate
        return fitness_scores[0][0]
