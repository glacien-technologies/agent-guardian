# Strategies

**TL;DR** — Multi-turn attack state machines. Each strategy is bound to one attack conversation: the caller appends turns to a history and feeds the target's latest response back in; the strategy emits either a `NextPrompt` or `StrategyDone`. Strategies are idempotent given `(history, target_response, rng-seed)` — no clock, no network beyond the injected attacker LLM.

The four strategies bundled in v1.0 are PAIR, TAP, Crescendo, and MAD-MAX. The first three implement published academic attacks; MAD-MAX is a mixture-of-strategies meta-strategy. For the conceptual tour and when to pick which, see [The swarm](../../concepts/swarm.md).

## Base types

`Turn`, `NextPrompt`, `StrategyDone`, `StrategyContext`, and the abstract `Strategy` class.

::: agent_guardian.strategies.base
    options:
      show_root_heading: false
      members:
        - Strategy
        - StrategyContext
        - Turn
        - NextPrompt
        - StrategyDone
        - StrategyResult

`StrategyResult` is the type alias `NextPrompt | StrategyDone` — every `generate_next()` returns one of these two.

## PAIR — Prompt Automatic Iterative Refinement

The attacker LLM critiques its own previous attempt against the target's response, then rewrites the attack to be more effective. We keep a "best attempt so far" pointer in case the agent layer wants to return to the best critique state. Every attacker call is wrapped in `attacker_complete()` so the provider's safety alignment sees a sanctioned-research framing.

> **Reference:** Chao, P. *et al.* *Jailbreaking Black Box Large Language Models in Twenty Queries.* arXiv [2310.08419](https://arxiv.org/abs/2310.08419), 2023.

::: agent_guardian.strategies.pair
    options:
      show_root_heading: false
      members:
        - PAIRStrategy

## TAP — Tree of Attacks with Pruning

Tree-search jailbreak with branching factor `b`, width `w`, depth `d`, and on-topic pruning by an evaluator-LLM score. The strategy-layer implementation is single-branch greedy descent with internal branching done by the attacker LLM in one call (the agent layer owns global tree scheduling); each `generate_next()` asks the attacker for `branching_factor` refinements, scores them, and picks the highest-scored survivor.

> **Reference:** Mehrotra, A. *et al.* *Tree of Attacks: Jailbreaking Black-Box LLMs Automatically.* arXiv [2312.02119](https://arxiv.org/abs/2312.02119), 2024.

::: agent_guardian.strategies.tap
    options:
      show_root_heading: false
      members:
        - TAPStrategy

## Crescendo — multi-turn benign-to-malicious escalation

Start benign on the *same topic* as the malicious goal, then gradually escalate. The escalation level (0..100) increments by `escalation_step` each turn unless a refusal is observed, in which case it drops by twice the step. Two refusals at level 0 mean we've hit a stable refusal loop; the strategy rotates to the next seed and, after `_MAX_SEED_RESTARTS`, bows out.

> **Reference:** Russinovich, M. *et al.* *Crescendo: A Multi-Turn LLM Jailbreaking Attack.* arXiv [2404.01833](https://arxiv.org/abs/2404.01833), 2024.

::: agent_guardian.strategies.crescendo
    options:
      show_root_heading: false
      members:
        - CrescendoStrategy

## MAD-MAX — Modular Adversarial Diversity

Mixture-of-strategies wrapper. Each call computes each surviving child's rolling success rate, picks one via epsilon-greedy bandit (random with probability `epsilon`, else argmax of success rate with `rng.choice` tiebreak), delegates `generate_next()` to it, and removes children that emit `StrategyDone`. When the pool empties, MAD-MAX itself stops.

> **Reference:** Schoepf, S. *et al.* *MAD-MAX: Modular Adversarial Diversity for Multi-Attacker Jailbreaking.* arXiv [2503.06253](https://arxiv.org/abs/2503.06253), 2025.

::: agent_guardian.strategies.mad_max
    options:
      show_root_heading: false
      members:
        - MadMaxStrategy
