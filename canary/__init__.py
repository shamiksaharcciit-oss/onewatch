"""canary — change evidence for LLM/RAG systems.

The package follows the ratified five-component run loop. Each subpackage lands in its
chartered phase rather than being stubbed out early:

    suite/      C2  BUILT  the frozen, versioned probe set -- the instrument itself
    target/     C2  BUILT  the probed system: the interface, and the deterministic mock
    freezer/    C2  BUILT  E10-verbatim freezing of responses; seals each run as E_t
    detector/   C3  --     the pure, float-free comparison v = I(E_baseline, E_t)
    baseline/   C3  --     declared, content-addressed baselines; audited rebaselining
    receipt/    C3  --     the rederivable-manifest v3 envelope, ledger, Merkle anchor

Empty packages are not created ahead of their phase. A directory that exists but does
nothing reads, to anyone opening the tree, as a component that exists and does nothing
-- and this programme's whole claim is that its artifacts do not overstate themselves.

`acj` and `quantise` sit at the top level because both disciplines cut across every
component: ACJ canonicalisation for everything GENERATED, and E006's single quantisation
boundary between measurement and everything downstream of it.

WHAT THIS TOOL CLAIMS, AND WHAT IT DOES NOT
-------------------------------------------
It says **that** behaviour changed and **where behaviourally**. It does not say
**which stage** caused it: the canary observes an endpoint from outside, and stage
attribution is the forensics pillar's job. That boundary is a design commitment, not a
current limitation to be engineered away later.
"""

__all__ = ["__version__"]

#: 0.0.0 until something is released. The version is not a progress bar.
__version__ = "0.0.0"
