"""``python -m hydra.swarm`` → role-aware distributed swarm node.

Thin shim so the package is runnable as a module; all logic lives in
``hydra.swarm.node``. See that module's docstring for the role model
(coordinator | worker | all) and the fail-closed scope doctrine.
"""

from hydra.swarm.node import main

if __name__ == "__main__":
    main()
