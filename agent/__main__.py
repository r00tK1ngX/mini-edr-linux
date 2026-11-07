"""CLI executable entry point for Mini EDR Linux Agent.

Allows running the agent with:
    python3 -m agent [args]
"""

from agent.main import main

if __name__ == "__main__":
    main()
