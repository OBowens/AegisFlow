"""PyInstaller entry point for aegis-agent.exe.

Kept dead simple: route the SCM's '--as-service' launch to the service
dispatcher, and everything else to the normal CLI.
"""

import sys


def _main() -> int:
    argv = sys.argv[1:]
    if argv and argv[0] == "--as-service":
        from aegis_agent.winservice import run_as_service

        run_as_service()
        return 0
    from aegis_agent.cli import main

    return main(argv)


if __name__ == "__main__":
    sys.exit(_main())
