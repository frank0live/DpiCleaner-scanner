"""Entry points.

``python -m dpicleaner`` with **no arguments** opens the GUI; any argument
(``ip``/``sni``/``reality``/``-V``/``--help``) goes to the headless CLI.
The installed ``dpicleaner`` console script behaves the same way.
"""

import sys


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        from .ui.app import run
        run()
        return 0
    from .cli import main as cli_main
    return cli_main(argv)


if __name__ == "__main__":
    sys.exit(main())
