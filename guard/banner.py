import os
import sys

ART = r"""    _    _     ____  _   _  ___
   / \  | |   |  _ \| | | |( _ )
  / _ \ | |   | |_) | | | |/ _ \
 / ___ \| |___|  _ <| |_| | (_) |
/_/   \_\_____|_| \_\\___/ \___/"""


def show(mode):
    color = sys.stdout.isatty() and "NO_COLOR" not in os.environ and os.environ.get("TERM") != "dumb"
    shades = ["\033[38;5;51m", "\033[38;5;45m", "\033[38;5;81m", "\033[38;5;141m", "\033[38;5;177m"]
    print()
    for i, line in enumerate(ART.splitlines()):
        print((shades[i] if color else "") + line + ("\033[0m" if color else ""))
    print(f"\n  ALRU8 | NETWORK GUARD | {mode}\n", flush=True)
