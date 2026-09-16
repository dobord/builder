"""Never render exception details on a public release runner."""
import sys
import os
from pathlib import Path
from . import tasks, publish

COMMANDS = {"request": tasks.request, "prepare": tasks.prepare, "build": tasks.build,
            "diagnostics": tasks.diagnostics, "cleanup": tasks.cleanup,
            "notify": publish.notify, "verify": publish.verify_result, "publish": publish.publish_release}


def main():
    try:
        if len(sys.argv) != 2 or sys.argv[1] not in COMMANDS:
            raise ValueError("invalid operation")
        temporary = Path(os.environ["RUNNER_TEMP"])
        defaults = {"CIPHER_DIR": temporary / ("cipher-input" if sys.argv[1] == "prepare" else "cipher-output"),
                    "INPUT_FILE": temporary / "cipher-input/input.enc",
                    "DIAGNOSTIC_DIR": temporary / "cipher-diagnostics",
                    "STAGING_DIR": temporary / "verified-release"}
        for name, value in defaults.items():
            os.environ.setdefault(name, str(value))
        COMMANDS[sys.argv[1]]()
    except Exception:
        print("::error::Encrypted release operation failed. Private details were withheld.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
