"""Never render exception details on a public release runner."""
import sys
import os
from pathlib import Path
import traceback
from . import tasks, publish, process

COMMANDS = {"request": tasks.request, "prepare": tasks.prepare, "build": tasks.build,
            "diagnostics": tasks.diagnostics, "cleanup": tasks.cleanup,
            "notify": publish.notify, "verify": publish.verify_result, "publish": publish.publish_release}


def main():
    command = sys.argv[1] if len(sys.argv) == 2 else ""
    try:
        if command not in COMMANDS:
            raise ValueError("invalid operation")
        temporary = Path(os.environ["RUNNER_TEMP"])
        defaults = {"CIPHER_DIR": temporary / ("cipher-input" if command == "prepare" else "cipher-output"),
                    "INPUT_FILE": temporary / "cipher-input/input.enc",
                    "DIAGNOSTIC_DIR": temporary / "cipher-diagnostics",
                    "STAGING_DIR": temporary / "verified-release"}
        for name, value in defaults.items():
            os.environ.setdefault(name, str(value))
        COMMANDS[command]()
    except Exception as error:
        # Only the non-credentialed build operation contributes to encrypted diagnostics.
        # Never append request/prepare exceptions, environment dumps or source-fetch logs.
        if command == "build":
            try:
                with (tasks.work() / "build.log").open("a", encoding="utf-8") as log:
                    log.write("\nPRIVATE_DRIVER_EXCEPTION\n" + traceback.format_exc())
            except Exception:
                pass
        if isinstance(error, process.StageFailure):
            print(f"::error::Release stage={error.stage}; category={error.kind}. Details remain encrypted.", file=sys.stderr)
        else:
            print("::error::Encrypted release operation failed. Private details were withheld.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
