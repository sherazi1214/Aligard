"""Worker CLI: python -m backend.app.worker [--once] [--force]."""
import argparse
import json

from backend.app.config import get_settings
from backend.app.logging_config import configure_logging
from backend.app.observability import init_sentry
from backend.app.worker.scheduler import run_forever, run_once


def main() -> None:
    parser = argparse.ArgumentParser(description="AliGuard background email scanner")
    parser.add_argument("--once", action="store_true", help="Due accounts ko aik dafa scan karke exit karein")
    parser.add_argument("--force", action="store_true", help="--once ke sath next_run_at ko ignore karein")
    args = parser.parse_args()
    settings = get_settings()
    configure_logging(settings.log_level, settings.effective_log_format)
    init_sentry(settings, "worker")
    if args.force and not args.once:
        parser.error("--force sirf --once ke sath use karein")
    if args.once:
        print(json.dumps(run_once(force=args.force), indent=2, default=str))
    else:
        run_forever()


if __name__ == "__main__":
    main()
