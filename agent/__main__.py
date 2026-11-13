"""CLI for the dedicated SingBox Panel agent service."""
import argparse
import logging
import os
import sys

from . import __version__


def main():
    parser = argparse.ArgumentParser(prog='sing-panel-agent')
    parser.add_argument('--version', action='version', version=__version__)
    commands = parser.add_subparsers(dest='command', required=True)
    service = commands.add_parser('run')
    service.add_argument('--config', default='/var/lib/sing-panel-agent/config.json')
    join = commands.add_parser('enroll')
    join.add_argument('--config', default='/var/lib/sing-panel-agent/config.json')
    join.add_argument('--panel', required=True)
    join.add_argument('--token-stdin', action='store_true', required=True)
    join.add_argument('--binary', default='/opt/sing-panel-agent/sing-box')
    join.add_argument('--stats-port', type=int, default=19190)
    join.add_argument('--install-dir', default='/opt/sing-panel-agent')
    join.add_argument('--allow-insecure-local', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    os.umask(0o077)
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
    try:
        from .client import enroll, run
        if args.command == 'enroll':
            token = sys.stdin.read(512).strip()
            identity = enroll(args.config, args.panel, token, args.binary, args.stats_port,
                              args.allow_insecure_local, args.install_dir)
            print('Agent 已接入，服务器 ID：' + identity)
        else:
            run(args.config)
    except (ValueError, OSError) as error:
        print('Agent: ' + str(error), file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == '__main__':
    main()
