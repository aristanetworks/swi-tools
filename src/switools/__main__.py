# ------------------------------------------------------------------------------
#  Arista Networks, Inc. Confidential and Proprietary.
#  Copyright (c) 2025 Arista Networks, Inc. All rights reserved.
# ------------------------------------------------------------------------------
#  Maintainers:
#    creid@arista.com
#
#  Description:
#
#  Tags:
#
# ------------------------------------------------------------------------------

import logging

from switools import __app_name__, cli

# Initialise logging
logger = logging.getLogger(__name__)


def main():
    _channel = logging.StreamHandler()
    _formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(name)s:%(lineno)d - %(message)s")
    _channel.setFormatter(_formatter)
    logging.basicConfig(level=logging.WARNING, handlers=[_channel])
    cli.app(prog_name=__app_name__)


if __name__ == "__main__":
    main()
