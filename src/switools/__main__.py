# Copyright (c) 2026 Arista Networks, Inc.
# Use of this source code is governed by the Apache License 2.0
# that can be found in the LICENSE file.
# ------------------------------------------------------------------------------
#  Maintainers:
#    abio@arista.com
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
    cli.app( prog_name=__app_name__ )

if __name__ == "__main__":
    main()
