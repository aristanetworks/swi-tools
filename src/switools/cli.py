# ------------------------------------------------------------------------------
#  Arista Networks, Inc. Confidential and Proprietary.
#  Copyright (c) 2025 Arista Networks, Inc. All rights reserved.
# ------------------------------------------------------------------------------
#  Maintainers:
#    alejandros@arista.com
#    creid@arista.com
#
#  Description:
#
#  Tags:
#
# ------------------------------------------------------------------------------

import logging
from typing import Annotated, Optional
from switools.callbacks import _version_callback
from switools.create import app as create_app
from switools.crc32collision import app as collision_app
from switools.signature import app as signature_app
from switools.verify import app as verify_app

import typer

# Initialise logging
logger = logging.getLogger(__name__)

app = typer.Typer(add_completion=False)

@app.callback()
def main(
    version: Annotated[
        Optional[bool],
        typer.Option(
            "--version",
            "-v",
            help="Show the application's version and exit.",
            callback=_version_callback,
            is_eager=True,
        ),
    ] = None,
) -> None:
    return

app.add_typer(create_app)
app.add_typer(collision_app)
app.add_typer(signature_app)
app.add_typer(verify_app)
