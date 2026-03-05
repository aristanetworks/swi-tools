# Copyright (c) 2026 Arista Networks, Inc.
# Use of this source code is governed by the Apache License 2.0
# that can be found in the LICENSE file.
# ------------------------------------------------------------------------------
#  Maintainers:
#    alejandros@arista.com
#    abio@arista.com
#
#  Description:
#
#  Tags:
#
# ------------------------------------------------------------------------------

import logging
from pathlib import Path
from typing import List

import typer

logger = logging.getLogger(__name__)


def version(value: bool) -> None:
    logger.debug(f"callback.version: {value}")
    if value:
        from switools import __app_name__, __version__
        typer.echo(f"{__app_name__} v{__version__}")
        raise typer.Exit()


def verbosity(param: typer.CallbackParam, value: bool) -> None:
    logger.debug(f"callback.verbosity: {value}")
    if value:
        if param.name == "verbose" and logger.parent.level > logging.INFO:
            logger.parent.setLevel(logging.INFO)
        if param.name == "very_verbose" and logger.parent.level > logging.DEBUG:
            logger.parent.setLevel(logging.DEBUG)


def path_exists(value: Path | List[Path]) -> Path | List[Path]:
    logger.debug(f"callback.path_exists: {value}")
    if bool(value):
        if type(value) is Path and not value.exists():
            raise typer.BadParameter(f"Path '{value}' does not exist")
        if type(value) is list:
            for v in value:
                if not v.exists():
                    raise typer.BadParameter(f"Path '{v}' does not exist")
    return value


def parent_path_exists(value: Path | List[Path]) -> Path | List[Path]:
    logger.debug(f"callback.parent_path_exists: {value}")
    if bool(value):
        if type(value) is Path and not value.parent.exists():
            raise typer.BadParameter(f"Path '{value.parent}' does not exist")
        if type(value) is list:
            for v in value:
                if not v.parent.exists():
                    raise typer.BadParameter(f"Path '{v.parent}' does not exist")
    return value
