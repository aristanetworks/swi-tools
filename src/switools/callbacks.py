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
from pathlib import Path
from typing import List

import typer

# Initialise logging
logger = logging.getLogger(__name__)


def _version_callback(value: bool) -> None:
    logger.debug(f"_version_callback: {value}")
    if value:
        from switools import __app_name__, __version__
        typer.echo(f"{__app_name__} v{__version__}")
        raise typer.Exit()


def _verbosity_callback(param: typer.CallbackParam, value: bool) -> None:
    logger.debug(f"_verbosity_callback: {value}")
    if value:
        if param.name == "verbose" and logger.parent.level > logging.INFO:
            logger.parent.setLevel(logging.INFO)
        if param.name == "very_verbose" and logger.parent.level > logging.DEBUG:
            logger.parent.setLevel(logging.DEBUG)


def _path_exists_callback(value: Path | List[Path]) -> Path | List[Path]:
    logger.debug(f"_path_exists_callback: {value}")
    if bool(value):
        if type(value) is Path and not value.exists():
            raise typer.BadParameter(f"Path '{value}' does not exist")
        if type(value) is list:
            for v in value:
                if not v.exists():
                    raise typer.BadParameter(f"Path '{v}' does not exist")
    return value


def _parent_path_exists_callback(value: Path | List[Path]) -> Path | List[Path]:
    logger.debug(f"_parent_path_exists_callback: {value}")
    if bool(value):
        if type(value) is Path and not value.parent.exists():
            raise typer.BadParameter(f"Path '{value.parent}' does not exist")
        if type(value) is list:
            for v in value:
                if not v.parent.exists():
                    raise typer.BadParameter(f"Path '{v.parent}' does not exist")
    return value
