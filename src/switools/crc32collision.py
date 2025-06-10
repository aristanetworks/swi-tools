#!/usr/bin/env python3
# Copyright (c) 2018 Arista Networks, Inc.
# Use of this source code is governed by the Apache License 2.0
# that can be found in the LICENSE file.

import typer

from binascii import crc32
from pathlib import Path
from typing import Annotated

from switools.callbacks import _path_exists_callback

# Utility functions to create CRC32 collisions

CRCPOLY = 0xedb88320
CRCINV = 0x5b358fd3

def crcfix( toMatch, toChange ):
   newCrc = 0

   toMatch = toMatch ^ 0xffffffff
   for _ in range( 0, 32 ):
      if ( newCrc & 1 ) != 0:
         newCrc = ( newCrc >> 1 ) ^ CRCPOLY
      else:
         newCrc = newCrc >> 1

      if ( toMatch & 1 ) != 0:
         newCrc ^= CRCINV

      toMatch = toMatch >> 1

   newCrc = newCrc ^ ( toChange ^ 0xffffffff )
   return newCrc

def checkCrc32Value( crc ):
   # According to https://docs.python.org/2/library/binascii.html#binascii.crc32,
   # the return value of binascii.crc32 is in the range [-2**31, 2**31-1]. 
   # However, to be forwards compatible with python 3, the value should be
   # & 0xffffffff'd to be in the range [0, 2**32-1]. 
   assert crc >= 0 and crc < 2**32, \
      "CRC32 is not in the range [0, 2**32-1]. Use & 0xffffffff on the value."

def matchingBytes( crcToMatch, crcToChange ):
   checkCrc32Value( crcToMatch )
   checkCrc32Value( crcToChange )

   bytesToMatch = crcfix( crcToMatch, crcToChange )

   crcBytes = []
   for i in range( 0, 4 ):
      byte = ( bytesToMatch >> ( i * 8 ) ) & 0xff
      crcBytes.append( byte )
   return crcBytes

app = typer.Typer(add_completion=False)

@app.command(name="collision")
def _collision(
   file_to_match: Annotated[Path, typer.Argument(help="File whose CRC32 is to be matched.", callback=_path_exists_callback)] = None,
   file_to_change: Annotated[Path, typer.Argument(help="File to produce a new CRC32 that matches the first.", callback=_path_exists_callback)] = None,
):
   """
   Generate CRC32 collision for two files.
   """
   with open( file_to_match, 'rb' ) as f:
      crcToMatch = crc32( f.read() ) & 0xffffffff
   with open( file_to_change, 'rb' ) as f:
      crcToChange = crc32( f.read() ) & 0xffffffff

   crcBytes = matchingBytes( crcToMatch, crcToChange )
   print( "0x%x%x%x%x" % ( crcBytes[ 0 ],
                           crcBytes[ 1 ],
                           crcBytes[ 2 ],
                           crcBytes[ 3 ] ) )

if __name__ == '__main__':
   app()
