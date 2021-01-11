#!/usr/bin/env python3
# Copyright (c) 2018 Arista Networks, Inc.
# Use of this source code is governed by the Apache License 2.0
# that can be found in the LICENSE file.

from binascii import crc32
import argparse

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

# Usage: filetomatch filetochange
def main():
   helpText = "Generate CRC32 collision for two files"
   parser = argparse.ArgumentParser( description=helpText )
   parser.add_argument( "fileToMatch", help="File whose CRC32 is to be matched" )
   parser.add_argument( "fileToChange", 
                        help="File to produce a new CRC32 that matches the first" )
   args = parser.parse_args()
   fileToMatch = args.fileToMatch
   fileToChange = args.fileToChange

   with open( fileToMatch, 'rb' ) as f:
      crcToMatch = crc32( f.read() ) & 0xffffffff
   with open( fileToChange, 'rb' ) as f:
      crcToChange = crc32( f.read() ) & 0xffffffff

   crcBytes = matchingBytes( crcToMatch, crcToChange )
   print( "0x%x%x%x%x" % ( crcBytes[ 0 ],
                           crcBytes[ 1 ],
                           crcBytes[ 2 ],
                           crcBytes[ 3 ] ) )

if __name__ == '__main__':
   main()
