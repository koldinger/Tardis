#! /usr/bin/python

from Tardis import CacheDir
import argparse
import sys

parser = argparse.ArgumentParser(description="Generate file paths in a cache dir directory", add_help=True)
parser.add_argument('--base', '-b', dest='base', default='.', help='Base CacheDir directory')
parser.add_argument('files', nargs='*', help='List of files to print')
args = parser.parse_args()

c = CacheDir.CacheDir(args.base)

for i in args.files:
    print c.path(i)