#!/bin/sh
nc -w 60 $2 $3 < $1 | head -1 | sed -e"s/.$/ - $2/"
