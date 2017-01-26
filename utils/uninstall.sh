#!/bin/bash

find /usr -name virgil -type f -exec rm {} \; > /dev/null 2>&1
rm -fr ~/.virgil > /dev/null 2>&1
