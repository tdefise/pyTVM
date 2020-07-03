#!/usr/bin/env python
# -*- coding: utf-8 -*-

from cwe import Database

db = Database()
weakness = db.get(640)

print(weakness)
print(weakness.description)
