"""Shared, deliberately small test-data builders.

The helpers in this package only construct isolated dictionaries.  They do
not hold mutable module-level state, so individual tests remain responsible
for their own fixtures and monkeypatches.
"""
