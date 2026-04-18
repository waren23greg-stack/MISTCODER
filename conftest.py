"""
MISTCODER -- pytest configuration
Sets import mode globally so all test modules resolve correctly
on both Windows and Linux (GitHub Actions).
"""
collect_ignore_glob = ["**/src/**"]
