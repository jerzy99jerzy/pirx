"""Adapters: the only modules permitted to reach the network.

Everything else in the package is offline by construction, and the
import-allowlist scrape enforces it. Keeping the dialect of each ticketing
system behind a three-function protocol means the capability layer never
learns what a Jira issue key looks like.
"""
