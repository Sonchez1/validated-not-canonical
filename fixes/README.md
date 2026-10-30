# Hardening patches

One directory per ecosystem and library, each holding a `git format-patch`
file against the upstream default branch and a `NOTES.md` with the code
path that accepts the non-canonical host, the test results, the project's
security-reporting channel and a ready-to-paste pull-request description.

The patches are withheld from the public repository until each maintainer
has responded to the private report or 90 days have passed, whichever is
first. They will be committed here afterwards.
