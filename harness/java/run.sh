#!/usr/bin/env bash
# Java harness: builds with Maven, then runs vnc.Run which reads
# corpus/corpus.json and writes results/raw/java.jsonl (see harness/SCHEMA.md).
#
# Requires: Maven (mvn on PATH) and a JDK 21+ (JAVA_HOME or java on PATH).
# No network I/O is performed by the harness itself; Maven only downloads
# dependencies on the first run. If that download fails with a TLS/PKIX or
# 403 error on a managed machine, check the endpoint-protection proxy
# (e.g. `aikidoctl events --json`) before changing anything.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

mvn -q -B package
java -cp "target/classes:target/lib/*" vnc.Run --out ../../results/raw/java.jsonl
