# java-web-log-triage

Small Java CLI for reviewing web access logs during blue-team practice.

The project focuses on CS fundamentals in a security context: parsing text
records, grouping events, writing simple detection rules, and reporting useful
signals without external dependencies.

## Current scope

- Parse common Apache/Nginx combined access log lines.
- Flag a small set of suspicious request paths.
- Summarize source IPs, status codes, method/status pairs, repeated
  client/server-error sources, user agents, and findings from a local log file.
- Keep the code buildable with only `javac` and `make`.

## Usage

```sh
make test
make run
```

To scan a different file:

```sh
make compile
java -cp build/classes dev.tzheng.weblogtriage.Main /path/to/access.log
```

`samples/access.log` contains a tiny mixed log with normal requests,
suspicious paths, repeated 4xx responses from one source, and one malformed
line for testing the report. It also includes one 5xx response so the
server-error source section is visible in the sample output. Scanner-style
user agents are included so the user-agent section is visible too.

## Rule notes

The first rule set is documented in [docs/rules.md](docs/rules.md). The rules
are intentionally simple string checks, which makes them easy to inspect and
extend while learning Java collections and text parsing.

## Why this exists

This is a beginner-to-intermediate Java security utility, not a full SIEM. It
is meant to make log parsing and detection logic concrete enough to test and
modify while learning.
