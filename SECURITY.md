# Security policy

whohack is an experimental security preview. No version is designated a supported
production security release. Keep the operating system and its antivirus active;
whohack does not replace them. See [release gates](docs/backlog.md) for coverage,
privilege, model-quality and recovery limitations.

Report vulnerabilities through the repository host's private vulnerability
reporting feature when enabled. If it is unavailable, open an issue asking the
maintainer for a private contact, without exploit details, credentials, personal
paths or telemetry. A public release requires the maintainer to configure a
working private reporting channel. No response-time commitment is offered yet.

Include the affected version, OS/build, configuration with secrets removed,
expected/observed behavior and a harmless minimal reproduction. Never submit
live malware, stolen credentials, private files or real victim telemetry. Use
disposable owned processes and synthetic events for response demonstrations.

The local token and input manifests protect ordinary operation; they do not
protect against an administrator controlling the host. The Windows preview runs
as the signed-in user. A manual network operation can request a separate UAC
helper. Automatic response is disabled by default. Protect privilege boundaries,
PID/birth/image checks, pipe peer authentication, quarantine restoration and
model input constraints when changing security-sensitive code.
