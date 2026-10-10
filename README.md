# logherald

Selects log messages by severity and by include and exclude rules, and sends
them by mail and XMPP ([go-sendxmpp](https://salsa.debian.org/mdosch/go-sendxmpp)).
It has two modes, which share the filters, the outputs and the configuration
file:

- **`logherald digest`**: a digest of the messages of a time span, from the
  systemd journal and from the files rsyslog writes, typically every hour
  from a systemd timer. A message that is in both, as when journald forwards
  to rsyslog, is counted once.
- **`logherald stream`**: the messages that arrive on stdin, as rsyslog's
  `omprog` writes them, sent in batches: after `max_lines` messages,
  `interval` seconds after the first one, when the input ends, and on SIGTERM,
  SIGINT or SIGUSR1. One message per batch instead of one per line keeps a
  burst of errors from flooding the phone.

A typical setup uses both: `stream` for errors right away, `digest` for an
hourly overview of the warnings.

## Requirements

- Python 3.7 or newer; PyYAML for a configuration file
- for digests: `journalctl`, and `systemd-analyze` for the full time syntax
  of journalctl
- a mail server on localhost, e.g. postfix or exim, for mail
- go-sendxmpp for XMPP

## Usage

```sh
logherald digest --print                             # the last hour, printed
logherald digest --print --since today -p err        # errors since midnight
logherald digest -C /etc/logherald/config.yaml       # as the systemd service runs it
logherald digest --show-sources                      # the rsyslog files and their severities
logherald stream -C /etc/logherald/config.yaml --confirm   # as rsyslog's omprog runs it
printf '<27>web nginx: upstream timed out\n' | logherald stream --print   # any stream of syslog lines
```

Options of both modes:

| Option | Meaning |
|---|---|
| `-C`, `--config` | YAML configuration file, see `logherald.yaml.example` |
| `-p`, `--priority` | Severity like journalctl `-p`: a level and everything more severe, or `FROM..TO` (default: `warning`) |
| `--include`, `--exclude` | `FIELD=REGEX` rules, see [Filters](#filters); repeatable |
| `--mail-to`, `--xmpp-to` | Recipients; repeatable |
| `--xmpp-config` | go-sendxmpp's configuration file, with the account |
| `--print` | Print instead of sending |
| `-v`, `--verbose` | Explain on stderr what is done |

`digest`:

| Option | Meaning |
|---|---|
| `-S`, `--since`, `-U`, `--until` | Time span in the syntax of journalctl (default: `-1h` and `now`) |
| `-n`, `--max-lines` | List up to this many messages; above it send the table only, with high priority (default: 100) |
| `--top` | Rows of the host and program table (default: 10) |
| `--no-journal`, `--no-rsyslog` | Leave out one of the sources |
| `--rsyslog-config` | rsyslog's configuration (default: `/etc/rsyslog.conf`) |
| `--journal-arg` | Argument for journalctl instead of `--merge`, e.g. `--directory=/var/log/journal/remote`; repeatable |
| `--show-sources` | Print the files rsyslog writes, with the severities they hold, and exit |

`stream`:

| Option | Meaning |
|---|---|
| `-n`, `--max-lines` | Send after this many messages (default: 20) |
| `-s`, `--interval` | Send this many seconds after the first message of a batch (default: 300) |
| `--format` | `auto`, `json`, `syslog` or `text`, see [Input](#input) (default: `auto`) |
| `--confirm` | Answer `OK` to every message, for omprog's `confirmMessages="on"` |
| `--max-age` | Do not report messages time-stamped longer ago than this many seconds (default: 0, no limit) |
| `--known-hosts` | File of the hosts seen; a new host's backlog is not reported (default: none) |
| `--spool` | Keep unsent messages in this file across restarts (default: none) |

The command line overrides the configuration file. Exit status: 0; 1 if
sending failed (for `stream`: if messages could not be sent before exiting,
and no spool kept them); 2 for an invalid configuration or command line.

## Configuration

One file serves both modes. `priority`, `include`, `exclude`, `mail` and
`xmpp` apply to both; the sections `digest:` and `stream:` hold the settings
of one mode, and may override the common ones for it:

```yaml
priority: warning
include:
  - {program: '^smartd$', message: 'unreadable|uncorrectable'}
mail: {to: [root@localhost]}
xmpp: {to: [admin@example.org], config: /etc/logherald/sendxmpp.conf}

digest:
  since: -1h
  max_lines: 100
stream:
  priority: err            # only errors right away; warnings in the digest
  mail: {to: []}           # and only by XMPP
  max_lines: 20
  interval: 300
```

A mode's `include` or `exclude` replaces the common list; `mail` and `xmpp`
are merged key by key. Unknown settings are an error, so a digest setting at
the top level is not silently ignored. See `logherald.yaml.example` for all
of them.

## Filters

A message is reported if it

1. matches no `exclude` rule, and
2. matches an `include` rule, or has a severity selected by `priority`.

A rule matches a message if all its fields match. Fields are `host`,
`program` (the syslog identifier, also `source` or `tag`), `facility`,
`message` (also `content`), `unit` (the systemd unit) and `origin`
(`journal`, the path of an rsyslog file, or `stdin`). Values are Python
regular expressions, searched anywhere in the field. `unit` is known for
journal entries, and in stream mode for messages from rsyslog's imjournal
with the `%jsonmesg%` format; otherwise it is empty.

On the command line a rule has one field, `FIELD=REGEX`; in the
configuration file a rule can combine several:

```yaml
include:
  - {program: '^smartd$', message: 'unreadable|uncorrectable'}
exclude:
  - {program: '^kernel$', message: 'IN=.*OUT='}
```

In digest mode, include rules make the journal and rsyslog's files be read
for every severity, not only the selected ones.

## Digest mode

```
Subject: [logherald] server1.example.org: 7 message(s) 2026-10-02 17:00:00 - 2026-10-02 18:00:00

Log digest of server1.example.org for 2026-10-02 17:00:00 - 2026-10-02 18:00:00
Severity: warning or more severe; 2 include rule(s); 1 exclude rule(s)
Sources: journal, rsyslog
7 message(s) (journal: 4, rsyslog: 3), 3 duplicate(s) merged

Most messages by host and program:
  Count  Errors  Host     Program
      1       1  server1  kernel
      1       1  server2  nginx
      2       0  server1  sshd
      ...

Messages:
2026-10-02 17:31:19 server1 kernel err: EXT4-fs error: disk full
2026-10-02 17:40:29 printer cupsd[1] warning+: paper jam
...
```

The digest starts with a table of the hosts and programs with the most
messages, errors first, followed by the messages, up to `max_lines` of them.
With more, only the table is sent, with high priority. A severity with `+`
comes from an rsyslog file and is a bound, see [rsyslog files](#rsyslog-files);
`?` marks a message whose severity is unknown, which only an include rule
can report.

`--since` and `--until` are interpreted by `systemd-analyze timestamp`, so
`-1h`, `"1 hour ago"`, `today`, `"2026-10-02 08:00"` and `@1790000000` work
as in journalctl. The journal and the rsyslog files are read for exactly the
same span.

### Journal

`journalctl -o json --merge` for the time span. `--merge` includes the
journals of other hosts, e.g. those systemd-journal-remote receives; change
it with `digest: {journal: {args: [...]}}` or `--journal-arg`.

### rsyslog files

The files come from rsyslog's configuration, including `$IncludeConfig` and
`include()`, legacy selectors (`*.=warning;*.=err -/var/log/warn`),
`action(type="omfile" ...)`, `if $syslogseverity <= 4 then ...` and dynamic
files (`?Template`, `dynaFile=`): `/var/log/hosts/%HOSTNAME%/warn` is read as
`/var/log/hosts/*/warn`. Rotated copies (`warn.1`, `warn-20261001.xz`) are
read if they were written to within the span. `--show-sources` lists the
files with the severities they can hold.

The common file formats do not store a message's severity, so it is taken
from the configuration:

- A file that can only hold selected severities counts entirely, with the
  least severe of them marked `+`: with `-p warning`, openSUSE's
  `/var/log/warn` (warning, err, crit, alert, emerg) is read as `warning+`.
- A file that can also hold other severities, such as `/var/log/messages` or
  Debian's `/var/log/syslog`, gives no severity, so its lines count only
  for include rules. Their messages are usually in the journal anyway.
- A line that carries its priority, as in the RFC 5424 format
  (`RSYSLOG_SyslogProtocol23Format`) or with a `<PRI>` prefix, has its exact
  severity.

Conditions that are more than a conjunction of severity comparisons, such as
`if $programname == 'x' or ...`, count as all severities. For files the
configuration does not reveal, name them with their severities:

```yaml
digest:
  rsyslog:
    files:
      - {path: '/var/log/remote/*/errors.log', priority: err}
```

On a central log server that writes every remote host to one `*.*` file, add
a file for warnings and worse, or one in a format with the priority:

```
*.warning  action(type="omfile" dynaFile="RemoteWarn")
```

### Duplicates

Messages from the same host (compared by its short name), program and text
(with rsyslog's `#011` escapes undone) within `duplicate_window` seconds
(default 5) are one message, if they come from different origins: the
journal, or different rsyslog files. The journal's copy is kept, with its
exact severity. Repetitions within one origin stay separate messages.

### Sending a digest

The digest goes by mail, the summary (the header and the table) by XMPP,
or the whole digest with `xmpp: {full: true}`. Without recipients it is
printed. A digest without messages and problems is not sent, unless
`send_empty: true`.

With more than `max_lines` messages, the mail carries `X-Priority: 1`,
`Importance: high` and `Priority: urgent`, and the subject starts with
`HIGH PRIORITY:`. XMPP messages have no priority (XMPP's priority belongs to
the presence of a resource), so the XMPP message starts with
`HIGH PRIORITY:` as well, and also goes to `xmpp: {high_priority_to: [...]}`.

Problems, such as an unreadable journal or rsyslog configuration, are listed
in the digest, so a broken setup does not stay silent.

### systemd

`systemd/logherald-digest.service` sends the digest of the last hour with
`/etc/logherald/config.yaml`; `systemd/logherald-digest.timer` starts it every
hour and 10 minutes after boot. The service runs as root, as rsyslog's
configuration and files are usually readable only by root, and waits for
`network-online.target`. The hourly span and the run after boot can overlap
or leave a gap of a few seconds; the run after boot covers the hour before
it, including the shutdown.

## Stream mode

### Input

One message per line. `--format auto` recognizes

- RFC 5424 (`RSYSLOG_SyslogProtocol23Format`),
- a time stamp (BSD or RFC 3339) and host name, optionally after `<PRI>`,
  such as `RSYSLOG_ForwardFormat` or the lines of rsyslog's files,
- rsyslog's `%jsonmesg%` (a template `"%jsonmesg%\n"`), which also carries
  the systemd unit of messages from imjournal.

Only lines with a priority (`<PRI>`, RFC 5424, JSON) have a severity. Lines
without, or in no known format, are reported only by an include rule; with
`--format text`, every line is such a line.

### rsyslog

`data/rsyslog-logherald.conf`:

```
module(load="omprog")

action(type="omprog"
       name="logherald"
       binary="/usr/bin/logherald stream -C /etc/logherald/config.yaml --confirm"
       template="RSYSLOG_SyslogProtocol23Format"
       confirmMessages="on"
       signalOnClose="on"
       closeTimeout="120000"
       output="/var/log/logherald.log"
       queue.type="LinkedList"
       queue.size="10000"
       action.resumeRetryCount="-1")
```

- `confirmMessages="on"` with `--confirm`: logherald answers `OK` to each
  message once it is in the batch, so rsyslog knows it was taken.
- `signalOnClose` and `closeTimeout`: when rsyslog stops or restarts, it
  closes the pipe, sends SIGTERM, and waits up to two minutes before killing
  logherald; meanwhile the batch goes out.
- `output`: logherald's error messages, e.g. when go-sendxmpp fails.
- The queue keeps rsyslog's other actions running should logherald fall
  behind.

To spare logherald the info and debug messages, wrap the action in
`if $syslogseverity <= 4 then { ... }`; then its include rules see only what
passes that filter.

omprog runs the program with rsyslog's privileges, usually root. The
go-sendxmpp configuration holds the XMPP password: make it readable by root
only.

### Batches

```
[logherald] web: 23 message(s)

2026-10-05 10:00:00 web nginx[42] err: upstream timed out (×21, last 10:04:57)
2026-10-05 10:00:01 web sshd[7] info: Accepted publickey for root from 10.0.0.5
2026-10-05 10:02:13 web kernel crit: EXT4-fs error: disk full
```

Identical messages of a batch (same host, program, severity and text) are
listed once, with their count and the time of the last. XMPP gets the subject
as the first line and the whole batch; mail gets the batch with the subject.

A batch is sent in the background: logherald keeps reading, and
confirming, the messages rsyslog writes meanwhile, so a slow or unreachable
XMPP or mail server does not fill omprog's queue.

If go-sendxmpp or the mail fails, the messages stay and the next attempt is
after 30 seconds, then 60, 120 and so on up to an hour; new messages are
added meanwhile. Mail and XMPP keep their own messages, so one failing does
not resend to the other. Each holds at most `max_buffer` messages (default
1000); beyond that the oldest are dropped, and the next batch says how many.
At the end of the input logherald waits for a batch being sent, or else
tries once more, and exits with 1 if messages are left that no spool keeps.

### Spool

With `spool: /var/lib/logherald/spool.json`, the messages that could not be
sent are kept in that file (readable by its owner only), and sent after the
next start: a log server that boots before the XMPP server, or shuts down
after it, then loses no notification. logherald writes the file when a send
fails and when it exits, before it tries a last time, so that it holds the
messages even if rsyslog kills logherald after `closeTimeout`; then a batch
may be sent twice. The file is removed once everything is sent.

### New hosts and old messages

rsyslog can hand logherald old messages: a host's whole journal when
`systemd-journal-upload` starts on it for the first time, or the journals
again when imjournal's state file is lost. Two settings keep them from being
reported; the messages stay in the journals and files.

- `known_hosts: /var/lib/logherald/known-hosts`: a file of the hosts seen,
  with the time each was first seen. During the first hour after a host was
  first seen, its messages time-stamped more than 5 minutes before that are
  its backlog, and not reported; the next batch says that there is a new
  host. Hosts in the file are not affected: remove a host's line to treat it
  as new again. Limiting this to an hour keeps a host whose clock or time
  zone is off from being silenced for good.
- `max_age: 86400`: messages time-stamped longer ago than this many seconds
  are not reported, from any host; the next batch says how many. Choose it
  well above the clock and time zone differences of the hosts: rsyslog
  takes a BSD time stamp, which has no time zone, as local time.

Both compare the messages' own time stamps; a line without one counts as
received now.

## Installation

```sh
install -m 0755 logherald /usr/bin/
install -D -m 0644 logherald.yaml.example /etc/logherald/config.yaml
# digests
install -m 0644 systemd/logherald-digest.service systemd/logherald-digest.timer /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now logherald-digest.timer
# stream
install -m 0644 data/rsyslog-logherald.conf /etc/rsyslog.d/logherald.conf
systemctl restart rsyslog
```

## Bash completion

`completions/logherald` completes the modes, the options of each mode and
their values. The packages install it; otherwise copy it to bash-completion's
directory:

```sh
install -D -m 0644 completions/logherald /usr/share/bash-completion/completions/logherald
```

## Tests

```sh
python3 -m unittest -v
```

The tests use a fake journalctl, rsyslog configurations in the layouts of
openSUSE and Debian, a fake SMTP server and a fake go-sendxmpp, and rsyslogd
with omprog if it is installed. `tests/test_completion.py` checks the bash
completion against `--help`.

## License

GPL-2.0-or-later, see [LICENSE](LICENSE).
