"""Tests of logherald digest with a fake journalctl, fake rsyslog configurations and files, a fake SMTP
server and a fake go-sendxmpp."""
import gzip
import importlib.machinery
import importlib.util
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(os.path.dirname(HERE), "logherald")

loader = importlib.machinery.SourceFileLoader("logherald", SCRIPT)
spec = importlib.util.spec_from_loader("logherald", loader)
lh = importlib.util.module_from_spec(spec)
loader.exec_module(lh)

NOW = time.time()


def read(path):
    with open(path, encoding="utf-8") as handle:
        return handle.read()

FAKE_JOURNALCTL = r'''#!/usr/bin/python3
"""journalctl -o json for tests: filters the entries of $FAKE_JOURNAL by -p, --since and --until."""
import json, os, sys
args = sys.argv[1:]
with open(os.environ["FAKE_LOG"], "a") as log:
    log.write("journalctl " + json.dumps(args) + "\n")
if os.environ.get("FAKE_JOURNAL_FAIL"):
    sys.stderr.write("No journal files were opened due to insufficient permissions.\n")
    sys.exit(1)
def value(name):
    return args[args.index(name) + 1] if name in args else None
since, until, prio = value("--since"), value("--until"), value("-p")
low, high = (int(part) for part in prio.split("..")) if prio else (0, 7)
for line in open(os.environ["FAKE_JOURNAL"]):
    entry = json.loads(line)
    stamp = int(entry["__REALTIME_TIMESTAMP"]) / 1e6
    if since and stamp < float(since[1:]) or until and stamp > float(until[1:]):
        continue
    if not low <= int(entry.get("PRIORITY", 6)) <= high:
        continue
    print(line.rstrip("\n"))
'''

FAKE_XMPP = r'''#!/bin/sh
echo "go-sendxmpp $*" >> "$FAKE_LOG"
cat > "$FAKE_XMPP_TEXT"
'''


def journal_entry(seconds_ago, host, program, message, priority, pid="100", unit=""):
    entry = {"__REALTIME_TIMESTAMP": str(int((NOW - seconds_ago) * 1e6)), "_HOSTNAME": host,
             "SYSLOG_IDENTIFIER": program, "SYSLOG_PID": pid, "MESSAGE": message, "PRIORITY": str(priority)}
    if unit:
        entry["_SYSTEMD_UNIT"] = unit
    return json.dumps(entry)


def traditional(seconds_ago):
    return time.strftime("%b %e %H:%M:%S", time.localtime(int(NOW - seconds_ago)))


def rfc3339(seconds_ago):
    stamp = NOW - seconds_ago
    offset = time.strftime("%z", time.localtime(stamp))
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(stamp)) + ".123456" + offset[:3] + ":" + offset[3:]


class FakeSMTP:
    """Just enough SMTP to receive one message."""

    def __init__(self):
        self.server = socket.socket()
        self.server.bind(("127.0.0.1", 0))
        self.server.listen(1)
        self.port = self.server.getsockname()[1]
        self.data = None
        self.rcpt = []
        threading.Thread(target=self.serve, daemon=True).start()

    def serve(self):
        conn, _ = self.server.accept()
        stream = conn.makefile("rb")
        conn.sendall(b"220 fake ESMTP\r\n")
        while True:
            line = stream.readline()
            if not line:
                break
            command = line.decode().strip().upper()
            if command.startswith(("EHLO", "HELO")):
                conn.sendall(b"250 fake\r\n")
            elif command.startswith("MAIL"):
                conn.sendall(b"250 ok\r\n")
            elif command.startswith("RCPT"):
                self.rcpt.append(line.decode().strip())
                conn.sendall(b"250 ok\r\n")
            elif command == "DATA":
                conn.sendall(b"354 go ahead\r\n")
                lines = []
                while True:
                    data_line = stream.readline()
                    if data_line in (b".\r\n", b""):
                        break
                    lines.append(data_line)
                self.data = b"".join(lines).decode("utf-8", "replace")
                conn.sendall(b"250 queued\r\n")
            elif command == "QUIT":
                conn.sendall(b"221 bye\r\n")
                break
            else:
                conn.sendall(b"250 ok\r\n")
        stream.close()
        conn.close()
        self.server.close()


class TestParsing(unittest.TestCase):
    def test_priority(self):
        self.assertEqual(frozenset(range(5)), lh.parse_priority("warning"))
        self.assertEqual(frozenset(range(4)), lh.parse_priority("3"))
        self.assertEqual(frozenset({3, 4, 5}), lh.parse_priority("err..notice"))
        self.assertEqual(frozenset({3, 4, 5}), lh.parse_priority("notice..err"))
        with self.assertRaises(ValueError):
            lh.parse_priority("loud")

    def test_selector_levels(self):
        levels = lh.selector_levels
        self.assertEqual(frozenset(range(8)), levels("*.*"))
        self.assertEqual(frozenset(range(5)), levels("*.warning"))
        self.assertEqual(frozenset({3, 4}), levels("*.=warning;*.=err"))
        self.assertEqual(frozenset(range(8)), levels("*.*;mail.none;news.none"))
        self.assertEqual(frozenset(), levels("mail.none"))
        self.assertEqual(frozenset({5, 6, 7}), levels("*.*;*.!warning"))
        self.assertEqual(frozenset(range(4)), levels("kern,mail.err"))

    def test_condition_levels(self):
        levels = lh.condition_levels
        self.assertEqual(frozenset(range(5)), levels(" $syslogseverity <= 4 "))
        self.assertEqual(frozenset(range(3)), levels(" ($syslogseverity < 3) and ($programname == 'x') "))
        self.assertEqual(frozenset({3}), levels(" $syslogseverity-text == 'err' "))
        self.assertEqual(frozenset(range(4)), levels(' prifilt("*.err") '))
        self.assertEqual(frozenset(range(8)), levels(" ($programname == 'a') or ($syslogseverity <= 3) "))
        self.assertEqual(frozenset(range(8)), levels(" $programname == 'NetworkManager' "))

    def test_line_formats(self):
        until = NOW + 60

        def fields(entry):
            return entry.host, entry.program, entry.pid, entry.message, entry.priority

        entry = lh.parse_line("%s server1 sshd[123]: Failed password for root" % traditional(30), until)
        self.assertAlmostEqual(NOW - 30, entry.time, delta=1.5)
        self.assertEqual(("server1", "sshd", "123", "Failed password for root", None), fields(entry))
        entry = lh.parse_line("%s server2 kernel: oops" % rfc3339(10), until)
        self.assertAlmostEqual(NOW - 10, entry.time, delta=1.5)
        self.assertEqual(("server2", "kernel", "", "oops", None), fields(entry))
        entry = lh.parse_line("<11>1 %s server3 app 42 ID47 [x@1 a=\"b\"] \ufeffbroken" % rfc3339(5), until)
        self.assertEqual(("server3", "app", "42", "broken", 3), fields(entry))
        self.assertEqual("user", entry.facility)
        entry = lh.parse_line("<12>%s server4 cron[7]: job failed" % rfc3339(5), until)
        self.assertEqual(("server4", "cron", "7", "job failed", 4), fields(entry))
        self.assertIsNone(lh.parse_line("garbage", until))

    def test_time_fallback(self):
        parse = lh.parse_time_fallback
        self.assertAlmostEqual(NOW - 3600, parse("-1h", NOW))
        self.assertAlmostEqual(NOW - 5400, parse("-1h 30min", NOW))
        self.assertAlmostEqual(NOW - 7200, parse("2 hours ago", NOW))
        self.assertAlmostEqual(NOW - 2629800, parse("-1M", NOW))
        self.assertEqual(1790000000.0, parse("@1790000000", NOW))
        self.assertEqual(time.mktime((2026, 10, 2, 8, 0, 0, 0, 0, -1)), parse("2026-10-02 08:00", NOW))
        with self.assertRaises(ValueError):
            parse("soon", NOW)

    def test_time_with_systemd_analyze(self):
        if not shutil.which("systemd-analyze"):
            self.skipTest("systemd-analyze is not installed")
        self.assertAlmostEqual(time.time() - 3600, lh.parse_time("-1h", time.time()), delta=5)
        self.assertEqual(time.mktime((2026, 10, 2, 8, 0, 0, 0, 0, -1)),
                         lh.parse_time("2026-10-02 08:00", NOW))
        with self.assertRaises(ValueError):
            lh.parse_time("soon", NOW)

    def test_rules(self):
        rule = lh.parse_rule({"program": "^sshd$", "message": "Failed"})
        entry = lh.Entry(NOW, "h", "sshd", "1", "Failed password", 4, "journal")
        self.assertTrue(rule.matches(entry))
        entry.program = "sshd-session"
        self.assertFalse(rule.matches(entry))
        self.assertTrue(lh.parse_rule("source=sshd").matches(entry))
        with self.assertRaises(ValueError):
            lh.parse_rule("color=red")
        with self.assertRaises(ValueError):
            lh.parse_rule("message")

    def test_duplicates(self):
        def entry(seconds_ago, origin, message="disk full", host="server1.example.org"):
            return lh.Entry(NOW - seconds_ago, host, "kernel", "", message, 3, origin)
        entries = [entry(10, "journal"), entry(10.4, "/var/log/warn", host="server1"),
                   entry(10.2, "/var/log/messages", "disk  full"),
                   # a real repetition within one origin stays
                   entry(9, "journal"),
                   # outside the window it is a separate message
                   entry(100, "/var/log/warn")]
        kept, merged = lh.merge_duplicates(entries, 5, "server1")
        self.assertEqual(2, merged)
        self.assertEqual(3, len(kept))
        self.assertEqual("journal", kept[1].origin)


class TestRsyslogConfig(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        os.makedirs(os.path.join(self.dir, "rsyslog.d"))

    def tearDown(self):
        shutil.rmtree(self.dir)

    def write(self, name, text):
        path = os.path.join(self.dir, name)
        with open(path, "w") as handle:
            handle.write(textwrap.dedent(text).replace("{D}", self.dir))
        return path

    def test_opensuse_layout(self):
        self.write("rsyslog.d/NetworkManager.frule", """\
            if      ($programname == 'NetworkManager') or \\
                    ($programname startswith 'nm-') \\
            then {
                    -{D}/NetworkManager
                    stop
            }
            """)
        self.write("rsyslog.d/remote.conf", """\
            $template RemoteHost,"{D}/hosts/%HOSTNAME%/messages"
            template(name="RemoteWarn" type="string" string="{D}/hosts/%HOSTNAME%/warn")
            ruleset(name="remote") {
                *.* ?RemoteHost
                if $syslogseverity <= 4 then action(type="omfile" dynaFile="RemoteWarn")
            }
            """)
        path = self.write("rsyslog.conf", """\
            $ModLoad imuxsock.so
            $IncludeConfig {D}/rsyslog.d/*.conf
            if	( \\
                ($syslogfacility-text == 'kern') and /* warning */ \\
                ($syslogseverity <= 4) and not \\
                ($msg contains 'IN=' and $msg contains 'OUT=') \\
            ) then {
                /dev/tty10
                |/dev/xconsole
            }
            *.emerg					 :omusrmsg:*
            $IncludeConfig {D}/rsyslog.d/*.frule
            mail.*					-{D}/mail
            mail.warning				-{D}/mail.warn
            *.=warning;*.=err			-{D}/warn
            *.crit					 {D}/warn
            *.*;mail.none;news.none			-{D}/messages   # everything
            local0.*;local1.*			-{D}/localmessages
            """)
        config = lh.RsyslogConfig(path)
        d = self.dir
        self.assertEqual({
            d + "/hosts/*/messages": set(range(8)),
            d + "/hosts/*/warn": set(range(5)),
            d + "/NetworkManager": set(range(8)),
            d + "/mail": set(range(8)),
            d + "/mail.warn": set(range(5)),
            d + "/warn": {0, 1, 2, 3, 4},
            d + "/messages": set(range(8)),
            d + "/localmessages": set(range(8)),
        }, dict(config.targets))
        self.assertEqual([], config.problems)

    def test_debian_layout(self):
        path = self.write("rsyslog.conf", """\
            module(load="imuxsock") # provides support for local system logging
            module(load="imklog")   # provides kernel logging support
            $FileGroup adm
            include(file="{D}/rsyslog.d/*.conf" mode="optional")
            *.*;auth,authpriv.none		-{D}/syslog
            auth,authpriv.*			{D}/auth.log
            kern.*				-{D}/kern.log
            *.emerg				:omusrmsg:*
            """)
        self.write("rsyslog.d/50-errors.conf", """\
            *.err action(type="omfile" file="{D}/errors.log" template="RSYSLOG_FileFormat")
            & action(type="omfwd" target="logserver")
            """)
        config = lh.RsyslogConfig(path)
        d = self.dir
        self.assertEqual({d + "/errors.log": set(range(4)), d + "/syslog": set(range(8)),
                          d + "/auth.log": set(range(8)), d + "/kern.log": set(range(8))}, dict(config.targets))

    def test_unknown_dynafile_template(self):
        path = self.write("rsyslog.conf", "*.* ?Nowhere\n")
        config = lh.RsyslogConfig(path)
        self.assertEqual({}, dict(config.targets))
        self.assertIn("unknown template 'Nowhere'", config.problems[0])

    def test_unreadable(self):
        with self.assertRaises(lh.HeraldError):
            lh.RsyslogConfig(os.path.join(self.dir, "missing.conf"))


class TestEndToEnd(unittest.TestCase):
    """logherald digest as it runs, with a journal of local and remote hosts and rsyslog files."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        d = self.dir
        self.bin = os.path.join(d, "bin")
        os.makedirs(self.bin)
        for name, text in (("journalctl", FAKE_JOURNALCTL), ("go-sendxmpp", FAKE_XMPP)):
            path = os.path.join(self.bin, name)
            with open(path, "w") as handle:
                handle.write(text)
            os.chmod(path, 0o755)
        self.fake_log = os.path.join(d, "calls.log")
        self.xmpp_text = os.path.join(d, "xmpp.txt")
        os.makedirs(os.path.join(d, "hosts", "printer"))
        with open(os.path.join(d, "rsyslog.conf"), "w") as handle:
            handle.write(textwrap.dedent("""\
                $template RemoteWarn,"{D}/hosts/%HOSTNAME%/warn"
                *.=warning;*.=err			-{D}/warn
                *.crit					 {D}/warn
                *.*					-{D}/messages
                if $syslogseverity <= 4 then ?RemoteWarn
                """).replace("{D}", d))
        self.journal([
            journal_entry(600, "server1", "kernel", "EXT4-fs error: disk full", 3, pid=""),
            journal_entry(500, "server1", "sshd", "Failed password for root", 4),
            journal_entry(400, "server1", "sshd", "Failed password for root", 4),
            journal_entry(300, "server1", "cron", "job started", 6),
            journal_entry(250, "server1", "backup", "backup finished: segfault avoided", 6),
            journal_entry(200, "server2.example.org", "nginx", "upstream timed out", 3, unit="nginx.service"),
            journal_entry(7200, "server1", "old", "outside the time span", 3),
        ])
        # rsyslog's copies of journal messages, and messages only rsyslog has
        self.lines("warn", [
            "%s server1 kernel: EXT4-fs error: disk full" % traditional(600),
            "%s server1 sshd[100]: Failed password for root" % traditional(500),
            "%s server1 sshd[100]: Failed password for root" % traditional(400),
            "%s server1 smartd[9]: Device /dev/sda: 8 Currently unreadable sectors" % traditional(100),
        ])
        self.lines("messages", [
            "%s server1 cron[5]: job started" % traditional(300),
            "%s server1 smartd[9]: Device /dev/sda: 8 Currently unreadable sectors" % traditional(100),
            "%s server1 dhcpd[3]: DHCPACK on 10.0.0.5" % traditional(90),
        ])
        self.lines("hosts/printer/warn", ["%s printer cupsd[1]: paper jam" % rfc3339(50)])
        # a rotated copy with an older message from within the time span
        with gzip.open(os.path.join(d, "warn-20261001.gz"), "wt") as handle:
            handle.write("%s server1 raid[2]: md0 degraded\n" % traditional(1800))

    def tearDown(self):
        shutil.rmtree(self.dir)

    def journal(self, entries):
        self.journal_path = os.path.join(self.dir, "journal.json")
        with open(self.journal_path, "w") as handle:
            handle.write("\n".join(entries) + "\n")

    def lines(self, name, lines):
        with open(os.path.join(self.dir, name), "w") as handle:
            handle.write("\n".join(lines) + "\n")

    def run_digest(self, *argv, env=None):
        environ = dict(os.environ, PATH=self.bin + os.pathsep + os.environ["PATH"], FAKE_LOG=self.fake_log,
                       FAKE_JOURNAL=self.journal_path, FAKE_XMPP_TEXT=self.xmpp_text)
        environ.update(env or {})
        return subprocess.run([sys.executable, SCRIPT, "digest", "--rsyslog-config", os.path.join(self.dir, "rsyslog.conf"),
                               "--since", "-1h"] + list(argv),
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
                              env=environ, timeout=120)

    def test_digest(self):
        result = self.run_digest("--print")
        self.assertEqual(0, result.returncode, result)
        out = result.stdout
        self.assertIn("Sources: journal, rsyslog", out)
        # journal 4 (disk full, 2x sshd, nginx) + rsyslog only: smartd, printer, raid; 3 merged duplicates
        self.assertIn("7 message(s) (journal: 4, rsyslog: 3), 3 duplicate(s) merged", out, out)
        self.assertEqual(2, out.count("Failed password for root"), "a repetition is not a duplicate")
        self.assertEqual(1, out.count("EXT4-fs error: disk full"))
        self.assertEqual(1, out.count("8 Currently unreadable sectors"), "warn and messages are one message")
        self.assertIn("printer cupsd[1] warning+: paper jam", out, "remote host from a dynamic file")
        self.assertIn("server1 raid[2] warning+: md0 degraded", out, "rotated, compressed file")
        self.assertIn("server2.example.org nginx[100] err: upstream timed out", out)
        self.assertNotIn("job started", out)
        self.assertNotIn("DHCPACK", out)
        self.assertNotIn("outside the time span", out)
        # the table: errors first
        table = out.split("Most messages by host and program:")[1].split("Messages:")[0]
        rows = [line.split() for line in table.strip().splitlines()[1:]]
        self.assertEqual(["1", "1", "server1", "kernel"], rows[0])
        self.assertIn(["2", "0", "server1", "sshd"], rows)
        journal_calls = [json.loads(line.split(" ", 1)[1]) for line in read(self.fake_log).splitlines()]
        self.assertIn("-p", journal_calls[0])
        self.assertIn("--merge", journal_calls[0])

    def test_priority(self):
        out = self.run_digest("--print", "-p", "err").stdout
        self.assertIn("EXT4-fs error", out)
        self.assertNotIn("Failed password", out)
        # /var/log/warn also holds warnings, so its lines without the journal's copy are of unknown severity
        self.assertNotIn("smartd", out)

    def test_include_and_exclude(self):
        out = self.run_digest("--print", "--include", "message=segfault", "--include", "program=^dhcpd$",
                              "--exclude", "host=^server2", "--exclude", "message=^Failed").stdout
        self.assertIn("backup finished: segfault avoided", out)
        self.assertIn("backup[100] info: backup finished", out)
        self.assertIn("dhcpd[3] ?: DHCPACK", out, "an included line of unknown severity")
        self.assertNotIn("nginx", out)
        self.assertNotIn("Failed password", out)
        journal_calls = [json.loads(line.split(" ", 1)[1]) for line in read(self.fake_log).splitlines()]
        self.assertNotIn("-p", journal_calls[0], "include rules need every level")

    def test_yaml_config(self):
        path = os.path.join(self.dir, "lh.yaml")
        with open(path, "w") as handle:
            handle.write(textwrap.dedent("""\
                priority: err
                exclude:
                  - {program: nginx, host: server2}
                digest:
                  top: 1
                  rsyslog:
                    enabled: false
                stream:
                  priority: debug
                """))
        out = self.run_digest("--print", "--config", path).stdout
        self.assertIn("Sources: journal\n", out)
        self.assertIn("1 message(s)", out)
        self.assertIn("EXT4-fs error", out)

    def test_too_many_messages(self):
        out = self.run_digest("--print", "-n", "3").stdout
        self.assertIn("Subject: HIGH PRIORITY: ", out)
        self.assertIn("More than 3 messages, so they are not listed. To see them:", out)
        self.assertIn("logherald digest --print --since '", out)
        self.assertNotIn("Messages:", out)

    def test_mail_and_xmpp(self):
        smtp = FakeSMTP()
        config = os.path.join(self.dir, "send.yaml")
        with open(config, "w") as handle:
            handle.write(textwrap.dedent("""\
                digest:
                  max_lines: 3
                mail:
                  to: [admin@example.org]
                  from: logs@example.org
                  port: %d
                xmpp:
                  to: admin@jabber.example.org
                  high_priority_to: [oncall@jabber.example.org]
                  config: /etc/go-sendxmpp.conf
                """ % smtp.port))
        result = self.run_digest("--config", config)
        self.assertEqual(0, result.returncode, result)
        for _ in range(50):
            if smtp.data:
                break
            time.sleep(0.1)
        self.assertIn("X-Priority: 1 (Highest)", smtp.data)
        self.assertIn("Importance: high", smtp.data)
        self.assertIn("Subject: HIGH PRIORITY: [logherald]", smtp.data)
        self.assertEqual(["rcpt to:<admin@example.org>"], [r.lower() for r in smtp.rcpt])
        calls = read(self.fake_log)
        self.assertIn("go-sendxmpp -f /etc/go-sendxmpp.conf admin@jabber.example.org oncall@jabber.example.org",
                      calls)
        text = read(self.xmpp_text)
        self.assertTrue(text.startswith("HIGH PRIORITY: [logherald]"))
        self.assertIn("Most messages by host and program:", text)
        self.assertNotIn("Messages:", text, "XMPP gets the summary")

    def test_normal_priority_mail(self):
        smtp = FakeSMTP()
        config = os.path.join(self.dir, "send.yaml")
        with open(config, "w") as handle:
            handle.write("mail:\n  to: [admin@example.org]\n  port: %d\n" % smtp.port)
        result = self.run_digest("--config", config)
        self.assertEqual(0, result.returncode, result)
        for _ in range(50):
            if smtp.data:
                break
            time.sleep(0.1)
        self.assertNotIn("X-Priority", smtp.data)
        self.assertIn("Messages:", smtp.data)

    def test_nothing_to_send(self):
        result = self.run_digest("--since", "-1s", "--mail-to", "admin@example.org", "-v")
        self.assertEqual(0, result.returncode, result)
        self.assertIn("nothing to send", result.stderr)

    def test_problems_are_reported(self):
        result = self.run_digest("--print", "--rsyslog-config", os.path.join(self.dir, "missing.conf"),
                                 env={"FAKE_JOURNAL_FAIL": "1"})
        self.assertEqual(0, result.returncode, result)
        self.assertIn("journalctl failed: No journal files were opened due to insufficient permissions.", result.stdout)

    def test_since_until_syntax(self):
        result = self.run_digest("--print", "--since", "-1h", "--until", "-5min")
        self.assertEqual(0, result.returncode, result)
        self.assertNotIn("paper jam", result.stdout, "50s ago is after --until")
        result = self.run_digest("--print", "--since", "soon")
        self.assertEqual(2, result.returncode, result)
        self.assertIn("cannot parse time 'soon'", result.stderr)

    def test_mode_section_overrides(self):
        path = os.path.join(self.dir, "logherald.yaml")
        with open(path, "w") as handle:
            handle.write("priority: debug\ndigest:\n  priority: err\n")
        out = self.run_digest("--print", "--config", path).stdout
        self.assertIn("Severity: err or more severe", out)
        self.assertNotIn("Failed password", out)

    def test_unknown_setting(self):
        path = os.path.join(self.dir, "logherald.yaml")
        with open(path, "w") as handle:
            handle.write("since: -2h\n")
        result = self.run_digest("--print", "--config", path)
        self.assertEqual(2, result.returncode, result)
        self.assertIn("unknown setting 'since'", result.stderr)

    def test_show_sources(self):
        out = self.run_digest("--show-sources").stdout
        self.assertIn(self.dir + "/warn", out)
        self.assertIn("emerg,alert,crit,err,warning", out)


if __name__ == "__main__":
    unittest.main()
