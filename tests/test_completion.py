"""Tests of the bash completion in completions/logherald."""
import importlib.machinery
import importlib.util
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SCRIPT = os.path.join(ROOT, "logherald")
COMPLETION = os.path.join(ROOT, "completions", "logherald")

loader = importlib.machinery.SourceFileLoader("logherald", SCRIPT)
spec = importlib.util.spec_from_loader("logherald", loader)
lh = importlib.util.module_from_spec(spec)
loader.exec_module(lh)


def complete(*words, cwd=None):
    """The candidates bash offers for the last of words, which may be empty."""
    words = ("logherald",) + words
    script = 'source "$1"; shift; COMP_WORDS=("$@"); COMP_CWORD=$(($# - 1)); ' \
             '$(complete -p "$1" | sed -E "s/.*-F ([^ ]+) .*/\\1/"); printf "%s\\n" "${COMPREPLY[@]}"'
    result = subprocess.run(["bash", "-c", script, "bash", COMPLETION] + list(words),
                            capture_output=True, text=True, check=True, cwd=cwd)
    return [line for line in result.stdout.split("\n") if line]


def help_words(*args):
    """The option strings and modes --help lists.

    Before Python 3.13 argparse repeats the metavar after every option string
    ("-H HOST, --host HOST"), since then only after the last ("-H, --host HOST").
    An option line starts with the invocation, followed by the description after
    two or more spaces or, if the invocation is long, on the next line.
    """
    text = subprocess.run([sys.executable, SCRIPT] + list(args) + ["--help"], capture_output=True, text=True,
                          check=True).stdout
    words = set()
    for line in text.split("\n"):
        match = re.match(r"  (-\S.*?)(?:\s{2,}|$)", line)
        if match:
            words.update(re.findall(r"(?:^|, )(-{1,2}[^\s,=\[]+)", match.group(1)))
        match = re.match(r"\s{4}([a-z]+)\s", line)
        if match:
            words.add(match.group(1))
    return words


@unittest.skipUnless(shutil.which("bash"), "bash is not installed")
class CompletionTests(unittest.TestCase):
    def test_syntax(self):
        subprocess.run(["bash", "-n", COMPLETION], check=True)

    def test_offers_exactly_the_modes_and_options_of_help(self):
        self.assertEqual(set(complete("")), help_words())
        self.assertTrue({"digest", "stream"} <= help_words())

    def test_offers_exactly_the_options_of_the_mode_help(self):
        for mode in ("digest", "stream"):
            self.assertEqual(set(complete(mode, "")), help_words(mode), mode)

    def test_mode_prefix(self):
        self.assertEqual(complete("d"), ["digest"])
        self.assertEqual(complete("-V", "s"), ["stream"])

    def test_option_prefix(self):
        self.assertEqual(complete("digest", "--no-"), ["--no-journal", "--no-rsyslog"])
        self.assertEqual(complete("stream", "--no-"), [])
        self.assertEqual(complete("stream", "--sp"), ["--spool"])

    def test_priority(self):
        self.assertEqual(complete("digest", "-p", ""), lh.LEVELS)
        self.assertEqual(complete("stream", "--priority", "=", "w"), ["warning"])

    def test_format(self):
        self.assertEqual(complete("stream", "--format", ""), ["auto", "json", "syslog", "text"])
        self.assertEqual(complete("stream", "--format", "=", "s"), ["syslog"])

    def test_rule_fields(self):
        fields = sorted(field + "=" for field in set(lh.RULE_FIELDS.values()))
        self.assertEqual(sorted(complete("digest", "--include", "")), fields)
        self.assertEqual(complete("stream", "--exclude", "=", "ho"), ["host="])
        # the regular expression after FIELD=
        self.assertEqual(complete("digest", "--include", "host", "=", ""), [])
        self.assertEqual(complete("digest", "--include", "host", "=", "we"), [])
        self.assertEqual(complete("digest", "--include", "=", "host", "=", ""), [])

    def test_files(self):
        with tempfile.TemporaryDirectory() as directory:
            open(os.path.join(directory, "logherald.yaml"), "w").close()
            for mode, option in (("digest", "-C"), ("digest", "--rsyslog-config"), ("stream", "--spool"),
                                 ("stream", "--known-hosts"), ("stream", "--xmpp-config")):
                self.assertEqual(complete(mode, option, "log", cwd=directory), ["logherald.yaml"], option)
            self.assertEqual(complete("stream", "--config", "=", "log", cwd=directory), ["logherald.yaml"])

    def test_no_candidates_for_values(self):
        for option in ("--mail-to", "--xmpp-to", "-S", "--until", "-n", "--top", "--journal-arg"):
            self.assertEqual(complete("digest", option, ""), [], option)
        self.assertEqual(complete("digest", "--journal-arg", "--directory", "=", ""), [])
        for option in ("-s", "--max-age", "--max-lines"):
            self.assertEqual(complete("stream", option, ""), [], option)

    def test_unknown_mode(self):
        self.assertEqual(complete("bogus", ""), [])


if __name__ == "__main__":
    unittest.main()
