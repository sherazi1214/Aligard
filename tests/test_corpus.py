import csv

import pytest

from engine import corpus
from engine.corpus import Record

PHISH = "Urgent: verify your {b} account now. Your account will be suspended in 24 hours unless you confirm your PIN: http://{b}-secure.xyz/login/{n}"
LEGIT = "Hi team, the {b} project meeting is tomorrow at 3pm in the conference room. Please bring your updates and notes, thanks {n}"


def _recs(n=40):
    out = []
    for i in range(n):
        out.append(Record(f"Subject {i}\n" + PHISH.format(b=f"bank{i}x{i * 7}", n=i * 1111), 1, "a"))
        out.append(Record(f"Subject {i}\n" + LEGIT.format(b=f"proj{i}y{i * 3}", n=i * 2222), 0, "b"))
    return out


def test_parse_label_variants():
    assert [corpus.parse_label(x) for x in ("1", "Phishing", "SPAM", "0", "ham", "legit")] == [1, 1, 1, 0, 0, 0]
    with pytest.raises(ValueError):
        corpus.parse_label("maybe")


def _write(path, rows, header):
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(header)
        w.writerows(rows)


def test_load_csv_text_and_label(tmp_path):
    p = tmp_path / "a.csv"
    _write(p, [["Please verify your account password immediately at the link", "phishing"],
               ["Lunch at noon tomorrow? Let me know what you prefer", "0"],
               ["short", "1"]], ["text", "label"])
    recs = corpus.load_csv(p, "mine")
    assert [(r.label, r.source) for r in recs] == [(1, "mine"), (0, "mine")]  # chhota text (short) chhoot gaya


def test_load_csv_subject_body_and_fixed_label(tmp_path):
    p = tmp_path / "b.csv"
    _write(p, [["Invoice", "<p>Please see the <b>attached</b> invoice for last month</p><script>x()</script>"]],
           ["Subject", "Body"])
    recs = corpus.load_csv(p, "enron", label=0)
    assert len(recs) == 1 and "<" not in recs[0].text and "x()" not in recs[0].text


def test_load_csv_needs_label_or_arg(tmp_path):
    p = tmp_path / "c.csv"
    _write(p, [["some long enough message text for the loader"]], ["text"])
    with pytest.raises(ValueError):
        corpus.load_csv(p, "x")


def test_load_email_dir_and_mbox(tmp_path):
    raw = (b"From: a@b.com\nTo: c@d.com\nSubject: Verify your account\nContent-Type: text/plain\n\n"
           b"Please verify your account immediately by clicking the link below to avoid closure.\n")
    d = tmp_path / "spam"
    d.mkdir()
    (d / "0001.abc").write_bytes(raw)
    (d / "cmds").write_text("junk")
    recs = corpus.load_email_dir(d, "spamassassin", 1)
    assert len(recs) == 1 and recs[0].label == 1 and "Verify your account" in recs[0].text
    mb = tmp_path / "n.mbox"
    mb.write_bytes(b"From MAILER-DAEMON Mon Jan 1 00:00:00 2024\n" + raw + b"\n")
    recs2 = corpus.load_mbox(mb, "nazario", 1)
    assert len(recs2) == 1 and recs2[0].source == "nazario"


def test_dedup_removes_exact_even_if_url_or_number_differs():
    a = Record("Verify your account now http://evil1.xyz/a 123456789 please confirm", 1, "x")
    b = Record("Verify your account now http://evil2.top/b 987654321 please confirm", 1, "y")
    kept, st = corpus.dedup([a, b])
    assert len(kept) == 1 and st["exact_duplicates_removed"] == 1


def test_dedup_drops_conflicting_labels():
    t = "Your parcel could not be delivered please confirm your address and pay the fee today"
    kept, st = corpus.dedup([Record(t, 1, "x"), Record(t, 0, "y")])
    assert kept == [] and st["label_conflicts_removed"] == 1


def test_dedup_groups_near_duplicates():
    base = ("Dear customer we detected unusual activity on your account and it will be suspended "
            "within 24 hours unless you verify your identity and confirm your login details right now ")
    a = Record(base + "thanks team", 1, "x")
    b = Record(base + "thanks support", 1, "y")
    c = Record("Completely different message about the cricket match plan this weekend with everyone invited", 0, "z")
    kept, st = corpus.dedup([a, b, c], near_threshold=0.7)
    groups = {r.text[-7:]: r.group for r in kept}
    assert len(kept) == 3 and kept[0].group == kept[1].group != kept[2].group
    assert st["near_duplicates_grouped"] == 1 and groups


def test_split_is_leak_free_and_stratified():
    recs, _ = corpus.dedup(_recs())
    sp = corpus.split_by_cluster(recs, val_frac=0.15, test_frac=0.2, seed=1)
    corpus.assert_no_leak(sp)
    assert len(sp.train) + len(sp.val) + len(sp.test) == len(recs)
    for part in (sp.train, sp.val, sp.test):
        assert {r.label for r in part} == {0, 1}


def test_split_deterministic():
    recs, _ = corpus.dedup(_recs())
    a = corpus.split_by_cluster(recs, seed=5)
    b = corpus.split_by_cluster(recs, seed=5)
    assert [r.text for r in a.test] == [r.text for r in b.test]


def test_assert_no_leak_catches_overlap():
    r = Record("same text appears in both train and test partitions of the data", 1, "x", "c1")
    other = Record("another unrelated text for the validation set only here", 0, "x", "c2")
    with pytest.raises(AssertionError):
        corpus.assert_no_leak(corpus.Split([r], [other], [Record(r.text, 1, "y", "c9")]))
    with pytest.raises(AssertionError):
        corpus.assert_no_leak(corpus.Split([r], [other], [Record("different text but the same near-duplicate cluster id", 1, "y", "c1")]))


def test_split_by_source_keeps_source_out_of_train():
    recs, _ = corpus.dedup(_recs())
    sp = corpus.split_by_source(recs, {"a"})
    assert {r.source for r in sp.test} == {"a"}
    assert "a" not in {r.source for r in sp.train + sp.val}
    corpus.assert_no_leak(sp)
    with pytest.raises(ValueError):
        corpus.split_by_source(recs, {"nonexistent"})


def test_save_load_and_tamper_detection(tmp_path):
    recs, _ = corpus.dedup(_recs())
    sp = corpus.split_by_cluster(recs)
    manifest = corpus.save_split(sp, tmp_path / "out")
    assert manifest["files"]["test"]["n"] == len(sp.test)
    back = corpus.load_split(tmp_path / "out")
    assert [r.text for r in back.test] == [r.text for r in sp.test]
    with open(tmp_path / "out" / "test.csv", "a", encoding="utf-8") as fh:
        fh.write("extra,1,x,c0\n")
    with pytest.raises(ValueError):
        corpus.load_split(tmp_path / "out")


def test_parse_spec_handles_windows_paths():
    assert corpus._parse_spec(r"C:\data\nazario.mbox:nazario:1", None) == (r"C:\data\nazario.mbox", "nazario", 1)
    assert corpus._parse_spec("mine.csv:mine", None) == ("mine.csv", "mine", None)
    assert corpus._parse_spec("enron.csv:enron", 0) == ("enron.csv", "enron", 0)
    with pytest.raises(ValueError):
        corpus._parse_spec("justapath", None)


def test_urls_to_feed_filters_and_dedups():
    out = corpus.urls_to_feed(['"http://a.xyz/x"', "http://a.xyz/x", "not a url", "https://b.top/y", ""])
    assert out == ["http://a.xyz/x", "https://b.top/y"]
