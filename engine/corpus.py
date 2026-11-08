"""Data pipeline: alag alag public datasets ko ek format mein jodna, duplicates hatana, aur
train/val/test is tarah banana ke test ka koi email (ya uska near-duplicate) train mein na jaye.

Kaam ka silsila:
  1. load_*  : har source ko list[Record] mein badlo (text, label, source, group)
  2. dedup   : exact + near-duplicate (MinHash/LSH) hatao. Near-duplicates ek cluster ban jate hain
  3. split   : cluster-level split (poora cluster ek hi taraf), ya source-level (alag source test mein)
  4. save    : train.csv / val.csv / test.csv + manifest.json (counts + sha256, taake test file
               chupke se badli na jaye)

CLI:
  python -m engine.corpus build --out data/ \\
      --csv my_reported.csv:mine \\
      --mbox nazario_2022.mbox:nazario:1 \\
      --spamassassin-dir easy_ham:spamassassin:0 --spamassassin-dir spam:spamassassin:1 \\
      --enron-csv enron.csv:enron:0
  Format: PATH:SOURCE[:LABEL]  (LABEL 1=phishing/spam, 0=legit; csv mein label column se bhi aa sakta hai)

URL-only feeds (PhishTank/OpenPhish) email text nahi hain, text model ko unse train NAHI karte;
unhe `urls-to-feed` se LocalFeed file banao (reputation layer ke liye)."""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import mailbox
import random
import re
import sys
from collections import Counter, defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from email import policy
from email.message import Message
from email.parser import BytesParser
from pathlib import Path

from engine.ml import prepare_text

csv.field_size_limit(min(sys.maxsize, 2**31 - 1))

POS_LABELS = {"1", "phishing", "phish", "spam", "malicious", "bad", "true", "yes"}
NEG_LABELS = {"0", "legit", "ham", "safe", "benign", "good", "false", "no", "legitimate"}
MIN_TEXT_CHARS = 20          # is se chhote "emails" (khali, sirf subject) kaam ke nahi
MAX_TEXT_CHARS = 20_000      # prepare_text bhi yahi cap lagata hai


@dataclass
class Record:
    text: str
    label: int          # 1 = phishing, 0 = legit
    source: str         # dataset ka naam (nazario, enron, mine...)
    group: str = ""     # near-duplicate cluster id (dedup ke baad bharta hai)


# ------------------------------------------------------------------ loaders
def parse_label(value: object) -> int:
    lab = str(value).strip().lower()
    if lab in POS_LABELS:
        return 1
    if lab in NEG_LABELS:
        return 0
    raise ValueError(f"label samajh nahi aaya: {value!r} (1/0, phishing/legit, spam/ham chalte hain)")


def _clean(text: str) -> str:
    text = re.sub(r"<(script|style)\b.*?</\1>", " ", text or "", flags=re.I | re.S)
    text = re.sub(r"<[^>]+>", " ", text)  # HTML tags; link ka text rehta hai
    return " ".join(text.split())[:MAX_TEXT_CHARS]


def message_text(msg: Message) -> str:
    """Subject + body (plain ko tarjeeh, warna HTML se tags hata kar). Attachments ignore."""
    subject = str(msg.get("subject", "") or "")
    plain, html = [], []
    parts = msg.walk() if msg.is_multipart() else [msg]
    for part in parts:
        if part.is_multipart() or part.get_content_disposition() == "attachment":
            continue
        ctype = part.get_content_type()
        if ctype not in ("text/plain", "text/html"):
            continue
        try:
            payload = part.get_content()
        except Exception:  # noqa: BLE001 - kharab encoding wali mails chhod do, poora load na ruke
            payload = (part.get_payload(decode=True) or b"").decode("utf-8", "replace")
        (plain if ctype == "text/plain" else html).append(str(payload))
    body = "\n".join(plain) if plain else "\n".join(html)
    return _clean(f"{subject}\n{body}")


def load_csv(path: str | Path, source: str, label: int | None = None) -> list[Record]:
    """Columns: `text` (ya `subject` + `body`), aur `label` (agar `label` argument na diya ho)."""
    out: list[Record] = []
    with open(path, newline="", encoding="utf-8", errors="replace") as fh:
        reader = csv.DictReader(fh)
        cols = {c.strip().lower(): c for c in (reader.fieldnames or [])}
        has_text = "text" in cols
        if not has_text and "body" not in cols:
            raise ValueError(f"{path}: 'text' (ya 'body') column chahiye, mile: {list(cols)}")
        if label is None and "label" not in cols:
            raise ValueError(f"{path}: 'label' column chahiye (ya PATH:SOURCE:LABEL do)")
        for row in reader:
            row = {k.strip().lower(): (v or "") for k, v in row.items() if k}
            raw = row["text"] if has_text else f"{row.get('subject', '')}\n{row['body']}"
            text = _clean(raw)
            if len(text) < MIN_TEXT_CHARS:
                continue
            out.append(Record(text, label if label is not None else parse_label(row["label"]), source))
    return out


def load_mbox(path: str | Path, source: str, label: int) -> list[Record]:
    """Nazario jaise mbox dumps."""
    out: list[Record] = []
    for msg in mailbox.mbox(str(path), factory=lambda f: BytesParser(policy=policy.default).parse(f)):
        text = message_text(msg)
        if len(text) >= MIN_TEXT_CHARS:
            out.append(Record(text, label, source))
    return out


def load_email_dir(path: str | Path, source: str, label: int) -> list[Record]:
    """SpamAssassin public corpus (har file ek raw email; `cmds` jaisi files chhod di jati hain)."""
    out: list[Record] = []
    parser = BytesParser(policy=policy.default)
    for f in sorted(Path(path).rglob("*")):
        if not f.is_file() or f.name == "cmds" or f.name.startswith("."):
            continue
        try:
            with open(f, "rb") as fh:
                msg = parser.parse(fh)
        except Exception:  # noqa: BLE001
            continue
        text = message_text(msg)
        if len(text) >= MIN_TEXT_CHARS:
            out.append(Record(text, label, source))
    return out


def load_enron_csv(path: str | Path, source: str = "enron", label: int = 0) -> list[Record]:
    """Enron: Kaggle jaise CSV mein aksar `message` (poori raw email) ya `file`+`message` hota hai.
    Raw message ko email parser se guzarte hain. (Enron legit corporate mail hai: label 0.)"""
    out: list[Record] = []
    parser = BytesParser(policy=policy.default)
    with open(path, newline="", encoding="utf-8", errors="replace") as fh:
        reader = csv.DictReader(fh)
        cols = {c.strip().lower(): c for c in (reader.fieldnames or [])}
        key = cols.get("message") or cols.get("text") or cols.get("body")
        if not key:
            raise ValueError(f"{path}: 'message' (ya text/body) column chahiye, mile: {list(cols)}")
        for row in reader:
            raw = row[key] or ""
            text = (message_text(parser.parsebytes(raw.encode("utf-8", "replace")))
                    if raw.lstrip().lower().startswith(("message-id:", "from:", "date:", "x-")) else _clean(raw))
            if len(text) >= MIN_TEXT_CHARS:
                out.append(Record(text, label, source))
    return out


def urls_to_feed(lines: Iterable[str]) -> list[str]:
    """PhishTank (CSV: `url` column) / OpenPhish (har line ek URL) ko LocalFeed.from_lines ki
    shakal mein badalta hai: sirf http(s) URLs, duplicates ke baghair."""
    seen: dict[str, None] = {}
    for line in lines:
        line = line.strip().strip('"')
        if line.lower().startswith(("http://", "https://")):
            seen.setdefault(line, None)
    return list(seen)


# ------------------------------------------------------------------ dedup
def _norm(text: str) -> str:
    # URLs/lambe numbers tokens ban jate hain, to sirf URL badal kar bani copies bhi pakdi jati hain
    return prepare_text(text)


def _shingles(norm: str, k: int = 5) -> set[int]:
    words = norm.split()
    if len(words) <= k:
        return {hash(tuple(words))} if words else set()
    return {hash(tuple(words[i:i + k])) for i in range(len(words) - k + 1)}


_MASK = (1 << 61) - 1
_PRIME = (1 << 61) - 1


def _minhash(shingles: set[int], seeds: list[tuple[int, int]]) -> tuple[int, ...]:
    return tuple(min(((a * s + b) % _PRIME) & _MASK for s in shingles) for a, b in seeds)


class _DSU:
    def __init__(self, n: int) -> None:
        self.p = list(range(n))

    def find(self, x: int) -> int:
        while self.p[x] != x:
            self.p[x] = self.p[self.p[x]]
            x = self.p[x]
        return x

    def union(self, a: int, b: int) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.p[max(ra, rb)] = min(ra, rb)


def dedup(records: list[Record], near_threshold: float = 0.8, num_perm: int = 64,
          bands: int = 16, seed: int = 7) -> tuple[list[Record], dict]:
    """(records, stats). Exact duplicates hata deta hai; near-duplicates (Jaccard >= near_threshold
    on 5-word shingles) ko ek `group` deta hai taake split mein wo kabhi alag taraf na jayen.

    PYTHONHASHSEED ka asar nahi: shingle hashes sirf is process ke andar mutaaliq hain."""
    if num_perm % bands:
        raise ValueError("num_perm bands se divisible hona chahiye")
    rng = random.Random(seed)  # noqa: S311
    seeds = [(rng.randrange(1, _PRIME), rng.randrange(0, _PRIME)) for _ in range(num_perm)]
    rows = num_perm // bands

    # 1) exact duplicates (normalised text par). Label alag hon to dono hata dete hain: ambiguous data.
    first: dict[str, int] = {}
    label_seen: dict[str, set[int]] = defaultdict(set)
    unique: list[Record] = []
    norms: list[str] = []
    exact_dropped = 0
    for r in records:
        n = _norm(r.text)
        if len(n) < MIN_TEXT_CHARS // 2:
            continue
        label_seen[n].add(r.label)
        if n in first:
            exact_dropped += 1
            continue
        first[n] = len(unique)
        unique.append(r)
        norms.append(n)
    conflict = {n for n, labs in label_seen.items() if len(labs) > 1}
    if conflict:
        keep = [i for i, n in enumerate(norms) if n not in conflict]
        unique, norms = [unique[i] for i in keep], [norms[i] for i in keep]

    # 2) near-duplicates: LSH banding + asli Jaccard check, phir union-find se cluster
    shing = [_shingles(n) for n in norms]
    sigs = [_minhash(s, seeds) if s else () for s in shing]
    dsu = _DSU(len(unique))
    for b in range(bands):
        buckets: dict[tuple[int, ...], list[int]] = defaultdict(list)
        for i, sig in enumerate(sigs):
            if sig:
                buckets[sig[b * rows:(b + 1) * rows]].append(i)
        for ids in buckets.values():
            if len(ids) < 2:
                continue
            # bohat bade bucket (boilerplate/template) mein O(n^2) se bachne ke liye har email sirf agle
            # WINDOW emails se milta hai. Union hamesha asli Jaccard check ke baad hota hai, band collision par nahi.
            window = len(ids) if len(ids) <= 200 else 25
            for x in range(len(ids)):
                for y in range(x + 1, min(len(ids), x + 1 + window)):
                    i, j = ids[x], ids[y]
                    if dsu.find(i) == dsu.find(j):
                        continue
                    inter = len(shing[i] & shing[j])
                    union = len(shing[i] | shing[j])
                    if union and inter / union >= near_threshold:
                        dsu.union(i, j)
    for i, r in enumerate(unique):
        r.group = f"c{dsu.find(i)}"
    clusters = Counter(r.group for r in unique)
    stats = {
        "input": len(records), "exact_duplicates_removed": exact_dropped,
        "label_conflicts_removed": len(conflict), "kept": len(unique),
        "clusters": len(clusters), "largest_cluster": max(clusters.values(), default=0),
        "near_duplicates_grouped": len(unique) - len(clusters),
    }
    return unique, stats


# ------------------------------------------------------------------ split
@dataclass
class Split:
    train: list[Record]
    val: list[Record]
    test: list[Record]


def split_by_cluster(records: list[Record], val_frac: float = 0.15, test_frac: float = 0.2,
                     seed: int = 42) -> Split:
    """Cluster-level, label-stratified split: ek cluster poora ek hi taraf jata hai, isliye test ka
    koi near-duplicate train mein nahi hota. Fractions records ke hisaab se (cluster size ka khayal)."""
    if not 0 < val_frac + test_frac < 1:
        raise ValueError("val_frac + test_frac 0 aur 1 ke beech hona chahiye")
    rng = random.Random(seed)  # noqa: S311
    buckets: dict[int, dict[str, list[Record]]] = {0: defaultdict(list), 1: defaultdict(list)}
    for r in records:
        buckets[r.label][r.group or f"solo{id(r)}"].append(r)
    out = {"train": [], "val": [], "test": []}
    for label, clusters in buckets.items():
        ids = sorted(clusters)
        rng.shuffle(ids)
        total = sum(len(clusters[c]) for c in ids)
        targets = {"test": test_frac * total, "val": val_frac * total}
        got = {"test": 0, "val": 0}
        for cid in ids:
            members = clusters[cid]
            if got["test"] < targets["test"]:
                part = "test"
            elif got["val"] < targets["val"]:
                part = "val"
            else:
                part = "train"
            if part != "train":
                got[part] += len(members)
            out[part].extend(members)
    for part in out.values():
        rng.shuffle(part)
    return Split(out["train"], out["val"], out["test"])


def split_by_source(records: list[Record], test_sources: set[str], val_frac: float = 0.15,
                    seed: int = 42) -> Split:
    """Poore sources test mein (jaise nazario test, baqi train). Ye sab se sakht aur sab se
    haqeeqi test hai: model ne wo dataset kabhi dekha hi nahi. Val train sources se cluster-split."""
    test = [r for r in records if r.source in test_sources]
    rest = [r for r in records if r.source not in test_sources]
    if not test:
        raise ValueError(f"test_sources {sorted(test_sources)} mein koi record nahi mila")
    inner = split_by_cluster(rest, val_frac=val_frac, test_frac=0.0001, seed=seed)
    # test_frac ~0: inner.test 1 cluster tak ho sakta hai, usay train mein wapas daal do
    return Split(inner.train + inner.test, inner.val, test)


def assert_no_leak(split: Split) -> None:
    """Ek hi cheez ka test: train/val/test mein koi cluster ya normalised text common nahi."""
    sets = {name: ({r.group for r in part if r.group}, {_norm(r.text) for r in part})
            for name, part in (("train", split.train), ("val", split.val), ("test", split.test))}
    for a, b in (("train", "val"), ("train", "test"), ("val", "test")):
        shared_groups = sets[a][0] & sets[b][0]
        shared_texts = sets[a][1] & sets[b][1]
        if shared_groups or shared_texts:
            raise AssertionError(f"LEAK {a}/{b}: {len(shared_groups)} clusters, {len(shared_texts)} texts common")


# ------------------------------------------------------------------ save / load
FIELDS = ["text", "label", "source", "group"]


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save_split(split: Split, out_dir: str | Path, extra: dict | None = None) -> dict:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    manifest: dict = {"files": {}, **(extra or {})}
    for name, part in (("train", split.train), ("val", split.val), ("test", split.test)):
        path = out / f"{name}.csv"
        with open(path, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(FIELDS)
            w.writerows([r.text, r.label, r.source, r.group] for r in part)
        manifest["files"][name] = {
            "n": len(part), "phishing": sum(r.label for r in part),
            "sources": dict(Counter(r.source for r in part)), "sha256": _sha(path),
        }
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2))
    return manifest


def load_split_csv(path: str | Path) -> list[Record]:
    out: list[Record] = []
    with open(path, newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            out.append(Record(row["text"], int(row["label"]), row.get("source", ""), row.get("group", "")))
    return out


def load_split(data_dir: str | Path, verify: bool = True) -> Split:
    """manifest ke sha256 se check karta hai ke split files badli nahi (test chupke se na badle)."""
    d = Path(data_dir)
    if verify and (d / "manifest.json").exists():
        manifest = json.loads((d / "manifest.json").read_text())
        for name, info in manifest["files"].items():
            if _sha(d / f"{name}.csv") != info["sha256"]:
                raise ValueError(f"{name}.csv badal gayi hai (manifest se sha256 match nahi karta)")
    return Split(load_split_csv(d / "train.csv"), load_split_csv(d / "val.csv"), load_split_csv(d / "test.csv"))


# ------------------------------------------------------------------ CLI
def _parse_spec(spec: str, default_label: int | None) -> tuple[str, str, int | None]:
    # PATH:SOURCE[:LABEL]. Windows paths (C:\...) ke liye aakhri 1-2 hisse peeche se uthate hain.
    parts = spec.split(":")
    label: int | None = default_label
    if len(parts) >= 3 and parts[-1] in ("0", "1"):
        label = int(parts[-1])
        parts = parts[:-1]
    if len(parts) < 2:
        raise ValueError(f"{spec!r}: PATH:SOURCE[:LABEL] chahiye")
    source = parts[-1]
    path = ":".join(parts[:-1])
    return path, source, label


def build_records(csvs: list[str], mboxes: list[str], sa_dirs: list[str], enron: list[str]) -> list[Record]:
    records: list[Record] = []
    for spec in csvs:
        path, source, label = _parse_spec(spec, None)
        records += load_csv(path, source, label)
    for spec in mboxes:
        path, source, label = _parse_spec(spec, None)
        if label is None:
            raise ValueError(f"{spec}: mbox ke liye label lazmi (PATH:SOURCE:1)")
        records += load_mbox(path, source, label)
    for spec in sa_dirs:
        path, source, label = _parse_spec(spec, None)
        if label is None:
            raise ValueError(f"{spec}: folder ke liye label lazmi (PATH:SOURCE:0 ya :1)")
        records += load_email_dir(path, source, label)
    for spec in enron:
        path, source, label = _parse_spec(spec, 0)
        records += load_enron_csv(path, source, label if label is not None else 0)
    return records


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build", help="sources jodo, dedup karo, leak-free split likho")
    b.add_argument("--out", required=True)
    b.add_argument("--csv", action="append", default=[], help="PATH:SOURCE[:LABEL]")
    b.add_argument("--mbox", action="append", default=[], help="PATH:SOURCE:LABEL")
    b.add_argument("--spamassassin-dir", action="append", default=[], help="PATH:SOURCE:LABEL")
    b.add_argument("--enron-csv", action="append", default=[], help="PATH:SOURCE[:LABEL]")
    b.add_argument("--test-source", action="append", default=[],
                   help="in sources ko poora test mein rakho (source-level split); warna cluster split")
    b.add_argument("--val-frac", type=float, default=0.15)
    b.add_argument("--test-frac", type=float, default=0.2)
    b.add_argument("--near-threshold", type=float, default=0.8)
    b.add_argument("--seed", type=int, default=42)
    u = sub.add_parser("urls-to-feed", help="PhishTank/OpenPhish URL list ko LocalFeed file banao")
    u.add_argument("input")
    u.add_argument("output")
    args = ap.parse_args(argv)

    if args.cmd == "urls-to-feed":
        with open(args.input, encoding="utf-8", errors="replace") as fh:
            lines = urls_to_feed(fh)
        Path(args.output).write_text("\n".join(lines) + "\n")
        print(f"{len(lines)} URLs -> {args.output}")
        return

    records = build_records(args.csv, args.mbox, args.spamassassin_dir, args.enron_csv)
    if not records:
        raise SystemExit("koi record load nahi hua: kam az kam ek --csv/--mbox/--spamassassin-dir/--enron-csv do")
    records, stats = dedup(records, near_threshold=args.near_threshold)
    if args.test_source:
        split = split_by_source(records, set(args.test_source), val_frac=args.val_frac, seed=args.seed)
        mode = f"source-level (test sources: {sorted(args.test_source)})"
    else:
        split = split_by_cluster(records, args.val_frac, args.test_frac, args.seed)
        mode = "cluster-level (random, near-duplicates ek taraf)"
    assert_no_leak(split)
    manifest = save_split(split, args.out, {"split_mode": mode, "seed": args.seed, "dedup": stats})
    print(json.dumps(manifest, indent=2))
    prev = sum(r.label for r in records) / len(records)
    print(f"\nphishing share (dedup ke baad): {prev:.1%}"
          "  <- asli inbox mein ye 1-2% hoti hai; evaluate mein --prevalence se adjust hota hai")


if __name__ == "__main__":
    main()
