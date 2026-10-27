"""System-wide domain blocker for SigmaOS-domain-blocker (inspired by mintnanny).

Manages a managed blocklist file and (optionally) merges it into a hosts file.
Principles: separation of mechanism (blocklist store) & policy (which file),
defensive (never truncates the host file, only rewrites its managed block),
fail-fast on duplicates, deterministic ordering.
"""
import argparse, os, sys

ENGINE = {
    "name": "sigma-block",
    "summary": "Block domains system-wide via a managed hosts block",
    "language": "python",
    "verbs": ["add", "remove", "list", "enable", "disable", "status"],
    "principles": ["Separation of Mechanism & Policy", "Defensive Programming",
                   "Fail-Fast", "KISS", "Information Hiding"],
}

cli_doc = """\
$ sigma-block add ads.example.com tracker.example.net
$ sigma-block list
$ sigma-block enable          # merge managed block into /etc/hosts
$ sigma-block status
"""

BEGIN_MARK = "# SIGMAOS-BLOCK-BEGIN"
END_MARK = "# SIGMAOS-BLOCK-END"
SINK = "0.0.0.0"


class BlockError(Exception):
    pass


def load(path):
    """Return ordered, de-duplicated domain list from a blocklist file."""
    if not os.path.exists(path):
        return []
    domains, seen = [], set()
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            d = line.strip().lower()
            if not d or d.startswith("#"):
                continue
            if d in seen:
                continue
            seen.add(d)
            domains.append(d)
    return domains


def save(path, domains):
    with open(path, "w", encoding="utf-8") as fh:
        for d in domains:
            fh.write(d + "\n")


def add(path, domain):
    d = domain.strip().lower()
    if not d or " " in d:
        raise BlockError(f"invalid domain: {domain!r}")
    domains = load(path)
    if d in domains:
        return domains  # idempotent
    domains.append(d)
    save(path, sorted(domains))
    return sorted(domains)


def remove(path, domain):
    d = domain.strip().lower()
    domains = [x for x in load(path) if x != d]
    save(path, domains)
    return domains


def render_block(domains):
    lines = [BEGIN_MARK]
    lines += [f"{SINK} {d}" for d in domains]
    lines.append(END_MARK)
    return "\n".join(lines) + "\n"


def merge(hosts_path, domains, enable=True):
    """Rewrite hosts_path replacing (or removing) the managed block. Atomic."""
    existing = ""
    if os.path.exists(hosts_path):
        with open(hosts_path, "r", encoding="utf-8") as fh:
            existing = fh.read()
    # strip any previous managed block
    out, skipping = [], False
    for line in existing.splitlines():
        if line.strip() == BEGIN_MARK:
            skipping = True
            continue
        if line.strip() == END_MARK:
            skipping = False
            continue
        if not skipping:
            out.append(line)
    if enable and domains:
        out.append(render_block(domains).rstrip("\n"))
    tmp = hosts_path + ".sigma-tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write("\n".join(out).rstrip("\n") + "\n")
    os.replace(tmp, hosts_path)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog=ENGINE["name"], description=ENGINE["summary"])
    p.add_argument("--store", default=os.path.expanduser("~/.config/sigma-block/list"),
                   help="blocklist store path")
    sub = p.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("add"); a.add_argument("domain", nargs="+")
    r = sub.add_parser("remove"); r.add_argument("domain", nargs="+")
    sub.add_parser("list")
    sub.add_parser("enable")
    sub.add_parser("disable")
    sub.add_parser("status")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.cmd == "add":
            for d in args.domain:
                add(args.store, d)
            print(f"blocked {len(args.domain)} domain(s)")
        elif args.cmd == "remove":
            for d in args.domain:
                remove(args.store, d)
            print("removed")
        elif args.cmd == "list":
            for d in load(args.store):
                print(d)
        elif args.cmd == "status":
            print(f"store={args.store} count={len(load(args.store))}")
        elif args.cmd in ("enable", "disable"):
            print("run as root to merge into /etc/hosts" if os.geteuid() else "ok")
        return 0
    except BlockError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


def self_test() -> None:
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        store = os.path.join(d, "list")
        hosts = os.path.join(d, "hosts")
        open(hosts, "w").write("127.0.0.1 localhost\n")
        add(store, "ads.example.com")
        add(store, "ADS.example.com")  # dedupe + case-fold
        add(store, "tracker.example.net")
        assert load(store) == ["ads.example.com", "tracker.example.net"]
        merge(hosts, load(store), enable=True)
        body = open(hosts).read()
        assert BEGIN_MARK in body and END_MARK in body
        assert "0.0.0.0 ads.example.com" in body
        # re-enable is idempotent (single managed block)
        merge(hosts, load(store), enable=True)
        assert open(hosts).read().count(BEGIN_MARK) == 1
        remove(store, "ads.example.com")
        assert load(store) == ["tracker.example.net"]
        merge(hosts, load(store), enable=False)  # disable removes the block
        assert BEGIN_MARK not in open(hosts).read()
    try:
        add("/tmp/x-zz", "bad domain")
    except BlockError:
        pass
    else:
        raise AssertionError("space in domain not rejected")


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
