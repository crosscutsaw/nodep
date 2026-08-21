#!/usr/bin/env python3
import os
import re
import io
import gzip
import lzma
import tarfile
import subprocess
import sys
import platform
import functools
import urllib.request
import urllib.parse
from html.parser import HTMLParser

BASE = "https://kali.download/kali/pool"
SECTIONS = ["main", "non-free", "contrib", "non-free-firmware"]
PKG_SEARCH = "https://pkg.kali.org/search"
VERSION = "0.1"
BOLD_BLUE = "\033[1;34m"
WHITE = "\033[0;37m"
RESET = "\033[0m"

def get_arch():
    machine = platform.machine()
    mapping = {
        "x86_64": "amd64",
        "aarch64": "arm64",
        "armv7l": "armhf",
        "i686": "i386",
        "i386": "i386",
    }
    if machine in mapping:
        return mapping[machine]
    try:
        out = subprocess.check_output(["dpkg", "--print-architecture"]).decode().strip()
        if out:
            return out
    except Exception:
        pass
    return machine

def resolve_source_name(pkgname):
    url = f"{PKG_SEARCH}?package_name={urllib.parse.quote(pkgname)}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            final_url = resp.geturl()
            html = resp.read().decode(errors="ignore")
        m = re.search(r"/pkg/([a-zA-Z0-9.+\-]+)", final_url)
        if m:
            return m.group(1)
        m2 = re.search(r'href="/pkg/([a-zA-Z0-9.+\-]+)"', html)
        if m2:
            return m2.group(1)
    except Exception:
        pass
    return pkgname

class LinkParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            for k, v in attrs:
                if k == "href":
                    self.links.append(v)

def fetch_listing(pkgname):
    source = resolve_source_name(pkgname)
    if source.startswith("lib") and len(source) > 3:
        letter = "lib" + source[3]
    else:
        letter = source[0:1]
    letter = letter.lower()
    for section in SECTIONS:
        url = f"{BASE}/{section}/{letter}/{source}/"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                html = resp.read().decode(errors="ignore")
            parser = LinkParser()
            parser.feed(html)
            files = [l for l in parser.links if not l.endswith("/") and not l.startswith("?")]
            if files:
                return url, files, source
        except Exception:
            continue
    return None, [], source

def pick_version_for_arch(files, arch, pkgname):
    prefix = pkgname + "_"
    candidates = [f for f in files if f.startswith(prefix) and f.endswith(f"_{arch}.deb")]
    if not candidates:
        candidates = [f for f in files if f.startswith(prefix) and f.endswith(".deb")]
    return candidates

def extract_version(fname, pkgname, arch):
    unq = urllib.parse.unquote(fname)
    m = re.match(rf"^{re.escape(pkgname)}_(.+)_{re.escape(arch)}\.deb$", unq)
    if m:
        return m.group(1)
    return None

def dpkg_compare_gt(v1, v2):
    try:
        subprocess.check_call(["dpkg", "--compare-versions", v1, "gt", v2], stderr=subprocess.DEVNULL)
        return 1
    except subprocess.CalledProcessError:
        pass
    try:
        subprocess.check_call(["dpkg", "--compare-versions", v1, "eq", v2], stderr=subprocess.DEVNULL)
        return 0
    except subprocess.CalledProcessError:
        return -1
    except Exception:
        return 0

def pick_best_candidate(candidates, pkgname, arch, constraints):
    versioned = [(extract_version(c, pkgname, arch), c) for c in candidates]
    versioned = [(v, c) for v, c in versioned if v]
    if not versioned:
        return sorted(candidates)[-1] if candidates else None

    if constraints:
        matching = []
        for v, c in versioned:
            ok = True
            for op, req in constraints:
                if not version_satisfies(v, op, req):
                    ok = False
                    break
            if ok:
                matching.append((v, c))
        if matching:
            versioned = matching

    versioned.sort(key=functools.cmp_to_key(lambda a, b: dpkg_compare_gt(a[0], b[0])))
    return versioned[-1][1]

def download_file(url, dest):
    print(f"downloading {url}")
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        data = resp.read()
    with open(dest, "wb") as f:
        f.write(data)
    print(f"saved to {dest}")

def version_satisfies(candidate, op, required):
    if not op or not required:
        return True
    try:
        subprocess.check_call(
            ["dpkg", "--compare-versions", candidate, op, required],
            stderr=subprocess.DEVNULL
        )
        return True
    except subprocess.CalledProcessError:
        return False
    except Exception:
        return False

CRITICAL_PACKAGES = {"libc6", "libc6-dev", "libstdc++6", "base-files"}

def get_installed_version(pkgname):
    try:
        out = subprocess.check_output(
            ["dpkg-query", "-W", "-f=${Version}", pkgname],
            stderr=subprocess.DEVNULL
        ).decode().strip()
        return out or None
    except Exception:
        return None

def check_compatibility(depends):
    problems = []
    for dep, constraints in depends.items():
        installed = get_installed_version(dep)
        if installed is None or not constraints:
            continue
        for op, ver in constraints:
            if not version_satisfies(installed, op, ver):
                problems.append({
                    "package": dep,
                    "needs": f"{op} {ver}",
                    "installed": installed,
                    "critical": dep in CRITICAL_PACKAGES
                })
    return problems

def parse_depends_text(control_text):
    depends_lines = []
    for line in control_text.splitlines():
        line = line.strip()
        if line.startswith("Depends:"):
            depends_lines.append(line[len("Depends:"):].strip())
        elif line.startswith("Pre-Depends:"):
            depends_lines.append(line[len("Pre-Depends:"):].strip())
    if not depends_lines:
        return {}
    parts = []
    for dl in depends_lines:
        parts.extend(dl.split(","))
    deps = {}
    op_map = {">=": ">=", "<=": "<=", "=": "=", ">>": ">>", "<<": "<<"}
    for p in parts:
        p = p.strip()
        if not p:
            continue
        alt = p.split("|")[0].strip()
        m = re.match(r"^([a-zA-Z0-9.+\-]+)(?:\s*\(([><=]+)\s*([^)]+)\))?", alt)
        if not m:
            continue
        name = m.group(1)
        op = m.group(2)
        ver = m.group(3)
        if name not in deps:
            deps[name] = []
        if op and ver:
            op = op_map.get(op, op)
            deps[name].append((op, ver.strip()))
    return deps

def peek_depends(url, budget=6 * 1024 * 1024):
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "Mozilla/5.0", "Range": f"bytes=0-{budget - 1}"}
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = resp.read()
    except Exception:
        return None

    if not data.startswith(b"!<arch>\n"):
        return None

    pos = 8
    control_data = None
    control_name = None
    while pos + 60 <= len(data):
        header = data[pos:pos + 60]
        name = header[0:16].decode(errors="ignore").strip()
        size_str = header[48:58].decode(errors="ignore").strip()
        try:
            size = int(size_str)
        except ValueError:
            break
        member_start = pos + 60
        member_end = member_start + size
        if member_end > len(data):
            return None
        if name.startswith("control.tar"):
            control_data = data[member_start:member_end]
            control_name = name
            break
        pos = member_end
        if pos % 2 == 1:
            pos += 1

    if control_data is None:
        return None

    try:
        if control_name.endswith(".gz"):
            raw = gzip.decompress(control_data)
        elif control_name.endswith(".xz"):
            raw = lzma.decompress(control_data)
        else:
            return None
    except Exception:
        return None

    try:
        tf = tarfile.open(fileobj=io.BytesIO(raw))
        for member in tf.getmembers():
            if member.name in ("./control", "control"):
                f = tf.extractfile(member)
                text = f.read().decode(errors="ignore")
                return parse_depends_text(text)
    except Exception:
        return None
    return None

def get_apt_candidate(pkgname):
    try:
        out = subprocess.check_output(
            ["apt-cache", "policy", pkgname],
            stderr=subprocess.DEVNULL
        ).decode(errors="ignore")
    except Exception:
        return None
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("Candidate:"):
            ver = line[len("Candidate:"):].strip()
            if ver and ver != "(none)":
                return ver
    return None

def get_deb_version(path):
    try:
        out = subprocess.check_output(["dpkg-deb", "-f", path, "Version"]).decode().strip()
        return out or None
    except Exception:
        return None

def get_depends(deb_path):
    out = subprocess.check_output(["dpkg", "-I", deb_path]).decode(errors="ignore")
    return parse_depends_text(out)

def main():
    print(f"\n{BOLD_BLUE}nodep v{VERSION}{RESET}\n")
    print(f"{WHITE}you may wipe ~/.nodep folder after everything is done{RESET}\n")

    arch = get_arch()
    print(f"detected architecture: {arch}")

    pkgname = input("enter full package name (e.g. metasploit-framework): ").strip()
    if not pkgname:
        print("no package name given, exiting")
        sys.exit(1)

    base_url, files, source = fetch_listing(pkgname)
    if not base_url:
        print(f"could not find {pkgname} in any pool section")
        sys.exit(1)

    print(f"found package at {base_url}")

    candidates = pick_version_for_arch(files, arch, pkgname)
    if not candidates:
        print("no matching .deb files found for this package")
        sys.exit(1)

    print("checking compatibility of each version against your system (no full download yet)")
    tags = {}
    for c in candidates:
        peeked = peek_depends(base_url + c)
        if peeked is None:
            tags[c] = "unknown, could not peek at package metadata"
            continue
        problems = check_compatibility(peeked)
        if not problems:
            tags[c] = "ok"
        else:
            critical_hit = any(p["critical"] for p in problems)
            if critical_hit:
                bad = ", ".join(p["package"] for p in problems if p["critical"])
                tags[c] = f"NOT COMPATIBLE, needs newer {bad} than your system has"
            else:
                bad = ", ".join(p["package"] for p in problems)
                tags[c] = f"warning, version mismatch on {bad}"

    print("available versions:")
    for i, c in enumerate(candidates):
        print(f"[{i}] {c}  -  {tags.get(c, 'unknown')}")

    home = os.path.expanduser("~")
    workdir = os.path.join(home, ".nodep", pkgname)
    depends_dir = os.path.join(workdir, "depends")
    os.makedirs(workdir, exist_ok=True)
    os.makedirs(depends_dir, exist_ok=True)

    chosen = None
    deb_path = None
    depends = {}

    while True:
        choice = input("pick the file to install: ").strip()
        try:
            idx = int(choice)
            candidate = candidates[idx]
        except (ValueError, IndexError):
            matched = [c for c in candidates if c == choice]
            if not matched:
                print("invalid selection")
                continue
            candidate = matched[0]

        candidate_path = os.path.join(workdir, candidate)
        download_file(base_url + candidate, candidate_path)

        print("confirming dependencies against what's installed")
        candidate_depends = get_depends(candidate_path)
        problems = check_compatibility(candidate_depends)

        if problems:
            print(f"\nfinal check: this version does not look compatible with your system:")
            for p in problems:
                tag = "CRITICAL" if p["critical"] else "warning"
                print(f"  [{tag}] {p['package']} needs {p['needs']}, you have {p['installed']}")

            critical_hit = any(p["critical"] for p in problems)
            if critical_hit:
                print("this involves core system libraries (libc6/libstdc++6/base-files),")
                print("forcing this could break dpkg/apt and other software on this box")

            proceed = input("continue anyway? [y/N]: ").strip().lower()
            if proceed != "y":
                print("picking a different version")
                continue

        chosen = candidate
        deb_path = candidate_path
        depends = candidate_depends
        break

    print("reading dependencies from package")
    if not depends:
        print("no dependencies listed")
    else:
        print(f"found {len(depends)} dependencies: {', '.join(depends)}")

    print("refreshing apt package lists")
    subprocess.run(["apt-get", "update"])

    NEVER_TOUCH = {"libc6", "libc6-dev", "libc-bin", "locales", "libc-l10n", "libc-gconv-modules-extra"}
    VIRTUAL_ABI_SUFFIXES = ("-api-min", "-api-max")
    VIRTUAL_IGNORE_SUFFIXES = ("-supported-min", "-supported-max")
    MAX_DEPTH = 1

    MAX_PACKAGES = 250
    MAX_ITERATIONS = 3000
    resolved = {}
    apt_packages = set()
    decision_version = {}
    constraints_seen = {}
    failed = set()
    failed_signature = {}
    processed_count = 0
    total_iterations = 0
    queue = [(name, cons, 0) for name, cons in depends.items()]

    while queue:
        total_iterations += 1
        if total_iterations > MAX_ITERATIONS:
            print(f"hit the {MAX_ITERATIONS} iteration safety cap, something is looping, stopping")
            break

        if processed_count >= MAX_PACKAGES:
            print(f"hit the {MAX_PACKAGES} package safety cap, stopping resolution early")
            break

        dep, constraints, depth = queue.pop(0)

        if dep in NEVER_TOUCH:
            print(f"resolving {dep}\n  core system package, leaving it as installed and not upgrading")
            installed = get_installed_version(dep)
            if installed is not None:
                decision_version[dep] = installed
            continue

        if dep.endswith(VIRTUAL_IGNORE_SUFFIXES):
            print(f"resolving {dep}\n  virtual version marker, nothing to install, skipping")
            continue

        matched_suffix = next((s for s in VIRTUAL_ABI_SUFFIXES if dep.endswith(s)), None)
        if matched_suffix:
            real_name = dep[: -len(matched_suffix)]
            print(f"resolving {dep}\n  virtual ABI marker, resolving the real package {real_name} instead")
            queue.append((real_name, [], depth))
            continue

        prior = constraints_seen.get(dep, [])
        merged = prior + [c for c in constraints if c not in prior]
        constraints_seen[dep] = merged

        current_version = decision_version.get(dep)
        if current_version is not None and all(version_satisfies(current_version, op, ver) for op, ver in merged):
            continue

        if dep in failed and failed_signature.get(dep) == merged:
            continue

        processed_count += 1
        print(f"resolving {dep}")

        installed = get_installed_version(dep)
        if installed is not None and all(version_satisfies(installed, op, ver) for op, ver in merged):
            print(f"  already satisfied by installed version {installed}, skipping")
            decision_version[dep] = installed
            failed.discard(dep)
            continue

        apt_candidate = get_apt_candidate(dep)
        if apt_candidate is not None and all(version_satisfies(apt_candidate, op, ver) for op, ver in merged):
            print(f"  debian apt has {apt_candidate}, letting apt handle it")
            apt_packages.add(dep)
            decision_version[dep] = apt_candidate
            failed.discard(dep)
            continue

        dep_url, dep_files, dep_source = fetch_listing(dep)
        if not dep_url:
            print(f"  not found on kali mirror (source resolved to '{dep_source}'), skipping")
            failed.add(dep)
            failed_signature[dep] = merged
            continue

        if dep_source != dep:
            print(f"  built from source package {dep_source}")

        dep_candidates = pick_version_for_arch(dep_files, arch, dep)
        if not dep_candidates:
            print(f"  no {arch} build found in {dep_source} pool, skipping")
            failed.add(dep)
            failed_signature[dep] = merged
            continue

        chosen_dep = pick_best_candidate(dep_candidates, dep, arch, merged)
        if not chosen_dep:
            print(f"  could not pick a version, skipping")
            failed.add(dep)
            failed_signature[dep] = merged
            continue

        dep_dest = os.path.join(depends_dir, chosen_dep)
        if os.path.exists(dep_dest):
            print(f"  already have {chosen_dep}")
        else:
            download_file(dep_url + chosen_dep, dep_dest)

        chosen_version = get_deb_version(dep_dest) or extract_version(chosen_dep, dep, arch) or "0"
        decision_version[dep] = chosen_version
        resolved[dep] = dep_dest
        failed.discard(dep)

        if depth >= MAX_DEPTH:
            continue

        sub_depends = get_depends(dep_dest)
        for sub_name, sub_constraints in sub_depends.items():
            queue.append((sub_name, sub_constraints, depth + 1))

    print(f"\nresolved {len(resolved)} packages from the kali mirror")
    if apt_packages:
        print(f"{len(apt_packages)} packages will come from debian apt")
    if failed:
        print(f"could not resolve anywhere: {', '.join(sorted(failed))}")

    if apt_packages:
        print("\ninstalling the apt-available packages first, apt resolves their own trees")
        subprocess.run(["apt-get", "install", "-y", "--no-install-recommends"] + sorted(apt_packages))

    all_debs = [deb_path] + list(resolved.values())
    print(f"\ninstalling {len(all_debs)} kali packages")

    max_passes = 3
    for i in range(max_passes):
        print(f"\ninstall pass {i + 1} of {max_passes}")
        result = subprocess.run(["dpkg", "-i"] + all_debs)
        if result.returncode == 0:
            print("dpkg reported no errors, stopping here")
            break
        print("some packages still blocked, retrying now that more of the batch is unpacked")

    print("\nrunning a final configure pass to settle anything left pending")
    subprocess.run(["dpkg", "--configure", "-a"])
    subprocess.run(["apt-get", "install", "-f", "-y"])

    print("done")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\ninterrupted, exiting")
        sys.exit(130)