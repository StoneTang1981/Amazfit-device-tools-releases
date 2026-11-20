"""Refresh the two online TUF roles of the public release feed."""
import argparse
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import time
from urllib.request import Request, urlopen
import zipfile

from cryptography.hazmat.primitives.serialization import load_pem_private_key
from securesystemslib.signer import CryptoSigner
from tuf.api.metadata import Metadata, MetaFile, Snapshot, Timestamp

REPO = "StoneTang1981/Amazfit-device-tools-releases"
WEB = "https://github.com/" + REPO
CATALOG = "device-tools-update-metadata.zip"
LIMIT = 2 * 1024 * 1024
CHECKPOINT = Path("stable") / CATALOG
ROOT = Metadata.from_file(str(Path(__file__).with_name("root.json")))
ASSETS = {f"Device_Tools-{arch}.zip" for arch in ("windows-amd64", "macos-arm64", "macos-x86_64")}


def read(url):
    req = Request(url, headers={"User-Agent": "Device-Tools-release-feed", "Cache-Control": "no-cache"})
    with urlopen(req, timeout=40) as response:
        data = response.read(LIMIT + 1)
    if len(data) > LIMIT:
        raise ValueError("Oversized response")
    return data


def latest():
    return json.loads(gh("api", f"repos/{REPO}/releases/latest?check={time.time_ns()}"))


def download(tag):
    return read(f"{WEB}/releases/download/{tag}/{CATALOG}")


def verify(raw):
    # Authenticate the entire previous chain even if its online roles have expired.
    if ROOT.signed.is_expired():
        raise ValueError("Offline root authorization expired")
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        entries = archive.infolist()
        if len(entries) > 64 or sum(e.file_size for e in entries) > LIMIT or len(set(archive.namelist())) != len(entries):
            raise ValueError("Malformed catalog archive")
        files = {e.filename: archive.read(e) for e in entries}
    roles = {}
    blobs = {}
    def role(name, path, pointer=None):
        data = files.pop(path)
        if pointer is not None:
            if not pointer.hashes or "sha256" not in pointer.hashes or pointer.length is None:
                raise ValueError("Missing signed digest or length")
            pointer.verify_length_and_hashes(data)
        md = Metadata.from_bytes(data)
        if md.signed.type != name or (pointer and md.signed.version != pointer.version):
            raise ValueError("Role or revision mismatch")
        ROOT.verify_delegate(name, md)
        roles[name], blobs[name] = md.signed, data
        return md.signed
    timestamp = role("timestamp", "timestamp.json")
    snap = timestamp.snapshot_meta
    targets = role("snapshot", f"{snap.version}.snapshot.json", snap).meta["targets.json"]
    role("targets", f"{targets.version}.targets.json", targets)
    if files:
        raise ValueError("Unexpected metadata; review the offline root before changing the feed format")
    return roles, blobs


def gh(*args):
    return subprocess.check_output(["gh", *args], text=True).strip()


def state_matches(plan):
    current = latest()
    if current["id"] != plan["id"] or hashlib.sha256(download(current["tag_name"])).hexdigest() != plan["digest"]:
        raise ValueError("Stable release changed; rerun against the new catalog")


def plan(folder, force):
    release = json.loads((folder / "latest.json").read_text())
    tag = release["tag_name"]
    match = re.fullmatch(r"V(\d+\.\d+\.\d+)(?:-(feed|withdraw)\.\d+)?", tag)
    if not match or release["draft"] or release["prerelease"]:
        raise ValueError("Unexpected stable release")
    raw = download(tag)
    roles, blobs = verify(raw)
    if CHECKPOINT.exists():
        old_roles, old_blobs = verify(CHECKPOINT.read_bytes())
        for name, role in roles.items():
            before = old_roles[name].version
            if role.version < before or (role.version == before and blobs[name] != old_blobs[name]):
                raise ValueError("Rollback or conflicting metadata revision")
    now = datetime.now(timezone.utc)
    targets = roles["targets"]
    if targets.is_expired():
        raise ValueError("Offline target authorization expired")
    if targets.expires <= now + timedelta(days=30):
        print("::warning::Offline target authorization expires " + targets.expires.isoformat())
    version = match[1]
    notes = set()
    if targets.targets:
        if match[2] == "withdraw" or set(targets.targets) != ASSETS:
            raise ValueError("Release tag or target list mismatch")
        for name, target in targets.targets.items():
            info = target.custom
            if (info["product"], info["version"], info["channel"], name) != (
                    "device-tools", version, "stable", f"Device_Tools-{info['platform']}.zip"):
                raise ValueError("Invalid release identity")
            notes.add(info["notes"])
        if len(notes) != 1:
            raise ValueError("Inconsistent release notes")
        body = notes.pop() + f"\n\n[下载 V{version}]({WEB}/releases/tag/V{version})"
    else:
        body = release["body"] or f"V{version} 已撤回。"
    plan_data = {"id": release["id"], "tag": tag, "digest": hashlib.sha256(raw).hexdigest()}
    output = folder / CATALOG
    if force or min(roles[n].expires for n in ("timestamp", "snapshot")) <= now + timedelta(days=3):
        rev = max(int(now.timestamp()), 1 + max(r.version for r in roles.values()))
        def sign(name, signed):
            key = CryptoSigner(load_pem_private_key(os.environ[f"TUF_{name.upper()}_KEY"].encode(), password=None))
            result = Metadata(signed)
            result.sign(key)
            ROOT.verify_delegate(name, result)
            return result.to_bytes()
        ref = MetaFile.from_data(targets.version, blobs["targets"], ["sha256"])
        snap = sign("snapshot", Snapshot(version=rev, expires=now + timedelta(days=30), meta={"targets.json": ref}))
        ts = sign("timestamp", Timestamp(version=rev, expires=now + timedelta(days=7),
                                        snapshot_meta=MetaFile.from_data(rev, snap, ["sha256"])))
        with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr(f"{targets.version}.targets.json", blobs["targets"])
            archive.writestr(f"{rev}.snapshot.json", snap)
            archive.writestr("timestamp.json", ts)
        signed, checked = verify(output.read_bytes())
        if signed["timestamp"].is_expired() or checked["targets"] != blobs["targets"]:
            raise ValueError("Invalid renewal")
        plan_data["candidate"] = f"V{version}-feed.{rev}"
        (folder / "notes.md").write_text(body, encoding="utf-8")
        print("Prepared", plan_data["candidate"], "valid through", signed["timestamp"].expires)
    else:
        output.write_bytes(raw)
        print("No renewal due. Timestamp valid through", roles["timestamp"].expires)
    (folder / "plan.json").write_text(json.dumps(plan_data))


def publish(folder):
    data = json.loads((folder / "plan.json").read_text())
    output = folder / CATALOG
    payload = output.read_bytes()
    candidate = data.get("candidate")
    state_matches(data)
    if candidate:
        gh("release", "create", candidate, str(output), "--repo", REPO, "--draft", "--target", "main",
           "--title", candidate, "--notes-file", str(folder / "notes.md"))
        gh("release", "edit", candidate, "--repo", REPO, "--draft=false", "--latest=false")
        for attempt in range(5):
            try:
                if download(candidate) == payload:
                    break
            except OSError:
                pass
            time.sleep(3)
        else:
            raise RuntimeError("Public candidate download did not verify")
        state_matches(data)
        gh("release", "edit", candidate, "--repo", REPO, "--latest")
    stable = candidate or data["tag"]
    for attempt in range(6):
        if latest()["tag_name"] == stable and read(f"{WEB}/releases/latest/download/{CATALOG}?check={time.time_ns()}") == payload:
            break
        time.sleep(4)
    else:
        raise RuntimeError("Anonymous stable entry did not verify")
    print("Verified anonymous stable catalog:", stable)
    # Record each distinct signed catalog on main for rollback detection and recovery.
    if not CHECKPOINT.exists() or CHECKPOINT.read_bytes() != payload:
        endpoint = f"repos/{REPO}/contents/{CHECKPOINT.as_posix()}"
        args = ["api", endpoint, "-X", "PUT", "-f", "branch=main", "-f", f"message=Record signed catalog {stable}",
                "-f", "content=" + base64.b64encode(payload).decode()]
        if CHECKPOINT.exists():
            previous = CHECKPOINT.read_bytes()
            blob = hashlib.sha1(f"blob {len(previous)}\0".encode() + previous).hexdigest()
            args.extend(["-f", "sha=" + blob])
        gh(*args)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["plan", "publish"])
    parser.add_argument("folder", type=Path)
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()
    args.folder.mkdir(parents=True, exist_ok=True)
    if args.action == "plan":
        plan(args.folder, args.force)
    else:
        publish(args.folder)
