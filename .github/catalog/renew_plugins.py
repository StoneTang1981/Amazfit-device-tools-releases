"""Renew the signed plugin index without moving the desktop release or replacing a ZIP."""
import argparse
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import time

from renew import REPO, annual_target, gh, next_check, read, sign_online, verify

INDEX = Path("stable/device-tools-map-plugins-metadata.zip")


def plan(folder, force):
    raw = INDEX.read_bytes()
    roles, blobs = verify(raw)
    now = datetime.now(timezone.utc)
    approved = annual_target(blobs["targets"], now)
    for name, target in roles["targets"].targets.items():
        info = target.custom
        if (info["product"] != "device-tools-map-plugin"
                or name != f"map-{info['kind']}-api{info['api']}-{info['platform']}.zip"):
            raise ValueError("Invalid plugin identity")
    if not roles["targets"].targets:
        raise ValueError("Empty plugin feed")
    if (force or approved != blobs["targets"]
            or min(roles[n].expires for n in ("timestamp", "snapshot")) <= next_check(now) + timedelta(hours=12)):
        rev, signed = sign_online(folder / INDEX.name, roles, approved, now)
        print("Prepared plugin renewal", rev, "valid through", signed["timestamp"].expires)
    else:
        print("Plugin catalog valid through", roles["timestamp"].expires)


def publish(folder):
    prior = INDEX.read_bytes()
    output = folder / INDEX.name
    payload = output.read_bytes() if output.exists() else prior
    endpoint = f"repos/{REPO}/contents/{INDEX.as_posix()}"
    if output.exists():
        old = verify(prior)[0]
        new = verify(payload)[0]
        if (new["timestamp"].version <= old["timestamp"].version
                or new["targets"].targets != old["targets"].targets):
            raise ValueError("Plugin renewal changed the authorized packages or rolled back")
        blob = hashlib.sha1(f"blob {len(prior)}\0".encode() + prior).hexdigest()
        gh("api", endpoint, "-X", "PUT", "-f", "branch=main", "-f", "sha=" + blob,
           "-f", "message=Renew signed map plugin catalog", "-f", "content=" + base64.b64encode(payload).decode())
    for attempt in range(6):
        url = f"https://raw.githubusercontent.com/{REPO}/main/{INDEX.as_posix()}?check={time.time_ns()}"
        try:
            if read(url) == payload:
                print("Verified anonymous plugin catalog and", len(verify(payload)[0]["targets"].targets), "targets")
                return
        except OSError:
            if attempt == 5:
                raise
        time.sleep(3)
    raise RuntimeError("Anonymous plugin catalog differs from the verified renewal")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("plan", "publish"))
    parser.add_argument("folder", type=Path)
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()
    args.folder.mkdir(parents=True, exist_ok=True)
    if args.action == "plan":
        plan(args.folder, args.force)
    else:
        publish(args.folder)
