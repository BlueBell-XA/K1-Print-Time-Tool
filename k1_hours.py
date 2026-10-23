#!/usr/bin/env python3
"""
Creality K1 persistent lifetime print-time utility.

Commands:
    python3 k1_hours.py                  # same as: read
    python3 k1_hours.py read
    python3 k1_hours.py set 250
    python3 k1_hours.py reset
    python3 k1_hours.py backup
    python3 k1_hours.py backups
    python3 k1_hours.py restore latest
    python3 k1_hours.py verify
    python3 k1_hours.py info

Global options:
    --dry-run       Show what a mutating command would do without writing.
    --no-reboot     Do not reboot automatically after set/reset/restore.
    -y, --yes       Skip interactive confirmation for set/reset/restore.
    --json          Emit machine-readable JSON.

This tool is intended to run as root on compatible Creality K1-series firmware.
It dynamically discovers the AES-128-CBC key and IV embedded in master-server,
validates decrypted data before accepting it, and fails without writing if the
firmware/data format is not recognised.
"""

import argparse
import base64
import ctypes
import glob
import json
import os
import re
import shutil
import subprocess
import sys
import time
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from pathlib import Path

MASTER_SERVER = "/usr/bin/master-server"
DATA_FILE = "/usr/data/creality/userdata/config/user_data_not_deleted.json"
BACKUP_PREFIX = "user_data_not_deleted.json.backup-"


class ToolError(RuntimeError):
    pass


def fail(message):
    raise ToolError(message)


def output_json(payload):
    print(json.dumps(payload, indent=2, sort_keys=True))


def format_duration(seconds):
    seconds = int(seconds)
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, secs = divmod(rem, 60)
    return {
        "seconds": seconds,
        "hours": seconds / 3600,
        "days": seconds / 86400,
        "exact": f"{days}d {hours}h {minutes}m {secs}s",
    }


def find_libcrypto():
    candidates = [
        "/usr/lib/libcrypto.so.1.1",
        "/usr/lib/libcrypto.so",
        "/lib/libcrypto.so.1.1",
        "/lib/libcrypto.so",
    ]
    candidates += sorted(glob.glob("/usr/lib/libcrypto.so*"))
    candidates += sorted(glob.glob("/lib/libcrypto.so*"))

    seen = set()
    for path in candidates:
        if path in seen or not os.path.isfile(path):
            continue
        seen.add(path)
        try:
            lib = ctypes.CDLL(path)
            getattr(lib, "AES_set_decrypt_key")
            getattr(lib, "AES_set_encrypt_key")
            getattr(lib, "AES_cbc_encrypt")
            return path, lib
        except Exception:
            continue

    fail("Could not find a usable OpenSSL libcrypto with AES functions.")


def configure_crypto(lib):
    lib.AES_set_decrypt_key.argtypes = [
        ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p
    ]
    lib.AES_set_decrypt_key.restype = ctypes.c_int

    lib.AES_set_encrypt_key.argtypes = [
        ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p
    ]
    lib.AES_set_encrypt_key.restype = ctypes.c_int

    lib.AES_cbc_encrypt.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_int,
    ]
    lib.AES_cbc_encrypt.restype = None


def aes_decrypt(lib, ciphertext, key, iv):
    if len(key) != 16 or len(iv) != 16:
        fail("AES-128 key and IV must both be 16 bytes.")
    if not ciphertext or len(ciphertext) % 16:
        fail("Ciphertext length is not a non-zero multiple of 16 bytes.")

    # OpenSSL 1.1.x AES_KEY is 244 bytes; allocate extra room defensively.
    aes_key = ctypes.create_string_buffer(512)
    output = ctypes.create_string_buffer(len(ciphertext))
    iv_buf = ctypes.create_string_buffer(iv, 16)

    if lib.AES_set_decrypt_key(key, 128, aes_key) != 0:
        fail("AES_set_decrypt_key failed.")

    lib.AES_cbc_encrypt(
        ciphertext, output, len(ciphertext), aes_key, iv_buf, 0
    )
    return output.raw


def aes_encrypt(lib, plaintext, key, iv):
    if len(key) != 16 or len(iv) != 16:
        fail("AES-128 key and IV must both be 16 bytes.")
    if not plaintext or len(plaintext) % 16:
        fail("Plaintext length is not a non-zero multiple of 16 bytes.")

    aes_key = ctypes.create_string_buffer(512)
    output = ctypes.create_string_buffer(len(plaintext))
    iv_buf = ctypes.create_string_buffer(iv, 16)

    if lib.AES_set_encrypt_key(key, 128, aes_key) != 0:
        fail("AES_set_encrypt_key failed.")

    lib.AES_cbc_encrypt(
        plaintext, output, len(plaintext), aes_key, iv_buf, 1
    )
    return output.raw


def parse_json_from_plaintext(raw):
    start = raw.find(b"{")
    if start < 0:
        return None

    # The known firmware stores a small JSON object followed by NUL/padding.
    end = raw.find(b"}", start)
    if end < 0:
        return None

    try:
        obj = json.loads(raw[start:end + 1].decode("utf-8"))
    except Exception:
        return None

    if (
        isinstance(obj, dict)
        and isinstance(obj.get("total_time"), int)
        and not isinstance(obj.get("total_time"), bool)
        and obj["total_time"] >= 0
    ):
        return obj

    return None


def extract_printable_strings(binary):
    strings = []
    for match in re.finditer(rb"[\x20-\x7e]{8,}", binary):
        try:
            strings.append((match.start(), match.group().decode("ascii")))
        except UnicodeDecodeError:
            continue
    return strings


def plausible_crypto_string(value):
    return (
        16 <= len(value) <= 100
        and re.fullmatch(r"[A-Za-z0-9]+", value) is not None
    )


def extract_candidate_strings(binary):
    strings = extract_printable_strings(binary)
    anchors = [
        offset
        for offset, value in strings
        if "encrypt error!" in value or "decrypt error!" in value
    ]

    # Prefer random-looking alphanumeric strings close to the encryption
    # routine. The tested K1 firmware stores the key/IV source strings here.
    nearby = []
    for anchor in anchors:
        for offset, value in strings:
            if abs(offset - anchor) <= 8192 and plausible_crypto_string(value):
                nearby.append(value)

    nearby = list(dict.fromkeys(nearby))
    if len(nearby) >= 2:
        return nearby

    # Fallback: wider scan if a firmware build moves the constants.
    fallback = [
        value
        for _, value in strings
        if 24 <= len(value) <= 100
        and re.fullmatch(r"[A-Za-z0-9]+", value) is not None
    ]

    # Avoid an unbounded O(n^2) search on an unexpected binary.
    return list(dict.fromkeys(fallback))[:256]


def decode_base64_file(path):
    try:
        encoded = Path(path).read_bytes().strip()
    except OSError as exc:
        fail(f"Could not read {path}: {exc}")

    try:
        ciphertext = base64.b64decode(encoded, validate=True)
    except Exception as exc:
        fail(f"{path} is not valid Base64: {exc}")

    if not ciphertext or len(ciphertext) % 16:
        fail(f"{path} does not contain valid AES block-aligned ciphertext.")

    return ciphertext


def discover_crypto(lib, ciphertext):
    try:
        binary = Path(MASTER_SERVER).read_bytes()
    except OSError as exc:
        fail(f"Could not read {MASTER_SERVER}: {exc}")

    candidates = extract_candidate_strings(binary)
    if len(candidates) < 2:
        fail("Could not locate enough possible AES key/IV strings in master-server.")

    for key_source in candidates:
        key = key_source[:16].encode("ascii", "ignore")
        if len(key) != 16:
            continue

        for iv_source in candidates:
            if iv_source == key_source:
                continue

            iv = iv_source[:16].encode("ascii", "ignore")
            if len(iv) != 16:
                continue

            try:
                raw = aes_decrypt(lib, ciphertext, key, iv)
            except ToolError:
                continue

            obj = parse_json_from_plaintext(raw)
            if obj is not None:
                return {
                    "key": key,
                    "iv": iv,
                    "key_source": key_source,
                    "iv_source": iv_source,
                    "data": obj,
                }

    fail(
        "Could not dynamically discover the AES key/IV. "
        "This firmware may use a different encryption scheme."
    )


def load_context():
    if os.geteuid() != 0:
        fail("Run this tool as root.")

    if not os.path.isfile(MASTER_SERVER):
        fail(f"Missing {MASTER_SERVER}")
    if not os.path.isfile(DATA_FILE):
        fail(f"Missing {DATA_FILE}")

    ciphertext = decode_base64_file(DATA_FILE)
    lib_path, lib = find_libcrypto()
    configure_crypto(lib)
    crypto = discover_crypto(lib, ciphertext)

    return {
        "ciphertext": ciphertext,
        "lib_path": lib_path,
        "lib": lib,
        **crypto,
    }


def decrypt_file_with_context(path, context):
    ciphertext = decode_base64_file(path)
    raw = aes_decrypt(
        context["lib"], ciphertext, context["key"], context["iv"]
    )
    obj = parse_json_from_plaintext(raw)
    if obj is None:
        fail(f"Could not decrypt or validate {path}.")
    return obj


def parse_hours(value):
    try:
        hours = Decimal(value)
    except InvalidOperation:
        fail("Hours must be a number, e.g. 1, 250, or 1385.5.")

    if not hours.is_finite() or hours < 0:
        fail("Hours must be a finite number greater than or equal to zero.")

    seconds = int(
        (hours * Decimal(3600)).to_integral_value(rounding=ROUND_HALF_UP)
    )

    # total_time is logged/stored by the firmware as a signed integer.
    if seconds > 2_147_483_647:
        fail("Requested value is too large for the firmware counter.")

    return hours, seconds


def backup_files():
    directory = Path(DATA_FILE).parent
    items = []

    for path in directory.glob("user_data_not_deleted.json.backup*"):
        if path.is_file():
            try:
                stat = path.stat()
            except OSError:
                continue
            items.append((stat.st_mtime, path))

    items.sort(key=lambda item: item[0], reverse=True)
    return items


def unique_backup_path():
    directory = Path(DATA_FILE).parent
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    base = directory / f"{BACKUP_PREFIX}{timestamp}"

    if not base.exists():
        return base

    counter = 1
    while True:
        candidate = directory / f"{BACKUP_PREFIX}{timestamp}-{counter}"
        if not candidate.exists():
            return candidate
        counter += 1


def create_backup(dry_run=False):
    destination = unique_backup_path()
    if dry_run:
        return str(destination)

    try:
        shutil.copy2(DATA_FILE, destination)
        with open(destination, "rb") as handle:
            os.fsync(handle.fileno())
    except OSError as exc:
        fail(f"Could not create backup {destination}: {exc}")

    return str(destination)


def encode_data(lib, key, iv, data):
    # Preserve every field and only let caller change the intended values.
    plaintext = (
        json.dumps(data, separators=(", ", ": "), ensure_ascii=True).encode("utf-8")
        + b"\x00"
    )
    plaintext += b"\x00" * ((-len(plaintext)) % 16)

    encrypted = aes_encrypt(lib, plaintext, key, iv)

    # Verify before allowing anything to be written.
    verify_raw = aes_decrypt(lib, encrypted, key, iv)
    verify_obj = parse_json_from_plaintext(verify_raw)
    if verify_obj != data:
        fail("Encryption verification failed. Original file was NOT modified.")

    return base64.b64encode(encrypted)


def atomic_replace_encoded(encoded, context):
    target = Path(DATA_FILE)
    temp = Path(f"{DATA_FILE}.new")
    stat = target.stat()

    try:
        with open(temp, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())

        os.chmod(temp, stat.st_mode)
        os.chown(temp, stat.st_uid, stat.st_gid)

        # Validate the exact bytes written to disk.
        test_cipher = decode_base64_file(temp)
        test_raw = aes_decrypt(
            context["lib"], test_cipher, context["key"], context["iv"]
        )
        if parse_json_from_plaintext(test_raw) is None:
            fail("On-disk verification failed. Original file was NOT modified.")

        os.replace(temp, target)

        try:
            directory_fd = os.open(str(target.parent), os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except OSError:
            pass

        os.sync()
    except Exception:
        try:
            if temp.exists():
                temp.unlink()
        except OSError:
            pass
        raise


def atomic_restore_file(source, context):
    source = Path(source)

    # Fully validate the backup before touching the active file.
    restored_data = decrypt_file_with_context(source, context)

    target = Path(DATA_FILE)
    temp = Path(f"{DATA_FILE}.new")
    stat = target.stat()

    try:
        encoded = source.read_bytes().strip()

        with open(temp, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())

        os.chmod(temp, stat.st_mode)
        os.chown(temp, stat.st_uid, stat.st_gid)

        # Validate the copied temp file again.
        test_data = decrypt_file_with_context(temp, context)
        if test_data != restored_data:
            fail("Restore verification failed. Original file was NOT modified.")

        os.replace(temp, target)

        try:
            directory_fd = os.open(str(target.parent), os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except OSError:
            pass

        os.sync()
    except Exception:
        try:
            if temp.exists():
                temp.unlink()
        except OSError:
            pass
        raise

    return restored_data


def reboot_if_requested(no_reboot, json_mode):
    if no_reboot:
        if not json_mode:
            print()
            print("IMPORTANT: reboot the printer before printing:")
            print("  reboot -f")
        return

    if not json_mode:
        print()
        print("Rebooting now so master-server reloads the changed value...")
    sys.stdout.flush()
    subprocess.call(["reboot", "-f"])


def confirm(prompt_word, current_seconds, new_seconds, no_reboot, assume_yes):
    if assume_yes:
        return

    print()
    print("WARNING")
    print("-------")
    print("Run this command only while the printer is IDLE.")
    print(f"Current lifetime: {current_seconds / 3600:.4f} hours")
    print(f"New lifetime:     {new_seconds / 3600:.4f} hours")
    print("A timestamped backup will be created first.")
    if no_reboot:
        print("Automatic reboot is disabled; reboot immediately after the change.")
    else:
        print("The printer will reboot immediately after the change.")
    print()

    answer = input(f"Type {prompt_word} to continue: ").strip()
    if answer != prompt_word:
        fail("Cancelled. Nothing changed.")


def resolve_backup(value):
    items = backup_files()
    if not items:
        fail("No backups were found.")

    if value == "latest":
        return items[0][1]

    candidate = Path(value)
    if not candidate.is_absolute():
        candidate = Path(DATA_FILE).parent / candidate.name

    try:
        candidate = candidate.resolve()
        allowed_dir = Path(DATA_FILE).parent.resolve()
    except OSError as exc:
        fail(f"Could not resolve backup path: {exc}")

    if candidate.parent != allowed_dir:
        fail("Restore files must be in the printer's Creality config directory.")

    if not candidate.name.startswith("user_data_not_deleted.json.backup"):
        fail("Selected file does not look like a K1 Print Time Tool backup.")

    if not candidate.is_file():
        fail(f"Backup not found: {candidate}")

    return candidate


def command_read(context, json_mode):
    duration = format_duration(context["data"]["total_time"])
    payload = {
        "command": "read",
        "total_time_seconds": duration["seconds"],
        "total_time_hours": duration["hours"],
        "total_time_days": duration["days"],
        "exact": duration["exact"],
    }

    if json_mode:
        output_json(payload)
        return

    print("Creality K1 Lifetime Print Time")
    print("-------------------------------")
    print(f"Hours:    {duration['hours']:.4f}")
    print(f"Days:     {duration['days']:.4f}")
    print(f"Seconds:  {duration['seconds']}")
    print(f"Exact:    {duration['exact']}")


def command_set(context, value, args, reset=False):
    if reset:
        _, seconds = parse_hours("0")
        prompt_word = "RESET"
        command_name = "reset"
    else:
        if value is None:
            fail("The set command requires an hours value.")
        _, seconds = parse_hours(value)
        prompt_word = "SET"
        command_name = "set"

    current_seconds = context["data"]["total_time"]

    if args.dry_run:
        payload = {
            "command": command_name,
            "dry_run": True,
            "current_seconds": current_seconds,
            "current_hours": current_seconds / 3600,
            "requested_seconds": seconds,
            "requested_hours": seconds / 3600,
            "would_create_backup": str(unique_backup_path()),
            "would_reboot": not args.no_reboot,
        }
        if args.json:
            output_json(payload)
        else:
            print("DRY RUN - nothing will be changed")
            print("--------------------------------")
            print(f"Current:   {current_seconds / 3600:.4f} h ({current_seconds} s)")
            print(f"Requested: {seconds / 3600:.4f} h ({seconds} s)")
            print(f"Backup:    {payload['would_create_backup']}")
            print(f"Reboot:    {'yes' if payload['would_reboot'] else 'no'}")
        return

    confirm(
        prompt_word,
        current_seconds,
        seconds,
        args.no_reboot,
        args.yes,
    )

    backup = create_backup()
    new_data = dict(context["data"])
    new_data["total_time"] = seconds

    encoded = encode_data(
        context["lib"], context["key"], context["iv"], new_data
    )
    atomic_replace_encoded(encoded, context)

    payload = {
        "command": command_name,
        "success": True,
        "previous_seconds": current_seconds,
        "new_seconds": seconds,
        "new_hours": seconds / 3600,
        "backup": backup,
        "rebooting": not args.no_reboot,
    }

    if args.json:
        output_json(payload)
    else:
        print()
        print(f"SUCCESS: lifetime print time set to {seconds / 3600:.4f} hours")
        print(f"Backup:  {backup}")

    reboot_if_requested(args.no_reboot, args.json)


def command_backup(args):
    path = create_backup(dry_run=args.dry_run)
    payload = {
        "command": "backup",
        "dry_run": args.dry_run,
        "backup": path,
    }

    if args.json:
        output_json(payload)
        return

    if args.dry_run:
        print(f"DRY RUN: would create {path}")
    else:
        print(f"Backup created: {path}")


def command_backups(context, json_mode):
    rows = []
    for mtime, path in backup_files():
        row = {
            "file": path.name,
            "path": str(path),
            "modified": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(mtime)),
        }
        try:
            data = decrypt_file_with_context(path, context)
            seconds = data["total_time"]
            row["total_time_seconds"] = seconds
            row["total_time_hours"] = seconds / 3600
            row["valid"] = True
        except ToolError as exc:
            row["valid"] = False
            row["error"] = str(exc)
        rows.append(row)

    if json_mode:
        output_json({"command": "backups", "backups": rows})
        return

    if not rows:
        print("No backups found.")
        return

    print("K1 Print Time Tool backups")
    print("--------------------------")
    for row in rows:
        if row["valid"]:
            print(
                f"{row['file']}  "
                f"{row['total_time_hours']:.4f} h  "
                f"{row['modified']}"
            )
        else:
            print(f"{row['file']}  INVALID  {row['modified']}")


def command_restore(context, value, args):
    if value is None:
        fail("The restore command requires a backup filename or 'latest'.")

    source = resolve_backup(value)
    restore_data = decrypt_file_with_context(source, context)
    current_seconds = context["data"]["total_time"]
    new_seconds = restore_data["total_time"]

    if args.dry_run:
        payload = {
            "command": "restore",
            "dry_run": True,
            "source": str(source),
            "current_seconds": current_seconds,
            "restore_seconds": new_seconds,
            "restore_hours": new_seconds / 3600,
            "would_create_backup": str(unique_backup_path()),
            "would_reboot": not args.no_reboot,
        }
        if args.json:
            output_json(payload)
        else:
            print("DRY RUN - nothing will be changed")
            print("--------------------------------")
            print(f"Source:    {source}")
            print(f"Current:   {current_seconds / 3600:.4f} h ({current_seconds} s)")
            print(f"Restored:  {new_seconds / 3600:.4f} h ({new_seconds} s)")
            print(f"Backup:    {payload['would_create_backup']}")
            print(f"Reboot:    {'yes' if payload['would_reboot'] else 'no'}")
        return

    confirm(
        "RESTORE",
        current_seconds,
        new_seconds,
        args.no_reboot,
        args.yes,
    )

    pre_restore_backup = create_backup()
    restored_data = atomic_restore_file(source, context)

    payload = {
        "command": "restore",
        "success": True,
        "source": str(source),
        "previous_seconds": current_seconds,
        "restored_seconds": restored_data["total_time"],
        "restored_hours": restored_data["total_time"] / 3600,
        "pre_restore_backup": pre_restore_backup,
        "rebooting": not args.no_reboot,
    }

    if args.json:
        output_json(payload)
    else:
        print()
        print(
            "SUCCESS: restored lifetime print time to "
            f"{restored_data['total_time'] / 3600:.4f} hours"
        )
        print(f"Source:   {source}")
        print(f"Backup:   {pre_restore_backup}")

    reboot_if_requested(args.no_reboot, args.json)


def command_verify(context, json_mode):
    data = decrypt_file_with_context(DATA_FILE, context)

    # Verify that the currently detected key/IV can also round-trip the data.
    encoded = encode_data(
        context["lib"], context["key"], context["iv"], dict(data)
    )
    test_cipher = base64.b64decode(encoded, validate=True)
    test_raw = aes_decrypt(
        context["lib"], test_cipher, context["key"], context["iv"]
    )
    test_data = parse_json_from_plaintext(test_raw)
    valid = test_data == data

    payload = {
        "command": "verify",
        "valid": valid,
        "total_time_seconds": data["total_time"],
        "total_time_hours": data["total_time"] / 3600,
        "crypto": "AES-128-CBC",
        "libcrypto": context["lib_path"],
    }

    if json_mode:
        output_json(payload)
    else:
        print("Verification")
        print("------------")
        print(f"Status:      {'PASS' if valid else 'FAIL'}")
        print(f"Hours:       {data['total_time'] / 3600:.4f}")
        print(f"Seconds:     {data['total_time']}")
        print("Crypto:      AES-128-CBC")
        print(f"libcrypto:   {context['lib_path']}")

    if not valid:
        fail("Verification failed.")


def command_info(context, json_mode):
    data = context["data"]
    duration = format_duration(data["total_time"])
    payload = {
        "command": "info",
        "master_server": MASTER_SERVER,
        "data_file": DATA_FILE,
        "libcrypto": context["lib_path"],
        "crypto": "AES-128-CBC",
        "key_iv_discovered_automatically": True,
        "total_time_seconds": duration["seconds"],
        "total_time_hours": duration["hours"],
        "total_time_days": duration["days"],
        "exact": duration["exact"],
        "persistent_fields": data,
        "backup_count": len(backup_files()),
    }

    if json_mode:
        output_json(payload)
        return

    print("Creality K1 Print Time Tool - Info")
    print("----------------------------------")
    print(f"Data file:     {DATA_FILE}")
    print(f"master-server: {MASTER_SERVER}")
    print(f"libcrypto:     {context['lib_path']}")
    print("Crypto:        AES-128-CBC")
    print("Key/IV:        discovered automatically")
    print(f"Hours:         {duration['hours']:.4f}")
    print(f"Seconds:       {duration['seconds']}")
    print(f"Exact:         {duration['exact']}")
    print(f"Backups:       {len(backup_files())}")
    print(f"Fields:        {json.dumps(data, sort_keys=True)}")


def build_parser():
    parser = argparse.ArgumentParser(
        description=(
            "Read, verify, back up, restore, set or reset the persistent "
            "lifetime print-time counter on compatible Creality K1-series firmware."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  python3 k1_hours.py
  python3 k1_hours.py read
  python3 k1_hours.py set 250
  python3 k1_hours.py set 693.6371 --dry-run
  python3 k1_hours.py reset
  python3 k1_hours.py backup
  python3 k1_hours.py backups
  python3 k1_hours.py restore latest
  python3 k1_hours.py verify
  python3 k1_hours.py info --json
""",
    )
    parser.add_argument(
        "command",
        nargs="?",
        default="read",
        choices=[
            "read",
            "set",
            "reset",
            "backup",
            "backups",
            "restore",
            "verify",
            "info",
        ],
        help="Command to run (default: read).",
    )
    parser.add_argument(
        "value",
        nargs="?",
        help="Hours for 'set', or backup filename/'latest' for 'restore'.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what a mutating command would do without writing anything.",
    )
    parser.add_argument(
        "--no-reboot",
        action="store_true",
        help="Do not automatically reboot after set/reset/restore.",
    )
    parser.add_argument(
        "-y",
        "--yes",
        action="store_true",
        help="Skip confirmation for set/reset/restore.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON.",
    )
    return parser


def validate_arguments(args):
    if args.command == "set":
        if args.value is None:
            fail("The set command requires an hours value.")
    elif args.command == "restore":
        if args.value is None:
            fail("The restore command requires a backup filename or 'latest'.")
    elif args.value is not None:
        fail(f"The {args.command} command does not accept a value.")

    if args.command in {"read", "backups", "verify", "info"} and args.dry_run:
        fail(f"--dry-run is not needed with the read-only '{args.command}' command.")

    if args.command not in {"set", "reset", "restore"} and args.no_reboot:
        fail(f"--no-reboot only applies to set, reset and restore.")

    if args.command not in {"set", "reset", "restore"} and args.yes:
        fail(f"--yes only applies to set, reset and restore.")


def main():
    parser = build_parser()
    args = parser.parse_args()

    try:
        validate_arguments(args)

        # backup itself does not need crypto discovery, but root/data-file checks
        # are still useful. Every other command needs the current context.
        if args.command == "backup":
            if os.geteuid() != 0:
                fail("Run this tool as root.")
            if not os.path.isfile(DATA_FILE):
                fail(f"Missing {DATA_FILE}")
            command_backup(args)
            return

        context = load_context()

        if args.command == "read":
            command_read(context, args.json)
        elif args.command == "set":
            command_set(context, args.value, args, reset=False)
        elif args.command == "reset":
            command_set(context, None, args, reset=True)
        elif args.command == "backups":
            command_backups(context, args.json)
        elif args.command == "restore":
            command_restore(context, args.value, args)
        elif args.command == "verify":
            command_verify(context, args.json)
        elif args.command == "info":
            command_info(context, args.json)
        else:
            fail(f"Unknown command: {args.command}")

    except ToolError as exc:
        if getattr(args, "json", False):
            output_json({"success": False, "error": str(exc)})
        else:
            print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        if getattr(args, "json", False):
            output_json({"success": False, "error": "Cancelled by user."})
        else:
            print("\nCancelled.", file=sys.stderr)
        sys.exit(130)


if __name__ == "__main__":
    main()
