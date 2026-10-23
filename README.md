# K1 Print Time Tool

A command-line utility for reading, verifying, backing up, restoring, setting, and resetting the **persistent lifetime print-time counter** on compatible Creality K1-series printers.

The stock printer UI may already show accumulated print hours. This tool is for users who want programmatic access to the underlying persistent counter, want to back it up, or legitimately need to adjust it after maintenance, a full mechanical rebuild, controller replacement, refurbishment, or similar work.

> [!WARNING]
> The `set`, `reset`, and `restore` commands modify a persistent Creality configuration file. Use them only while the printer is **IDLE**. The tool creates a backup before every write and validates the replacement data before installing it.

## What was discovered

On compatible K1 firmware, Creality stores the persistent lifetime print time in:

```text
/usr/data/creality/userdata/config/user_data_not_deleted.json
```

Despite the `.json` extension, the file is not plain JSON. On the tested firmware it contains Base64-encoded AES-128-CBC encrypted data. After decryption it contains data similar to:

```json
{
  "total_time": 4988990,
  "creality_num": 1
}
```

`total_time` is stored in **seconds**.

The stock `master-server` binary contains the crypto material required to read the file. Instead of hard-coding one firmware's key and IV, this tool dynamically searches `master-server` for candidate values and accepts them only when they successfully decrypt the file into valid JSON containing a non-negative integer `total_time`.

If the firmware or data format is not recognised, the tool fails without writing anything.

## Features

- Read current lifetime print time.
- Set lifetime print time to a specific number of hours.
- Reset the counter to zero.
- Create timestamped backups.
- List backups and show the print time contained in each valid backup.
- Restore a specific backup or the latest backup.
- Verify the current encrypted file and crypto handling.
- Show diagnostic information.
- JSON output for scripting.
- Dry-run support for write operations.
- Automatic backup before every `set`, `reset`, or `restore`.
- Atomic file replacement and verification.
- Automatic reboot after changes so Creality's services reload the new value.

## Compatibility

This project was developed against K1 firmware using:

```text
/usr/bin/master-server
/usr/data/creality/userdata/config/user_data_not_deleted.json
/usr/lib/libcrypto.so*
```

It is intended for the **Creality K1 family**, but not every K1, K1C, and K1 Max firmware version has been tested.

The script does **not** assume that every firmware uses the same embedded AES key and IV. It discovers candidate values dynamically and validates the result before accepting them.

## Requirements

- Root/SSH access enabled on the printer.
- Python 3 on the printer.
- Stock `master-server`.
- Compatible OpenSSL `libcrypto`.

No third-party Python packages are required.

# Installation

## 1. Enable root access

Enable root access from the printer's settings/root-account screen, then connect over SSH:

```bash
ssh root@PRINTER_IP
```

Replace `PRINTER_IP` with the printer's IP address.

## 2. Install the script

### Recommended: download directly from GitHub

From the printer's SSH shell:

```bash
wget -O /root/k1_hours.py https://raw.githubusercontent.com/BlueBell-XA/K1-Print-Time-Tool/main/k1_hours.py
```

If `wget` is unavailable, use SCP from your computer:

```bash
scp -O k1_hours.py root@PRINTER_IP:/root/k1_hours.py
```

The `-O` option forces legacy SCP mode. This is useful because some K1 setups allow SSH but do not expose the SFTP subsystem expected by newer SCP clients and WinSCP.

## 3. Verify the script

```bash
python3 -m py_compile /root/k1_hours.py
```

**No output means the syntax check passed.**

Optionally make it executable:

```bash
chmod +x /root/k1_hours.py
```

# Quick start

Running the script with no command defaults to `read`:

```bash
python3 /root/k1_hours.py
```

Equivalent:

```bash
python3 /root/k1_hours.py read
```

Example:

```text
Creality K1 Lifetime Print Time
-------------------------------
Hours:    1385.8306
Days:     57.7429
Seconds:  4988990
Exact:    57d 17h 49m 50s
```

# Commands

## Read

```bash
python3 /root/k1_hours.py read
```

Read-only.

## Set

Set lifetime print time to a specific number of hours:

```bash
python3 /root/k1_hours.py set 250
```

Decimal hours are supported:

```bash
python3 /root/k1_hours.py set 693.6371
```

The firmware stores whole seconds, so decimal values are rounded to the nearest second.

Before writing, the tool shows the current and requested values and requires:

```text
Type SET to continue:
```

A timestamped backup is created before the active file is changed.

## Reset

Reset the persistent lifetime counter to zero:

```bash
python3 /root/k1_hours.py reset
```

This requires:

```text
Type RESET to continue:
```

A backup is created first.

## Backup

Create a backup without changing the counter:

```bash
python3 /root/k1_hours.py backup
```

Backups are stored beside the original file, for example:

```text
user_data_not_deleted.json.backup-20261023-123456
```

## List backups

```bash
python3 /root/k1_hours.py backups
```

Valid backups are decrypted and their stored lifetime hours are shown.

## Restore

Restore the newest available backup:

```bash
python3 /root/k1_hours.py restore latest
```

Or restore a specific backup:

```bash
python3 /root/k1_hours.py restore user_data_not_deleted.json.backup-20261023-123456
```

The selected backup is validated first. The tool also creates a **new backup of the current active file before restoring**.

A restore requires:

```text
Type RESTORE to continue:
```

## Verify

Run a read-only validation:

```bash
python3 /root/k1_hours.py verify
```

This checks that the file is valid Base64, the ciphertext is AES block-aligned, the key/IV can be discovered, the JSON is valid, and the data can be encrypted/decrypted successfully.

## Info

Show diagnostic information:

```bash
python3 /root/k1_hours.py info
```

This includes the data-file path, `master-server`, detected `libcrypto`, crypto type, current counter, persistent fields, and backup count.

# Options

## Dry run

Preview a write operation without changing anything:

```bash
python3 /root/k1_hours.py set 500 --dry-run
python3 /root/k1_hours.py reset --dry-run
python3 /root/k1_hours.py restore latest --dry-run
```

This is strongly recommended before the first write on an untested printer/firmware combination.

## Disable automatic reboot

```bash
python3 /root/k1_hours.py set 500 --no-reboot
```

If you use this option, reboot manually before printing:

```bash
reboot -f
```

The running Creality services may still have the old counter in memory, so delaying the reboot is not recommended.

## Skip confirmation

```bash
python3 /root/k1_hours.py set 500 --yes
```

`-y` and `--yes` are equivalent.

## JSON output

```bash
python3 /root/k1_hours.py read --json
python3 /root/k1_hours.py info --json
python3 /root/k1_hours.py backups --json
```

# Full command reference

```text
python3 k1_hours.py [command] [value] [options]

Commands:
  read                 Read lifetime print time (default)
  set <hours>          Set lifetime print time
  reset                Reset lifetime print time to zero
  backup               Create a timestamped backup
  backups              List available backups
  restore <file>       Restore a backup
  restore latest       Restore the newest backup
  verify               Validate the current encrypted data
  info                 Show diagnostic information

Options:
  --dry-run            Preview a write operation without changing files
  --no-reboot          Do not reboot after set/reset/restore
  -y, --yes            Skip write confirmation
  --json               Machine-readable JSON output
  -h, --help           Show built-in help
```

Built-in help:

```bash
python3 /root/k1_hours.py --help
```

# Recommended first-time workflow

For an unfamiliar printer or firmware:

```bash
python3 /root/k1_hours.py verify
```

Then:

```bash
python3 /root/k1_hours.py read
```

Create a manual backup:

```bash
python3 /root/k1_hours.py backup
```

Preview the intended change:

```bash
python3 /root/k1_hours.py set 1 --dry-run
```

Then perform it:

```bash
python3 /root/k1_hours.py set 1
```

# Removing the tool

Removing the Python script does not alter the stored lifetime counter:

```bash
rm /root/k1_hours.py
```

View backups first with:

```bash
python3 /root/k1_hours.py backups
```

Backups live in:

```text
/usr/data/creality/userdata/config/
```

# Safety notes

- Do not run `set`, `reset`, or `restore` while printing.
- Keep at least one known-good backup until the printer has rebooted normally and shows the expected value.
- Do not power the printer off during a write.
- `set` and `reset` preserve existing JSON fields and only alter `total_time`.
- `restore` uses the exact validated encrypted backup.
- The tool fails if it cannot identify and validate the firmware's encryption scheme.

# Contributing / firmware reports

Reports from other K1, K1C, and K1 Max firmware versions are welcome.

Useful information includes:

- printer model;
- firmware version;
- whether `read` works;
- whether `verify` passes;
- whether `set --dry-run` works.

Please do not post private network information or credentials.

# License

This repository is licensed under the **GNU Affero General Public License v3.0 (AGPL-3.0)**. See [LICENSE](LICENSE).
