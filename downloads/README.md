# Downloads

This directory contains end-user download artifacts for DIPS.

## Files

- `DIPS_User_Guide_v0.1.1.pdf`: full user guide covering installation, first-run workflow, dashboard navigation, reports, settings, and beta support.
- `dips_0.1.1_all.deb`: Debian-based installer for the DIPS CLI runtime.
- `SHA256SUMS.txt`: checksums for the downloadable artifacts in this directory.

## Debian Package Notes

The `.deb` is intentionally lightweight:

- the CLI runtime is installed and ready after `dpkg -i`
- the dashboard can be enabled later with `sudo dips-enable-gui`
- Python `3.11+` and `python3-venv` are required on the target system

Install the package:

```bash
sudo dpkg -i downloads/dips_0.1.1_all.deb
dips doctor
```

Enable the dashboard after install:

```bash
sudo dips-enable-gui
dips-dashboard
```
