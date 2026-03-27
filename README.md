# Network Sentinel

![Release](https://img.shields.io/github/v/release/Evren12346/network-sentinel?sort=semver)
![Stars](https://img.shields.io/github/stars/Evren12346/network-sentinel?style=social)
![Repo Size](https://img.shields.io/github/repo-size/Evren12346/network-sentinel)

Network Sentinel is a desktop-friendly Python network monitoring utility focused on fast local visibility and operational simplicity.

## Install From GitHub (Recommended)

Linux one-liner:

```bash
git clone https://github.com/Evren12346/network-sentinel.git && cd network-sentinel && bash install.sh
```

Step-by-step:

```bash
git clone https://github.com/Evren12346/network-sentinel.git
cd network-sentinel
bash install.sh
```

After install, run from anywhere:

```bash
network-sentinel
```

## Features

- Real-time monitoring workflow from a single script
- Linux launcher script and desktop entry included
- Minimal dependency footprint

## Project Layout

- `sentinel.py`: core application
- `launch.sh`: Linux launcher
- `NetworkSentinel.desktop`: desktop shortcut template
- `requirements.txt`: Python dependencies

## Quick Start

1. Install dependencies (manual path):

```bash
pip install -r requirements.txt
```

2. Run:

```bash
python sentinel.py
```

Or use:

```bash
bash launch.sh
```

For most users, use the installer in the section above instead of this manual setup.

## Release

Current stable release: `v1.0.0`

## Repository

https://github.com/Evren12346/network-sentinel
