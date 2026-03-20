<p align="center">
  <img src="https://img.shields.io/badge/Platform-Windows%2010%20%7C%2011-blue?logo=windows" alt="Platform">
  <img src="https://img.shields.io/badge/PowerShell-5.1%2B-blue?logo=powershell" alt="PowerShell">
  <img src="https://img.shields.io/github/license/obsidiancorps/windows-hardening" alt="License">
  <img src="https://img.shields.io/github/stars/obsidiancorps/windows-hardening?style=social" alt="Stars">
</p>

# Windows Hardening Tool

> One script. 150+ checks. Harden Windows 10/11 in minutes.

An interactive PowerShell tool that audits and hardens your Windows system across **11 categories** — from telemetry and bloatware to Defender ASR rules and credential protection. No dependencies, no third-party tools, just a single `.ps1` file.

<p align="center">
  <strong>Audit &rarr; Review &rarr; Harden &rarr; Verify</strong>
</p>

## Highlights

- **Interactive TUI** with animated audit, color-coded results, and category picker
- **150+ hardening checks** based on CIS Benchmarks, Microsoft Security Baselines, and ACSC guidance
- **Audit mode** — scan your system and get a hardening score without changing anything
- **Quick Harden** — apply all recommended settings with one keypress
- **Custom Harden** — pick exactly which categories to apply
- **Automatic registry backup** before any changes, with one-click restore
- **Silent/CLI mode** for automation, scripting, and deployment pipelines
- **Zero dependencies** — runs on any Windows 10/11 machine with PowerShell 5.1

## Quick Start

```powershell
# Download and run (as Administrator)
irm https://raw.githubusercontent.com/obsidiancorps/windows-hardening/main/Harden-Windows.ps1 -OutFile Harden-Windows.ps1
powershell -ExecutionPolicy Bypass -File .\Harden-Windows.ps1
```

Or clone the repo:

```powershell
git clone https://github.com/obsidiancorps/windows-hardening.git
cd windows-hardening
powershell -ExecutionPolicy Bypass -File .\Harden-Windows.ps1
```

## What It Hardens

| # | Category | Settings | What it does |
|---|----------|:--------:|-------------|
| 1 | **Telemetry** | 12 | Diagnostic data, feedback, error reports, advertising ID |
| 2 | **Privacy** | 14 | Activity history, location, speech, camera/mic defaults |
| 3 | **Services** | 13 | DiagTrack, geolocation, Xbox, Maps, error reporting |
| 4 | **Scheduled Tasks** | 12 | CEIP, compatibility appraiser, feedback, disk diagnostics |
| 5 | **Network** | 15 | SMBv1, LLMNR, WPAD, NetBIOS, RDP NLA/TLS, DNS-over-HTTPS, telemetry firewall |
| 6 | **Security** | 19 | UAC, NTLM, LSA Protection, Credential Guard, SMB signing, PS logging |
| 7 | **Defender/ASR** | 19 | 14 Attack Surface Reduction rules + PUA/network protection |
| 8 | **Bloatware** | 21+ | Remove pre-installed apps, disable suggested content and spotlight |
| 9 | **AI/Copilot** | 8 | Disable Copilot, Recall, Bing AI, web search in Start |
| 10 | **Windows Update** | 5 | Defer feature updates, disable P2P delivery, no auto-restart |
| 11 | **Miscellaneous** | 7 | File extensions, GameDVR, widgets, lock screen hardening |

### Attack Surface Reduction Rules

The Defender category enables **14 ASR rules** in Block mode, covering the most common attack vectors:

- Office apps creating executables, child processes, or injecting code
- JavaScript/VBScript launching downloaded content
- Obfuscated scripts and untrusted USB processes
- Credential stealing from LSASS
- Email-delivered executables
- WMI persistence and PSExec/WMI process creation
- Abuse of vulnerable signed drivers

### Audit-Only Items

Some items are checked but **not automatically applied** because they require specific hardware or may break certain apps:

- **Credential Guard** — needs UEFI + TPM + VBS capable hardware
- **Controlled Folder Access** — can block legitimate apps from writing to Documents/Desktop

The script includes manual enable instructions for these in the source comments.

## Usage

### Interactive Mode

```powershell
.\Harden-Windows.ps1
```

Navigate the TUI menu:
1. **Audit System** — animated scan with per-category progress bars and overall score
2. **Quick Harden** — apply all settings (creates backup first)
3. **Custom Harden** — toggle individual categories on/off
4. **Create/Restore Backup** — manual backup management

### Silent Mode (CLI)

```powershell
# Apply everything (for automation / deployment)
.\Harden-Windows.ps1 -Silent -All

# Apply specific categories only
.\Harden-Windows.ps1 -Silent -Categories Telemetry,Privacy,Services,Defender,AI

# Valid categories:
# Telemetry, Privacy, Services, Tasks, Network, Security,
# Defender, Bloatware, AI, Updates, Misc
```

## What It Does NOT Do

- **Does not disable Windows Update** — that would be a security risk
- **Does not disable Windows Defender** — you need your AV
- **Does not modify UEFI/boot settings** — no risk of bricking
- **Does not touch your files or personal data**

## Backup and Restore

The tool **automatically creates a registry backup** in `%USERPROFILE%\WindowsHardeningBackups\` before applying any changes. Each backup is timestamped. You can restore any backup from the TUI menu or by importing the `.reg` file directly.

## False Positive Prevention

The audit engine handles three classes of checks to avoid false reporting:

| Check type | How it works |
|-----------|-------------|
| **Standard registry** | Reads key, compares to desired value |
| **NullOk (secure defaults)** | Missing key = already secure (e.g., DEP, WDigest, SEHOP are on by default) |
| **Custom check** | Scriptblock for complex state (e.g., SMBv1 uses `Get-WindowsOptionalFeature`, Credential Guard uses WMI) |

## Requirements

- Windows 10 (1903+) or Windows 11 (including 24H2)
- PowerShell 5.1+
- **Administrator privileges**

## FAQ

<details>
<summary><strong>Will this break anything?</strong></summary>

The settings are conservative and widely tested. Xbox services are disabled (irrelevant if you don't game on PC). Camera/microphone defaults are set to Deny but apps can still request access. If something breaks, use the Restore Backup option.
</details>

<details>
<summary><strong>Do I need to restart?</strong></summary>

Yes — LSA Protection, service changes, and some network settings require a restart to take full effect.
</details>

<details>
<summary><strong>Can I run this on a domain-joined machine?</strong></summary>

Yes, but domain Group Policy may override some settings. The audit will accurately show what's actually applied regardless of GPO.
</details>

<details>
<summary><strong>How do I undo everything?</strong></summary>

Use [5] Restore Backup in the TUI. For services, re-enable manually via `services.msc`. For bloatware, reinstall from the Microsoft Store.
</details>

<details>
<summary><strong>Can I use this in my organization?</strong></summary>

Yes. The `-Silent -All` mode is designed for deployment pipelines. The MIT license allows commercial use. Test on a staging machine first.
</details>

## References

This tool's checks are informed by:

- [CIS Microsoft Windows 11 Enterprise Benchmark v4.0.0](https://www.cisecurity.org/benchmark/microsoft_windows_desktop)
- [Microsoft Attack Surface Reduction Rules](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference)
- [ACSC Hardening Microsoft Windows 11](https://www.cyber.gov.au/resources-business-and-government/maintaining-devices-and-systems/system-hardening-and-administration/system-hardening/hardening-microsoft-windows-10-version-21h1-workstations)
- [Microsoft Security Baselines](https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/windows-security-configuration-framework/windows-security-baselines)

## Contributing

PRs welcome! Please:
1. Test on a clean Windows 10/11 VM before submitting
2. Add comments explaining **what** the setting does and **why** it matters
3. Use `NullOk` or `Check` scriptblocks where the default state is already secure

## License

[MIT](LICENSE)

---

<p align="center">
  Made by <a href="https://github.com/obsidiancorps">ObsidianCorps</a>
</p>
