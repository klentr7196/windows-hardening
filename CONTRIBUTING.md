# Contributing

Thanks for considering a contribution! Here's how to help.

## Adding Hardening Checks

1. Pick the right category function (`Invoke-Telemetry`, `Invoke-Security`, etc.)
2. Add your item to the `$items` array:

```powershell
# Explain what the setting does and why it matters
@{ Name = 'Human-readable name'; Path = 'HKLM:\...'; Key = 'ValueName'; Want = 1 }
```

3. If the setting is secure by default when the key is absent, add `NullOk = $true`
4. If the check needs more than a registry read, use a `Check` scriptblock
5. If the setting shouldn't be auto-applied (hardware dependent, may break apps), omit `ApplyFn` and add `[audit-only]` to the Name

## Testing

- Test on a clean Windows 10 and/or Windows 11 VM
- Run the audit (`[1]`) before and after applying
- Verify the backup/restore cycle works
- Test silent mode: `.\Harden-Windows.ps1 -Silent -Categories YourCategory`

## Code Style

- ASCII-only characters (no Unicode box-drawing) for PowerShell 5.1 compatibility
- Save with UTF-8 BOM encoding
- Comment every hardening item explaining what it does
- Use `Set-StrictMode -Version Latest` compatible code

## Pull Requests

- One feature/fix per PR
- Include the category and setting count in the PR title
- Reference CIS Benchmark, STIG, or Microsoft documentation where applicable
