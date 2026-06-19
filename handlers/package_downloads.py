"""Download URL validation and prebuilt-binary action helpers for PackageHandler."""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse


def validate_download_url(url: str, allowed_hosts: set[str]) -> str:
    parsed = urlparse(url)
    if parsed.scheme.lower() != "https":
        raise ValueError(f"Blocked non-HTTPS download URL: {url}")

    hostname = (parsed.hostname or "").lower()
    if hostname not in allowed_hosts:
        raise ValueError(f"Blocked untrusted download host: {hostname or 'unknown'}")
    return url


def build_download_action(
    *,
    tool_name: str,
    url: str,
    tools_bin_dir: Path,
    sys_executable: str,
    validate_url,
    curl_available: bool,
    action_builder,
) -> dict[str, object]:
    if Path(tool_name).name != tool_name or any(part in tool_name for part in ("/", "\\")):
        raise ValueError(f"Invalid tool name for download action: {tool_name}")

    safe_url = validate_url(url)
    dest_path = tools_bin_dir / tool_name
    if dest_path.is_symlink():
        raise ValueError(f"Refusing to overwrite symlink destination: {dest_path}")
    dest = str(dest_path)
    is_zip = urlparse(safe_url).path.lower().endswith(".zip")

    if is_zip:
        extract_script = (
            "import os, tempfile, urllib.request, zipfile; "
            "tmp = tempfile.NamedTemporaryFile(delete=False, suffix='.zip'); "
            "tmp_path = tmp.name; tmp.close(); "
            f"urllib.request.urlretrieve({safe_url!r}, tmp_path); "
            "z = zipfile.ZipFile(tmp_path); "
            f"members = [m for m in z.namelist() if os.path.basename(m).split('.')[0] == {tool_name!r}]; "
            "if not members: raise RuntimeError('No matching binary asset in archive'); "
            "data = z.open(members[0]).read(); "
            f"open({dest!r}, 'wb').write(data); "
            f"os.chmod({dest!r}, 0o755); "
            "z.close(); "
            "os.unlink(tmp_path)"
        )
        commands: list[list[str]] = [[sys_executable, "-c", extract_script]]
    elif curl_available:
        commands = [
            ["curl", "--proto", "=https", "--tlsv1.2", "-fsSL", "--output", dest, safe_url],
            ["chmod", "+x", dest],
        ]
    else:
        commands = [
            [
                sys_executable,
                "-c",
                f"import urllib.request, os; urllib.request.urlretrieve({safe_url!r}, {dest!r}); os.chmod({dest!r}, 0o755)",
            ]
        ]
    return action_builder(f"download:{tool_name}", commands, [tool_name])
