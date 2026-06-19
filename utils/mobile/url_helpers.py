"""URL-focused helper functions extracted from mobile static scan helpers."""

from __future__ import annotations

from urllib.parse import urlparse


def sanitize_url_candidate(constants, url: str) -> str:
    if not url:
        return ""
    cleaned = constants.URL_TRAILING_JUNK_RE.sub("", str(url).strip())
    if (
        not cleaned
        or "\\" in cleaned
        or cleaned.endswith("://")
        or cleaned.endswith("://.")
        or cleaned.endswith("://-")
    ):
        return ""
    return cleaned


def is_valid_url_host(constants, host: str) -> bool:
    if not host:
        return False
    if constants.URL_PLACEHOLDER_RE.search(host):
        return False
    if host == "localhost":
        return True
    if constants.IPV4_EXACT_RE.fullmatch(host):
        return True
    return bool(constants.HOSTNAME_RE.fullmatch(host))


def is_source_repo_reference_url(constants, host: str, path: str) -> bool:
    if host not in constants.REPO_REFERENCE_HOSTS:
        return False

    path_parts = [segment for segment in path.strip("/").split("/") if segment]
    if not path_parts:
        return False

    if host in {"github.com", "www.github.com"}:
        return len(path_parts) >= 3 and path_parts[2] in {
            "issues",
            "issue",
            "pull",
            "pulls",
            "blob",
            "tree",
            "commit",
            "commits",
            "compare",
            "wiki",
            "releases",
        }

    if host == "gitlab.com":
        return len(path_parts) >= 4 and path_parts[2] == "-" and path_parts[3] in {
            "issues",
            "merge_requests",
            "blob",
            "tree",
            "commit",
            "commits",
            "releases",
        }

    if host == "bitbucket.org":
        return len(path_parts) >= 3 and path_parts[2] in {
            "issues",
            "pull-requests",
            "src",
            "commits",
            "branches",
        }

    return False


def is_valuable_url(constants, url: str) -> bool:
    cleaned = sanitize_url_candidate(constants, url)
    if not cleaned:
        return False
    try:
        parsed = urlparse(cleaned)
    except ValueError:
        return False
    if parsed.scheme.lower() not in {"http", "https", "wss"}:
        return False
    host = (parsed.hostname or "").lower()
    if not is_valid_url_host(constants, host):
        return False
    if host in constants.URL_NOISE_HOSTS:
        return False
    if is_source_repo_reference_url(constants, host, parsed.path or ""):
        return False
    if constants.URL_PLACEHOLDER_RE.search(cleaned):
        return False
    if constants.URL_IGNORE_RE.search(cleaned):
        return False
    return True


def canonicalize_url(constants, url: str) -> str:
    cleaned = sanitize_url_candidate(constants, url)
    if not cleaned:
        return ""
    parsed = urlparse(cleaned)
    host = (parsed.hostname or "").lower()
    if not is_valid_url_host(constants, host):
        return ""
    netloc = host
    if parsed.port:
        netloc = f"{host}:{parsed.port}"
    path = parsed.path or ""
    if path == "/":
        path = ""
    elif path:
        path = path.rstrip("/")
    return f"{parsed.scheme.lower()}://{netloc}{path}"


def to_base_url(url: str) -> str:
    try:
        parsed = urlparse(str(url).strip())
    except ValueError:
        return ""

    scheme = (parsed.scheme or "").lower()
    host = (parsed.hostname or "").lower()
    if not scheme or not host:
        return ""

    netloc = host
    default_ports = {"http": 80, "https": 443, "ws": 80, "wss": 443}
    if parsed.port and parsed.port != default_ports.get(scheme):
        netloc = f"{host}:{parsed.port}"
    return f"{scheme}://{netloc}"


def collapse_urls_to_common_bases(urls: set[str]) -> list[str]:
    unique_bases = {base for base in (to_base_url(url) for url in urls) if base}
    return sorted(unique_bases)
