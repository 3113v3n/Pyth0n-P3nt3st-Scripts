import re


def _constants():
    class Constants:
        URL_TRAILING_JUNK_RE = re.compile(r"[.,;:)\]}>\"']+$")
        URL_PLACEHOLDER_RE = re.compile(r"%[a-zA-Z]")
        HOSTNAME_RE = re.compile(
            r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$",
            re.IGNORECASE,
        )
        IPV4_EXACT_RE = re.compile(
            r"^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$"
        )
        URL_IGNORE_RE = re.compile(
            r"\.(?:css|gif|jpeg|jpg|ogg|otf|png|svg|ttf|woff|woff2)(?:\?|$)",
            re.IGNORECASE,
        )
        URL_NOISE_HOSTS = {"schemas.android.com", "www.w3.org"}
        REPO_REFERENCE_HOSTS = {"github.com", "www.github.com", "gitlab.com", "bitbucket.org"}

    return Constants


def test_sanitize_url_candidate_rejects_placeholder_and_backslashes():
    from utils.mobile.url_helpers import sanitize_url_candidate

    constants = _constants()
    assert sanitize_url_candidate(constants, "https://example.com/path)") == "https://example.com/path"
    assert sanitize_url_candidate(constants, "https://example.com\\path") == ""
    assert sanitize_url_candidate(constants, "https://") == ""


def test_is_valid_url_host_accepts_hostname_localhost_and_ipv4():
    from utils.mobile.url_helpers import is_valid_url_host

    constants = _constants()
    assert is_valid_url_host(constants, "example.com") is True
    assert is_valid_url_host(constants, "localhost") is True
    assert is_valid_url_host(constants, "10.0.0.1") is True
    assert is_valid_url_host(constants, "%HOST%") is False


def test_is_source_repo_reference_url_detects_github_issue_and_blob_paths():
    from utils.mobile.url_helpers import is_source_repo_reference_url

    constants = _constants()
    assert is_source_repo_reference_url(constants, "github.com", "/org/repo/issues/1") is True
    assert is_source_repo_reference_url(constants, "github.com", "/org/repo/blob/main/app.py") is True
    assert is_source_repo_reference_url(constants, "github.com", "/org/repo") is False


def test_is_valuable_url_filters_noise_hosts_placeholders_and_repo_refs():
    from utils.mobile.url_helpers import is_valuable_url

    constants = _constants()
    assert is_valuable_url(constants, "https://api.example.com/v1") is True
    assert is_valuable_url(constants, "https://www.w3.org/schema") is False
    assert is_valuable_url(constants, "https://github.com/org/repo/issues/1") is False
    assert is_valuable_url(constants, "https://example.com/%s") is False


def test_canonicalize_url_normalizes_scheme_host_port_and_trailing_slash():
    from utils.mobile.url_helpers import canonicalize_url

    constants = _constants()
    assert canonicalize_url(constants, "HTTPS://Example.com:8443/path/") == "https://example.com:8443/path"
    assert canonicalize_url(constants, "https://example.com/") == "https://example.com"


def test_collapse_urls_to_common_bases_deduplicates_by_scheme_host_and_port():
    from utils.mobile.url_helpers import collapse_urls_to_common_bases

    bases = collapse_urls_to_common_bases(
        {
            "https://api.example.com/v1/users",
            "https://api.example.com/v1/roles",
            "https://api.example.com:8443/admin",
        }
    )

    assert bases == [
        "https://api.example.com",
        "https://api.example.com:8443",
    ]
