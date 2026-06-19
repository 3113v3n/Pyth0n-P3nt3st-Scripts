import pytest


def test_validate_download_url_rejects_non_https():
    from handlers.package_downloads import validate_download_url

    with pytest.raises(ValueError, match="Blocked non-HTTPS"):
        validate_download_url("http://github.com/tool", {"github.com"})


def test_validate_download_url_rejects_untrusted_host():
    from handlers.package_downloads import validate_download_url

    with pytest.raises(ValueError, match="Blocked untrusted download host"):
        validate_download_url("https://evil.example/tool", {"github.com"})


def test_validate_download_url_allows_trusted_https_host():
    from handlers.package_downloads import validate_download_url

    assert (
        validate_download_url("https://github.com/org/repo", {"github.com"})
        == "https://github.com/org/repo"
    )


def test_build_download_action_uses_curl_for_non_zip_download(tmp_path):
    from handlers.package_downloads import build_download_action

    def action_builder(name, commands, verify_names):
        return {
            "name": name,
            "commands": commands,
            "verify_names": verify_names,
        }

    action = build_download_action(
        tool_name="findomain",
        url="https://github.com/Findomain/Findomain/releases/latest/download/findomain-linux.zip.bin",
        tools_bin_dir=tmp_path,
        sys_executable="/usr/bin/python3",
        validate_url=lambda url: url,
        curl_available=True,
        action_builder=action_builder,
    )

    assert action["name"] == "download:findomain"
    assert action["verify_names"] == ["findomain"]
    assert action["commands"][0][:5] == [
        "curl",
        "--proto",
        "=https",
        "--tlsv1.2",
        "-fsSL",
    ]
    assert action["commands"][1] == ["chmod", "+x", str(tmp_path / "findomain")]


def test_build_download_action_uses_python_fallback_without_curl(tmp_path):
    from handlers.package_downloads import build_download_action

    def action_builder(name, commands, verify_names):
        return {
            "name": name,
            "commands": commands,
            "verify_names": verify_names,
        }

    action = build_download_action(
        tool_name="findomain",
        url="https://github.com/Findomain/Findomain/releases/latest/download/findomain-linux",
        tools_bin_dir=tmp_path,
        sys_executable="/usr/bin/python3",
        validate_url=lambda url: url,
        curl_available=False,
        action_builder=action_builder,
    )

    assert action["commands"][0][0:2] == ["/usr/bin/python3", "-c"]
    assert "urlretrieve" in action["commands"][0][2]


def test_build_download_action_rejects_symlink_destination(tmp_path):
    from handlers.package_downloads import build_download_action

    dest = tmp_path / "findomain"
    dest.symlink_to(tmp_path / "elsewhere")

    with pytest.raises(ValueError, match="Refusing to overwrite symlink destination"):
        build_download_action(
            tool_name="findomain",
            url="https://github.com/Findomain/Findomain/releases/latest/download/findomain-linux",
            tools_bin_dir=tmp_path,
            sys_executable="/usr/bin/python3",
            validate_url=lambda url: url,
            curl_available=False,
            action_builder=lambda name, commands, verify_names: {},
        )
