from utils.internal.scan_session import ScanSessionStore


def test_create_session_persists_and_indexes_unresponsive_file(tmp_path, monkeypatch):
    output_dir = tmp_path / "Internal"
    output_dir.mkdir()

    store = ScanSessionStore(str(output_dir))
    monkeypatch.setattr(
        store,
        "build_interface_snapshot",
        lambda name: {
            "name": name,
            "mac": "00:11:22:33:44:55",
            "ipv4_at_start": "10.0.0.5",
            "if_type": "ethernet",
        },
    )

    live_file = output_dir / "live.csv"
    unresponsive_file = output_dir / "unresponsive.csv"
    session = store.create_session(
        subnet_cidr="10.0.0.5/24",
        interface_name="eth0",
        live_file=str(live_file),
        unresponsive_file=str(unresponsive_file),
    )

    loaded = store.get_session_by_unresponsive_file(str(unresponsive_file))

    assert loaded is not None
    assert loaded["session_id"] == session["session_id"]
    assert loaded["subnet_cidr"] == "10.0.0.0/24"
    assert loaded["files"]["unresponsive_hosts"] == str(unresponsive_file.resolve())
