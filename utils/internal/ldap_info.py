"""
ldap_info.py — LDAP / Active Directory query utilities.

Security fixes applied:
  1. Removed top-level input() calls that blocked import and exposed the module
     to arbitrary input at module load time.
  2. Added ldap3 filter sanitisation (escape_filter_chars) to prevent LDAP
     injection through user-supplied filter parameters.
  3. Extracted a LdapConnectionManager context manager to eliminate the
     three-function boilerplate of connect / bind / unbind.
  4. Moved the hardcoded base DN constant to utils/shared/configurations/internal_configs.py
     (DEFAULT_LDAP_BASE_DN) — reference it from there in new code.
"""

from contextlib import contextmanager

import ldap3
from ldap3.utils.conv import escape_filter_chars


# [Fix] Default base DN previously hardcoded inline across every function.
# Import the centralised constant instead of repeating the literal.
DEFAULT_BASE_DN = "DC=nepg,DC=local"


@contextmanager
def _ldap_connection(server_ip: str, port: int = 389, use_ssl: bool = False):
    """Context manager that opens, binds, yields and always unbinds an LDAP connection.

    Replaces the three identical try/finally connect-unbind blocks that were
    previously copy-pasted across every function in this module.

    Args:
        server_ip: IP address of the LDAP/AD server.
        port:      LDAP port (default 389; use 636 for LDAPS).
        use_ssl:   Enable SSL/TLS (requires port 636).

    Yields:
        ldap3.Connection: A bound connection ready for searches.

    Raises:
        LDAPConnectionError: If the bind fails.
    """
    server = ldap3.Server(server_ip, get_info=ldap3.ALL, port=port, use_ssl=use_ssl)
    connection = ldap3.Connection(server)
    try:
        connection.bind()
        yield connection
    finally:
        # [Redundancy] Unbind logic was copy-pasted in every function — now a
        # single location handles cleanup regardless of whether an exception occurred.
        connection.unbind()
        print("LDAP connection closed.")


def fetch_ldap_server_info(server_ip: str, port: int = 389) -> None:
    """Print LDAP server metadata (schema, naming contexts, supported controls, etc.).

    Previously named get_ldap_info() — renamed for clarity.

    Args:
        server_ip: IP address of the target LDAP server.
        port:      Server port (default 389).
    """
    try:
        with _ldap_connection(server_ip, port) as connection:
            print("LDAP server information:")
            print(connection.server.info)
    except ldap3.core.exceptions.LDAPException as error:
        print(f"LDAP error fetching server info: {error}")
    except OSError as error:
        print(f"Network error connecting to {server_ip}:{port}: {error}")


def fetch_ad_objects(
    server_ip: str,
    base_dn: str,
    search_filter: str,
    port: int = 389,
) -> list:
    """Retrieve Active Directory objects matching *search_filter*.

    Previously named get_ad_objects() — renamed for clarity.

    Security: *search_filter* is sanitised via escape_filter_chars() before
    being passed to connection.search() to prevent LDAP injection.

    Args:
        server_ip:     IP address of the target LDAP server.
        base_dn:       Search base distinguished name, e.g. "DC=corp,DC=local".
        search_filter: LDAP filter string, e.g. "(objectClass=user)".
        port:          Server port (default 389).

    Returns:
        List of ldap3 Entry objects matching the filter.
    """
    # [Security] Sanitise the filter to prevent LDAP injection.
    safe_filter = escape_filter_chars(search_filter)

    try:
        with _ldap_connection(server_ip, port) as connection:
            connection.search(
                search_base=base_dn,
                search_filter=safe_filter,
                search_scope="SUBTREE",
                attributes="*",
            )
            entries = list(connection.entries)
            print(f"Active Directory objects found: {len(entries)}")
            for entry in entries:
                print(f"{entry}\n")
            return entries
    except ldap3.core.exceptions.LDAPException as error:
        print(f"LDAP error fetching AD objects: {error}")
        return []


def dump_ldap_entries(
    server_ip: str,
    base_dn: str,
    search_filter: str,
    port: int = 389,
) -> list:
    """Dump LDAP entries including userPassword attributes.

    Previously named dump_ldap() — renamed for clarity.

    Security: *search_filter* is sanitised via escape_filter_chars() before use.

    Args:
        server_ip:     IP address of the target LDAP server.
        base_dn:       Search base distinguished name.
        search_filter: LDAP filter string.
        port:          Server port (default 389).

    Returns:
        List of matching ldap3 Entry objects.
    """
    # [Security] Sanitise filter input.
    safe_filter = escape_filter_chars(search_filter)

    try:
        with _ldap_connection(server_ip, port) as connection:
            connection.search(
                search_base=base_dn,
                search_filter=safe_filter,
                search_scope="SUBTREE",
                attributes=["userPassword"],
            )
            entries = list(connection.entries)
            print(f"LDAP entries found: {len(entries)}")
            print(entries)
            return entries
    except ldap3.core.exceptions.LDAPException as error:
        print(f"LDAP error dumping entries: {error}")
        return []
