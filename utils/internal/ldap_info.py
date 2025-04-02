import ldap3
server_ip = input("Enter the LDAP server IP: ")
port = int(input("Enter the LDAP server port: "))

server = ldap3.Server(server_ip, get_info=ldap3.ALL, port=port, use_ssl=False)


def get_ldap_info():
    """Get LDAP server information"""
    try:
        # Connect to the LDAP server
        connection = ldap3.Connection(server)
        connection.bind()
        print("LDAP server information:")
        print(server.info)
    except Exception as e:
        print(f"Error connecting to LDAP server: {e}")
    finally:
        connection.unbind()  # Unbind the connection when done
        print("Connection closed.")


def get_ad_objects(base_dn, filter):
    """Get Active Directory objects"""
    try:
        # Connect to the LDAP server
        connection = ldap3.Connection(server)
        connection.bind()
        print("Active Directory objects:")
        connection.search(search_base=base_dn, search_filter=filter,
                          search_scope='SUBTREE', attributes='*')
        # Print the results
        print(f"Number of entries found: {len(connection.entries)}\n")
        for entry in connection.entries:
            print(f"{entry}\n")
    except Exception as e:
        print(f"Error connecting to LDAP server: {e}")
    finally:
        connection.unbind()  # Unbind the connection when done
        print("Connection closed.")


def dump_ldap(base_dn: str, filter: str):
    """Dump entire ldap"""
    try:
        # Connect to the LDAP server
        connection = ldap3.Connection(server)
        connection.bind()
        print("Active Directory objects:")
        connection.search(search_base=base_dn, search_filter=filter,
                          search_scope='SUBTREE', attributes='userPassword')
        # Print the results
        print(f"Number of entries found: {len(connection.entries)}\n")
        print(connection.entries)
        # for entry in connection.entries:
        #     print(entry)
    except Exception as e:
        print(f"Error connecting to LDAP server: {e}")
    finally:
        connection.unbind()  # Unbind the connection when done
        print("Connection closed.")

base_dn = 'DC=nepg,DC=local' #'dc=vsphere,dc=local'
filter1 = '(&(objectClass=*))'
filter2 = '(&(objectClass=user))'

get_ldap_info()
#get_ad_objects(base_dn, filter1)
#dump_ldap(base_dn, filter2)