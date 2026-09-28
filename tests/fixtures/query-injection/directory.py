def find_member(conn, name):
    flt = "(&(objectClass=inetOrgPerson)(cn=" + name + "))"
    return conn.search_s("ou=people,dc=example", 2, flt)

FIXED = "(objectClass=groupOfNames)"
