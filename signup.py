import hashlib
import ldap

def login(login, pwd):
    user_dn = "cn=" + login + ",ou=users,dc=tekuplive"
    LDAP_BASE_DN = "ou=users,dc=tekuplive"
    ldap_client = ldap.initialize("ldap://localhost:389")
    search_filter = f"(cn={login})"
    hashed_pwd = hashlib.sha256(pwd.encode("UTF-8")).hexdigest()
    try:
        ldap_client.bind_s(user_dn, hashed_pwd)
        print("bonjour")
    except ldap.INVALID_CREDENTIALS:
        print("username ou password invalide")
    except ldap.LDAPError as e:
        print(f"LDAP Error: {e}")

def register(numC, nom, prenom, email, login, genre, pwd):
    dn = 'cn=' + login + ',ou=users,dc=tekuplive'
    hashed_pwd = hashlib.sha256(pwd.encode("UTF-8")).hexdigest()
    entry = [
        ('objectClass', [b'top', b'person', b'organizationalPerson', b'inetOrgPerson']),
        ('uid', numC.encode("UTF-8")),
        ('givenname', nom.encode("UTF-8")),
        ('sn', prenom.encode("UTF-8")),
        ('mail', email.encode("UTF-8")),
        ('cn', login.encode("UTF-8")),
        ("title", genre.encode("UTF-8")),
        ('userPassword', hashed_pwd.encode("UTF-8"))]
    ldap_conn = ldap.initialize("ldap://localhost:389")
    ldap_conn.protocol_version = ldap.VERSION3
    ldap_conn.simple_bind_s("cn=admin,dc=tekuplive", "admin")
    
    try:
        ldap_conn.add_s(dn, entry)
        print("success")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        ldap_conn.unbind_s()
register("001", "John", "Doe", "john@example.com", "john_doe", "male", "password")
login("john_doe", "password")
