import pika
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta 
import json
import ldap

def generate_certificate(private_key):
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"TN"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Ariana"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Gazala"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"tekup"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"tekuplive"),
    ])
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=365)
    ).sign(private_key, hashes.SHA256(), default_backend())

    return cert

def save_certificate(cert, filename):
    with open(filename, 'wb') as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
def store_in_ldap(cert, client_id):

    ldap_conn = ldap.initialize("ldap://localhost:389")
    ldap_conn.protocol_version = ldap.VERSION3
    ldap_conn.simple_bind_s("cn=admin,dc=tekuplive", "admin")

    dn = f'cn={client_id},ou=users,dc=tekuplive'

    entry = [
        ('objectClass', [b'top', b'inetOrgPerson']),
        ('cn', client_id.encode("UTF-8")),
        ('userCertificate', cert.public_bytes(serialization.Encoding.DER)),
    ]

    try:
        ldap_conn.modify_s(dn, [(ldap.MOD_ADD, 'userCertificate;binary', cert.public_bytes(serialization.Encoding.DER))])
        print(f"Certificate de {client_id} a ete ajoute au LDAP")
    except ldap.NO_SUCH_OBJECT:
        print(f"{client_id} n'existe pas")
    except ldap.LDAPError as e:
        print(f"LDAP Error: {e}")
    finally:
        ldap_conn.unbind_s()
def callback(ch, method, properties, body):
    print(f"demande de certificate recu: {body}")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    cert = generate_certificate(private_key)
    save_certificate(cert, f"{client_id}_certificate.pem")
    client_data = json.loads(body.decode())
    store_in_ldap(cert, client_data["client_id"])

if __name__ == "__main__":
    connection = pika.BlockingConnection(pika.ConnectionParameters('localhost'))
    channel = connection.channel()

    channel.queue_declare(queue='certificate_request_queue')

    channel.basic_consume(queue='certificate_request_queue',
                          on_message_callback=callback,
                          auto_ack=True)

    print("en attente d'une demande de certificat")
    channel.start_consuming()
