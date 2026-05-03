#!/usr/bin/python3

import argparse
import cryptography.x509
import grp
import hashlib
import io
import logging
import os.path
import random
import requests
import shutil
import tarfile
import uuid
from datetime import time

NAME_KEY = "private.pem"
LEGACY_NAME_KEY = "private.key"
NAME_CERT = "certificate.crt"
NAME_COMBINED = "combined.pem"

def main():
    logging.basicConfig(level=logging.INFO)

    parser = argparse.ArgumentParser()
    parser.add_argument("--ca-work-directory")

    subparsers = parser.add_subparsers(dest="command")
    enroll_parser = subparsers.add_parser('enroll')
    renew_parser = subparsers.add_parser('renew')
    subparsers.add_parser('update-ca')

    for p in [enroll_parser, renew_parser]:
        p.add_argument("--cert-directory")
        p.add_argument("--cn")
        p.add_argument("--no-system-ca", action="store_true")
        p.add_argument("--group", default=None)

    args = parser.parse_args()

    if args.command == 'update-ca':
        fetch_ca(args)
    else:
        update(args)


def fetch_ca(args):
    response = requests.get("https://ca.yawk.at/ca.tar")
    response.raise_for_status()
    tar_bytes = response.content
    tar_hash = hashlib.sha256(tar_bytes).hexdigest()
    dest_dir = os.path.abspath(os.path.join(args.ca_work_directory, tar_hash))

    if os.path.exists(dest_dir):
        logging.info("CA already up to date")
    else:
        tmp = os.path.join(args.ca_work_directory, "." + tar_hash)
        if os.path.exists(tmp):
            shutil.rmtree(tmp)
        os.makedirs(tmp)
        tar = tarfile.open(fileobj=io.BytesIO(tar_bytes))
        combined = b""
        for i, member in enumerate(tar.getmembers()):
            cert = cryptography.x509.load_pem_x509_certificate(tar.extractfile(member).read())
            cns = cert.subject.get_attributes_for_oid(cryptography.x509.oid.NameOID.COMMON_NAME)
            if len(cns) != 1:
                raise Exception("Invalid number of common names")
            if cns[0].value != "root@ca.local.yawk.at" and cns[0].value != "ca@ca.local.yawk.at":
                raise Exception("Invalid CN")
            for ext in cert.extensions:
                if ext.oid == cryptography.x509.oid.ExtensionOID.NAME_CONSTRAINTS:
                    subtrees = ext.value.permitted_subtrees
                    if len(subtrees) != 1:
                        raise Exception("Invalid number of permitted subtrees")
                    if subtrees[0].value != "local.yawk.at":
                        raise Exception("Invalid permitted subtree")
                elif ext.oid != cryptography.x509.oid.ExtensionOID.BASIC_CONSTRAINTS and ext.oid != cryptography.x509.oid.ExtensionOID.KEY_USAGE and ext.oid != cryptography.x509.oid.ExtensionOID.SUBJECT_KEY_IDENTIFIER:
                    raise Exception("Unknown extension")
            reencoded = cert.public_bytes(cryptography.hazmat.primitives.serialization.Encoding.PEM)
            with open(os.path.join(tmp, "ca_yawk_at_" + str(i) + ".crt"), "wb") as cert_file:
                cert_file.write(reencoded)
            combined += reencoded
        with open(os.path.join(tmp, "ca_yawk_at_combined.crt"), "wb") as cert_file:
            cert_file.write(combined)
        os.rename(tmp, dest_dir)

    latest_link = os.path.join(args.ca_work_directory, "latest")
    try:
        if os.readlink(latest_link) == dest_dir:
            logging.info("System CA link up to date")
            return
        os.remove(latest_link)
    except FileNotFoundError:
        pass
    os.symlink(dest_dir, latest_link)
    logging.info("Certificate symlink updated")

    for f in os.listdir(args.ca_work_directory):
        if f != tar_hash and f != "latest":
            p = os.path.join(args.ca_work_directory, f)
            shutil.rmtree(p)
            logging.info("Removed obsolete certificate directory %s", p)

def write_key(args, path, content):
    with open(os.open(path, flags=os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode=0o640), 'wb') as key_file:
        key_file.write(content)
    if args.group is not None:
        os.chown(path, 0, grp.getgrnam(args.group).gr_gid)

def update(args):
    latest_dir = os.path.join(args.cert_directory, "latest")
    existing_cert_file = os.path.join(latest_dir, NAME_CERT)
    existing_key_file = os.path.join(latest_dir, LEGACY_NAME_KEY)
    enroll = args.command == "enroll"
    verify = not args.no_system_ca
    if enroll:
        if os.path.exists(existing_cert_file):
            logging.info("Certificate already present, skipping enrollment")
            return
    else:
        if not os.path.exists(existing_cert_file):
            raise Exception("Certificate file does not exist, not enrolled?")

    session_id = str(uuid.uuid4())
    dest = os.path.join(args.cert_directory, session_id)
    os.makedirs(dest)

    logging.info("Generating CSR")
    key = cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key(public_exponent=65537, key_size=2048)

    private_pem = key.private_bytes(
        cryptography.hazmat.primitives.serialization.Encoding.PEM,
        format=cryptography.hazmat.primitives.serialization.PrivateFormat.PKCS8,
        encryption_algorithm=cryptography.hazmat.primitives.serialization.NoEncryption()
    )
    write_key(args, os.path.join(dest, NAME_KEY), private_pem)
    write_key(args, os.path.join(dest, "private.der"), key.private_bytes(
        cryptography.hazmat.primitives.serialization.Encoding.DER,
        format=cryptography.hazmat.primitives.serialization.PrivateFormat.PKCS8,
        encryption_algorithm=cryptography.hazmat.primitives.serialization.NoEncryption()
    ))

    csr = cryptography.x509.CertificateSigningRequestBuilder().subject_name(cryptography.x509.Name([
        cryptography.x509.NameAttribute(cryptography.x509.oid.NameOID.COMMON_NAME, args.cn),
    ])).sign(key, cryptography.hazmat.primitives.hashes.SHA256())

    logging.info("Submitting CSR")
    response = requests.post(
        "https://ca.local.yawk.at/csr/" + ("enroll" if enroll else "renew"),
        csr.public_bytes(cryptography.hazmat.primitives.serialization.Encoding.PEM),
        verify=verify,
        cert=(None if enroll else (existing_cert_file, existing_key_file))
    )
    response.raise_for_status()
    cert = cryptography.x509.load_pem_x509_certificate(response.content)
    with open(os.path.join(dest, NAME_CERT), "wb") as cert_file:
        cert_file.write(response.content)
    os.symlink(os.path.join(dest, NAME_KEY), os.path.join(dest, LEGACY_NAME_KEY))
    write_key(args, os.path.join(dest, NAME_COMBINED), response.content + private_pem)
    logging.info("Certificate received, verifying")
    try:
        verification = cryptography.x509.verification
    except AttributeError:
        logging.warning("python-cryptography verification not available")
    else:
        ca_certs = []
        ca_dir = os.path.abspath(os.path.join(args.ca_work_directory, "latest"))
        for f in os.listdir(ca_dir):
            with open(os.path.join(ca_dir, f), "rb") as s:
                ca_certs.append(cryptography.x509.load_pem_x509_certificate(s.read()))
        verification.PolicyBuilder()\
            .store(verification.Store(ca_certs))\
            .build_client_verifier()\
            .verify(cert, [])
        # UDN CN is a bit annoying to verify, so don't do that.

    if not enroll:
        os.remove(os.path.join(latest_dir))
    os.symlink(os.path.abspath(dest), latest_dir)
    logging.info("Done, cleaning up")

    for f in os.listdir(args.cert_directory):
        if f != "latest" and f != session_id:
            shutil.rmtree(os.path.join(args.cert_directory, f))

    logging.info("Pinning cert")
    requests.post(
        "https://ca.local.yawk.at/csr/pin",
        verify=verify,
        cert=(existing_cert_file, existing_key_file)
    ).raise_for_status()


if __name__ == '__main__':
    main()
