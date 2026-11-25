"""Makes a complete TEST chip document for V18's chip tests (no real person, no real country).

    python -I tool/make_emrtd_fixtures.py <work dir>

Writes test/fixtures/emrtd/ and assets/csca/test/v18-test-csca.der:
- a TEST CSCA ("Utopia", C=UT, the ICAO specimen country) and a TEST Document
  Signer certificate it signed;
- for two made-up holders (an adult and an under-18), the files a chip holds:
  EF.COM, DG1 (MRZ), DG14 (Active Authentication info), DG15 (AA public key)
  and EF.SOD (hashes of DG1/14/15, CMS-signed by the TEST Document Signer);
- the chip's TEST Active Authentication private key (EC P-256), so the TEST
  chip simulator (test/helpers/test_chip.dart) can answer the copy test.

The app trusts the TEST CSCA ONLY when its V18 server is in dev mode, just like
the Anon Aadhaar TEST key. Needs `openssl` (Git for Windows has it).
"""
import datetime
import hashlib
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
MOBILE = os.path.dirname(HERE)
OUT = os.path.join(MOBILE, 'test', 'fixtures', 'emrtd')
ASSET = os.path.join(MOBILE, 'assets', 'csca', 'test')


def tlv(tag: bytes, value: bytes) -> bytes:
    n = len(value)
    if n < 0x80:
        length = bytes([n])
    elif n < 0x100:
        length = bytes([0x81, n])
    else:
        length = bytes([0x82, n >> 8, n & 0xFF])
    return tag + length + value


def integer(v: int) -> bytes:
    b = v.to_bytes(max(1, (v.bit_length() + 8) // 8), 'big')
    return tlv(b'\x02', b)


def oid(dotted: str) -> bytes:
    parts = [int(x) for x in dotted.split('.')]
    body = bytes([parts[0] * 40 + parts[1]])
    for p in parts[2:]:
        chunk = [p & 0x7F]
        p >>= 7
        while p:
            chunk.append(0x80 | (p & 0x7F))
            p >>= 7
        body += bytes(reversed(chunk))
    return tlv(b'\x06', body)


def run(*args, inp=None):
    r = subprocess.run(args, capture_output=True, input=inp)
    if r.returncode != 0:
        sys.exit('FAILED ' + ' '.join(args) + '\n' + r.stderr.decode())
    return r.stdout


def check_digit(s: str) -> str:
    w = [7, 3, 1]
    total = 0
    for i, ch in enumerate(s):
        if ch.isdigit():
            v = int(ch)
        elif ch == '<':
            v = 0
        else:
            v = ord(ch) - 55
        total += v * w[i % 3]
    return str(total % 10)


def td3(doc_no, dob, doe, surname, given, sex='<', state='UTO', nat='UTO', optional=''):
    name = (surname + '<<' + given.replace(' ', '<')).ljust(39, '<')[:39]
    line1 = 'P<' + state + name
    doc = doc_no.ljust(9, '<')
    opt = optional.ljust(14, '<')
    l2 = doc + check_digit(doc) + nat + dob + check_digit(dob) + sex + doe + check_digit(doe) + opt + check_digit(opt)
    composite = doc + check_digit(doc) + dob + check_digit(dob) + doe + check_digit(doe) + opt + check_digit(opt)
    l2 += check_digit(composite)
    assert len(line1) == 44 and len(l2) == 44, (len(line1), len(l2))
    return line1 + l2


def main(work):
    os.makedirs(work, exist_ok=True)
    os.makedirs(OUT, exist_ok=True)
    os.makedirs(ASSET, exist_ok=True)
    w = lambda n: os.path.join(work, n)

    ext = w('ext.cnf')
    open(ext, 'w').write(
        '[csca]\nbasicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n'
        'subjectKeyIdentifier=hash\n'
        '[dsc]\nkeyUsage=critical,digitalSignature\nauthorityKeyIdentifier=keyid\nsubjectKeyIdentifier=hash\n')

    # TEST CSCA: EC brainpoolP256r1 with EXPLICIT curve parameters, as many real CSCAs use.
    run('openssl', 'ecparam', '-name', 'brainpoolP256r1', '-param_enc', 'explicit', '-genkey', '-noout', '-out', w('csca.key'))
    run('openssl', 'req', '-new', '-x509', '-key', w('csca.key'), '-out', w('csca.pem'), '-days', '5000', '-sha256',
        '-subj', '/C=UT/O=V18 TEST/OU=NOT A REAL COUNTRY/CN=V18 TEST CSCA', '-extensions', 'csca', '-config', ext)
    # TEST Document Signer: RSA-2048, signed by the CSCA.
    run('openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048', '-out', w('dsc.key'))
    run('openssl', 'req', '-new', '-key', w('dsc.key'), '-out', w('dsc.csr'),
        '-subj', '/C=UT/O=V18 TEST/OU=NOT A REAL COUNTRY/CN=V18 TEST Document Signer')
    run('openssl', 'x509', '-req', '-in', w('dsc.csr'), '-CA', w('csca.pem'), '-CAkey', w('csca.key'),
        '-CAcreateserial', '-out', w('dsc.pem'), '-days', '3650', '-sha256', '-extfile', ext, '-extensions', 'dsc')
    run('openssl', 'x509', '-in', w('csca.pem'), '-outform', 'DER', '-out', os.path.join(ASSET, 'v18-test-csca.der'))
    run('openssl', 'x509', '-in', w('csca.pem'), '-outform', 'DER', '-out', os.path.join(OUT, 'test_csca.der'))
    run('openssl', 'x509', '-in', w('dsc.pem'), '-outform', 'DER', '-out', os.path.join(OUT, 'test_dsc.der'))

    holders = {
        'adult': dict(doc_no='V18T00001', dob='900101', doe='351231', surname='TESTER', given='ADA'),
        'minor': dict(doc_no='V18T00002', dob='120505', doe='321231', surname='TESTER', given='MINA'),
    }
    summary = {'about': 'TEST ONLY. Made-up holders of the ICAO specimen country Utopia (UTO), '
                        'signed by the V18 TEST CSCA. Made by tool/make_emrtd_fixtures.py.',
               'made': datetime.date.today().isoformat(), 'documents': {}}
    for name, h in holders.items():
        mrz = td3(**h)
        dg1 = tlv(b'\x61', tlv(b'\x5f\x1f', mrz.encode('ascii')))
        # Chip's Active Authentication key: EC P-256 (ECDSA, plain signature format).
        run('openssl', 'ecparam', '-name', 'prime256v1', '-genkey', '-noout', '-out', w(name + '_aa.key'))
        aa_spki = run('openssl', 'ec', '-in', w(name + '_aa.key'), '-pubout', '-outform', 'DER')
        aa_priv_der = run('openssl', 'ec', '-in', w(name + '_aa.key'), '-outform', 'DER')
        # ECPrivateKey: SEQUENCE { INTEGER 1, OCTET STRING d, ... } -> take d.
        d_len = aa_priv_der[6]
        d_hex = aa_priv_der[7:7 + d_len].hex()
        dg15 = tlv(b'\x6f', aa_spki)
        # DG14: SecurityInfos with ActiveAuthenticationInfo (ICAO 9303-11 9.2.9):
        #   id-icao-mrtd-security-aaProtocolObject 2.23.136.1.1.5, version 1,
        #   signatureAlgorithm ecdsa-plain-SHA256 (BSI TR-03111) 0.4.0.127.0.7.1.1.4.1.3
        aa_info = tlv(b'\x30', oid('2.23.136.1.1.5') + integer(1) + oid('0.4.0.127.0.7.1.1.4.1.3'))
        dg14 = tlv(b'\x6e', tlv(b'\x31', aa_info))
        com = tlv(b'\x60', tlv(b'\x5f\x01', b'0107') + tlv(b'\x5f\x36', b'040000') + tlv(b'\x5c', b'\x61\x6e\x6f'))
        sha256 = tlv(b'\x30', oid('2.16.840.1.101.3.4.2.1') + b'\x05\x00')
        hashes = tlv(b'\x30', b''.join(
            tlv(b'\x30', integer(n) + tlv(b'\x04', hashlib.sha256(d).digest()))
            for n, d in ((1, dg1), (14, dg14), (15, dg15))))
        lds = tlv(b'\x30', integer(0) + sha256 + hashes)
        open(w(name + '_lds.der'), 'wb').write(lds)
        cms = run('openssl', 'cms', '-sign', '-binary', '-nodetach', '-nosmimecap', '-in', w(name + '_lds.der'),
                  '-econtent_type', '2.23.136.1.1.1', '-signer', w('dsc.pem'), '-inkey', w('dsc.key'),
                  '-md', 'sha256', '-outform', 'DER')
        sod = tlv(b'\x77', cms)
        files = {'ef_com': com, 'dg1': dg1, 'dg14': dg14, 'dg15': dg15, 'sod': sod}
        for k, v in files.items():
            open(os.path.join(OUT, '%s_%s.bin' % (name, k)), 'wb').write(v)
        summary['documents'][name] = {
            'mrz': mrz, 'documentNumber': h['doc_no'], 'dateOfBirth': h['dob'], 'dateOfExpiry': h['doe'],
            'issuingState': 'UTO', 'docType': 'P', 'aaPrivateKeyD': d_hex,
        }
        print('wrote', name, mrz[44:])
    json.dump(summary, open(os.path.join(OUT, 'documents.json'), 'w'), indent=1)


if __name__ == '__main__':
    main(sys.argv[1])
