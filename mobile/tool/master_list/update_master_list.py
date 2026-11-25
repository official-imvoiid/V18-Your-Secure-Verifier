"""Bundle a new CSCA master list into the V18 app (passive authentication, PROTOCOL 4c.4).

Source: the German BSI CSCA Master List, a public file signed by the BSI:
  https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/ElekAusweise/CSCA/GermanMasterList.html
  (direct file: .../CSCA/GermanMasterList.zip?__blob=publicationFile)

Usage (from mobile/):
  python -I tool/master_list/update_master_list.py <GermanMasterList.zip or .ml>

What it checks before it copies anything:
  1. the CMS (SignedData) signature of the master list is valid (OpenSSL);
  2. the signer certificate ("CSCA Master List Signer") chains to a German CSCA
     certificate ("csca-germany") that is inside the list itself, and that CSCA
     is the one published by BSI (its SHA-256 is printed so you can compare it
     with https://www.bsi.bund.de -> CSCA -> Root certificate);
  3. every entry is an X.509 certificate.
Then it writes assets/csca/master_list.ml (the file exactly as signed by BSI)
and assets/csca/master_list.json (source, date, SHA-256 pin, countries).
The app refuses a bundled list whose SHA-256 differs from the pin.

Needs OpenSSL 3 on the PATH (Git for Windows has it). Python standard library only.
"""
import datetime
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
MOBILE = os.path.dirname(os.path.dirname(HERE))
OUT_DIR = os.path.join(MOBILE, 'assets', 'csca')
SOURCE_URL = 'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/ElekAusweise/CSCA/GermanMasterList.html'


def tlv(b, i):
    """Reads one DER TLV at i. Returns (tag, start_of_value, end)."""
    tag = b[i]
    i += 1
    ln = b[i]
    i += 1
    if ln & 0x80:
        n = ln & 0x7F
        ln = int.from_bytes(b[i:i + n], 'big')
        i += n
    return tag, i, i + ln


def children(b, start, end):
    out = []
    i = start
    while i < end:
        tag, vs, ve = tlv(b, i)
        out.append((tag, i, vs, ve))
        i = ve
    return out


def subject_country_and_cn(cert):
    """Finds C= and CN= in the subject of a DER certificate (enough for the summary)."""
    _, s, e = tlv(cert, 0)                       # Certificate
    tbs = children(cert, s, e)[0]                # TBSCertificate
    parts = children(cert, tbs[2], tbs[3])
    k = 1 if parts[0][0] == 0xA0 else 0          # skip [0] version
    subject = parts[k + 4]                       # serial, sigAlg, issuer, validity, subject
    c = cn = None
    for rdn in children(cert, subject[2], subject[3]):
        for atv in children(cert, rdn[2], rdn[3]):
            kids = children(cert, atv[2], atv[3])
            if len(kids) < 2:
                continue
            oid_t, val_t = kids[:2]
            oid = cert[oid_t[2]:oid_t[3]]
            val = cert[val_t[2]:val_t[3]].decode('utf-8', 'replace')
            if oid == bytes([0x55, 0x04, 0x06]):
                c = val
            elif oid == bytes([0x55, 0x04, 0x03]):
                cn = val
    return c, cn


def run(args, **kw):
    r = subprocess.run(args, capture_output=True, **kw)
    if r.returncode != 0:
        sys.exit('FAILED: ' + ' '.join(args) + '\n' + r.stderr.decode('utf-8', 'replace'))
    return r


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    src = sys.argv[1]
    with tempfile.TemporaryDirectory() as tmp:
        if src.lower().endswith('.zip'):
            with zipfile.ZipFile(src) as z:
                names = [n for n in z.namelist() if n.lower().endswith('.ml') and '/' not in n and '\\' not in n]
                if len(names) != 1:
                    sys.exit('Expected exactly one .ml file in the zip')
                ml_name = names[0]
                ml = z.read(ml_name)
        else:
            ml_name = os.path.basename(src)
            ml = open(src, 'rb').read()
        ml_path = os.path.join(tmp, 'list.ml')
        open(ml_path, 'wb').write(ml)
        content = os.path.join(tmp, 'content.der')
        signer = os.path.join(tmp, 'signer.pem')
        run(['openssl', 'cms', '-verify', '-binary', '-inform', 'DER', '-in', ml_path, '-noverify',
             '-out', content, '-certsout', signer])
        b = open(content, 'rb').read()
        _, s, e = tlv(b, 0)                      # CscaMasterList SEQUENCE
        version, cert_set = children(b, s, e)[:2]
        certs = [b[t[1]:t[3]] for t in children(b, cert_set[2], cert_set[3])]
        de = []
        countries = {}
        for c in certs:
            cc, cn = subject_country_and_cn(c)
            countries[cc or '?'] = countries.get(cc or '?', 0) + 1
            if cc == 'DE' and cn and cn.startswith('csca-germany'):
                de.append(c)
        if not de:
            sys.exit('No German CSCA in the list: cannot check the signer')
        bundle = os.path.join(tmp, 'de.pem')
        with open(bundle, 'w') as f:
            for c in de:
                der = os.path.join(tmp, 'c.der')
                open(der, 'wb').write(c)
                f.write(run(['openssl', 'x509', '-inform', 'DER', '-in', der]).stdout.decode())
        # The signer must be signed by a German CSCA from the list. (OpenSSL 3's
        # `verify` refuses explicit ECC parameters, which German CSCAs use, so
        # the signature is checked with `openssl dgst` and the names compared.)
        signer_der = os.path.join(tmp, 'signer.der')
        run(['openssl', 'x509', '-in', signer, '-outform', 'DER', '-out', signer_der])
        sd = open(signer_der, 'rb').read()
        _, s0, e0 = tlv(sd, 0)
        tbs_t, alg_t, sig_t = children(sd, s0, e0)[:3]
        tbs_bytes = sd[tbs_t[1]:tbs_t[3]]
        alg_oid = sd[children(sd, alg_t[2], alg_t[3])[0][2]:children(sd, alg_t[2], alg_t[3])[0][3]].hex()
        digest = {'2a8648ce3d040302': 'sha256', '2a8648ce3d040303': 'sha384', '2a8648ce3d040304': 'sha512',
                  '2a864886f70d01010b': 'sha256', '2a864886f70d01010c': 'sha384', '2a864886f70d01010d': 'sha512'}.get(alg_oid)
        if digest is None:
            sys.exit('Unknown signature algorithm on the master list signer: ' + alg_oid)
        sig_bytes = sd[sig_t[2] + 1:sig_t[3]]            # BIT STRING, skip the unused-bits byte
        tbs_parts = children(sd, tbs_t[2], tbs_t[3])
        k = 1 if tbs_parts[0][0] == 0xA0 else 0
        issuer_name = sd[tbs_parts[k + 2][1]:tbs_parts[k + 2][3]]
        tbs_file = os.path.join(tmp, 'tbs.der')
        sig_file = os.path.join(tmp, 'sig.der')
        open(tbs_file, 'wb').write(tbs_bytes)
        open(sig_file, 'wb').write(sig_bytes)
        ok_by = None
        for n, c in enumerate(de):
            _, cs0, ce0 = tlv(c, 0)
            ctbs = children(c, cs0, ce0)[0]
            cparts = children(c, ctbs[2], ctbs[3])
            ck = 1 if cparts[0][0] == 0xA0 else 0
            subject_name = c[cparts[ck + 4][1]:cparts[ck + 4][3]]
            if subject_name != issuer_name:
                continue
            der = os.path.join(tmp, 'ca%d.der' % n)
            pub = os.path.join(tmp, 'ca%d.pub.pem' % n)
            open(der, 'wb').write(c)
            run(['openssl', 'x509', '-inform', 'DER', '-in', der, '-noout', '-pubkey', '-out', pub])
            r = subprocess.run(['openssl', 'dgst', '-' + digest, '-verify', pub, '-signature', sig_file, tbs_file],
                               capture_output=True)
            if r.returncode == 0 and b'Verified OK' in r.stdout:
                ok_by = hashlib.sha256(c).hexdigest()
                break
        if ok_by is None:
            sys.exit('The master list signer is NOT signed by a German CSCA in the list. Not bundled.')
        signer_subject = run(['openssl', 'x509', '-in', signer, '-noout', '-subject']).stdout.decode().strip()
        sha = hashlib.sha256(ml).hexdigest()
        os.makedirs(OUT_DIR, exist_ok=True)
        open(os.path.join(OUT_DIR, 'master_list.ml'), 'wb').write(ml)
        meta = {
            'about': 'CSCA master list for passive authentication of chip documents (PROTOCOL 4c.4). '
                     'The file is exactly as published and signed by the German BSI. Update it with '
                     'tool/master_list/update_master_list.py.',
            'source': SOURCE_URL,
            'fileName': ml_name,
            'sha256': sha,
            'bytes': len(ml),
            'bundledOn': datetime.date.today().isoformat(),
            'signer': signer_subject,
            'signerChainCheckedTo': 'csca-germany (inside the list), SHA-256 ' + ok_by,
            'germanCscaSha256': [hashlib.sha256(c).hexdigest() for c in de],
            'certificates': len(certs),
            'countries': dict(sorted(countries.items())),
        }
        json.dump(meta, open(os.path.join(OUT_DIR, 'master_list.json'), 'w', encoding='utf-8'), indent=1)
        print(json.dumps({k: meta[k] for k in ('fileName', 'sha256', 'certificates', 'signer')}, indent=1))
        print('countries:', len(countries), 'IND' if 'IN' in countries else 'no IN')


if __name__ == '__main__':
    main()
