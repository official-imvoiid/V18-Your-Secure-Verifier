"""Makes synthetic EF.SOD test files for test/passport/passive_auth_test.dart.

Uses only the ICAO Doc 9303 specimen MRZ (the fictional "ANNA MARIA ERIKSSON"
of "Utopia") and throw-away test keys made by OpenSSL. No real passport data.

    python -I tool/make_sod_fixtures.py <work dir> test/fixtures/sod

Needs `openssl` on PATH (Git for Windows ships one).
"""
import hashlib
import os
import subprocess
import sys

MRZ = ("P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<"
       "L898902C36UTO7408122F1204159ZE184226B<<<<<10").encode("ascii")


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
    b = v.to_bytes(max(1, (v.bit_length() + 8) // 8), "big")
    return tlv(b"\x02", b)


SHA256_ALG = tlv(b"\x30", bytes.fromhex("0609608648016503040201") + b"\x05\x00")


def run(*args):
    subprocess.run(args, check=True, capture_output=True)


def main(work, out):
    os.makedirs(work, exist_ok=True)
    os.makedirs(out, exist_ok=True)
    dg1 = tlv(b"\x61", tlv(b"\x5f\x1f", MRZ))
    dg2_fake = b"\x75\x03abc"  # a stand-in DG2, never read from a chip
    hashes = tlv(b"\x30", b"".join(
        tlv(b"\x30", integer(n) + tlv(b"\x04", hashlib.sha256(d).digest()))
        for n, d in ((1, dg1), (2, dg2_fake))))
    lds = tlv(b"\x30", integer(0) + SHA256_ALG + hashes)
    open(os.path.join(work, "lds.der"), "wb").write(lds)
    open(os.path.join(out, "dg1.bin"), "wb").write(dg1)

    keys = {
        "ec_p256": ["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout"],
        "ec_brainpool_explicit": ["openssl", "ecparam", "-name", "brainpoolP256r1",
                                  "-param_enc", "explicit", "-genkey", "-noout"],
        "rsa": ["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"],
        "rsa_pss": ["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"],
    }
    for name, gen in keys.items():
        key = os.path.join(work, name + ".key")
        crt = os.path.join(work, name + ".crt")
        der = os.path.join(work, name + ".cms")
        run(*gen, "-out", key)
        run("openssl", "req", "-new", "-x509", "-key", key, "-out", crt, "-days", "3650",
            "-subj", "/C=UT/O=Utopia TEST/CN=TEST Document Signer " + name)
        cmd = ["openssl", "cms", "-sign", "-binary", "-nodetach", "-nosmimecap",
               "-in", os.path.join(work, "lds.der"), "-econtent_type", "2.23.136.1.1.1",
               "-signer", crt, "-inkey", key, "-md", "sha256", "-outform", "DER", "-out", der]
        if name == "rsa_pss":
            cmd += ["-keyopt", "rsa_padding_mode:pss", "-keyopt", "rsa_pss_saltlen:32"]
        run(*cmd)
        cms = open(der, "rb").read()
        open(os.path.join(out, "sod_" + name + ".bin"), "wb").write(tlv(b"\x77", cms))
        print("wrote", name)


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
