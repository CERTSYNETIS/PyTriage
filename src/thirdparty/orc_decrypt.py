#! /usr/bin/env python
# -*- coding:utf-8 -*-
#
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Copyright © 2011-2020 ANSSI. All Rights Reserved.
#
# Author(s): Ryad Benadjila (ANSSI), Sebastien Chapiron (ANSSI), Arnaud Ebalard (ANSSI)
#

import logging
import os
import re
import struct
import subprocess  # nosec B404 - checked
from pathlib import Path
from shutil import which
from tempfile import mkstemp
from typing import Optional
from typing import Tuple
from typing import Union

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.ciphers import modes
from cryptography.hazmat.primitives.hashes import HashAlgorithm
from cryptography.hazmat.primitives.serialization import load_pem_private_key

rsa_oaep_oid = re.compile(re.escape(bytes.fromhex("06092a864886f70d010107")))
rsa_encryption_oid = re.compile(re.escape(bytes.fromhex("06092a864886f70d0101010500")))
pkcs7_data_oid = bytes.fromhex("06092a864886f70d010701")


def decrypt_archive(
    archive_path: Path,
    private_key: Union[Path, bytes],
    output_file: Path,
    unstream_cmd: Path,
    method: str = "auto",
    force: bool = False,
    password: Union[bytes, None] = None,
    log=None,
) -> bool:
    log.info("Processing archive %s", archive_path)

    if output_file.exists() and not force:
        log.error(
            "Output file %s already exists, skipping (use --force to overwrite)",
            output_file,
        )
        return False

    output_file.parent.mkdir(parents=True, exist_ok=True)
    openssl_cmd = which("openssl")

    if archive_path.stat().st_size >= 2**32 / 2 - 1:
        if method == "auto" or method == "python":
            res = decrypt_archive_python(
                archive_path,
                private_key,
                output_file,
                unstream_cmd,
                password=password,
                log=log,
            )
        else:
            log.warning(
                "Processing archive %s with OpenSSL will likely fail because file is too big (%d bytes) !",
                archive_path,
                archive_path.stat().st_size,
            )
            res = decrypt_archive_openssl(
                archive_path,
                private_key,
                output_file,
                unstream_cmd,
                openssl_cmd,
                password=password,
                log=log,
            )
    else:
        if method == "auto":
            if not openssl_cmd or not Path(openssl_cmd).exists():
                log.warning(
                    "OpenSSL binary could not be found in the PATH, falling back to python decryption."
                )
                res = decrypt_archive_python(
                    archive_path,
                    private_key,
                    output_file,
                    unstream_cmd,
                    password=password,
                    log=log,
                )
            else:
                res = decrypt_archive_openssl(
                    archive_path,
                    private_key,
                    output_file,
                    unstream_cmd,
                    openssl_cmd,
                    password=password,
                    log=log,
                )
        elif method == "openssl":
            res = decrypt_archive_openssl(
                archive_path,
                private_key,
                output_file,
                unstream_cmd,
                openssl_cmd,
                password=password,
                log=log,
            )
        else:
            res = decrypt_archive_python(
                archive_path,
                private_key,
                output_file,
                unstream_cmd,
                password=password,
                log=log,
            )

    if res:
        log.info("Successfully decrypted archive into %s", output_file)
    else:
        log.error("Failed to decrypt archive")
    return res


def decrypt_archive_python(
    archive_path: Path,
    private_key: Union[Path, bytes],
    output_file: Path,
    unstream_cmd: Path,
    hash_algo: HashAlgorithm = hashes.SHA1(),  # nosec B303 - Not used for encryption, only decryption
    password: Union[bytes, None] = None,
    log=None,
) -> bool:
    log.debug(
        "Decrypting archive with private key %s using Python implementation",
        private_key,
    )

    def get_cipher(oid: str, key: bytes, iv: bytes):
        if oid == "2.16.840.1.101.3.4.1.42":  # AES 256 CBC
            log.debug("Using AES-256-CBC (OID %s) for decryption", oid)
            ret = Cipher(algorithms.AES(key), modes.CBC(iv))
        elif oid == "2.16.840.1.101.3.4.1.2":  # AES 128 CBC
            log.debug("Using AES-128-CBC (OID %s) for decryption", oid)
            ret = Cipher(algorithms.AES(key), modes.CBC(iv))
        elif oid == "1.2.840.113549.3.7":  # dES-EDE3-CBC
            log.debug("Using 3DES-CBC (OID %s) for decryption", oid)
            ret = Cipher(algorithms.TripleDES(key), modes.CBC(iv))
        else:
            raise NotImplementedError(f"Unknown encryption algorithm w/ OID {oid}")
        return ret

    def decode_oid(oid: bytes) -> str:
        if not (oid[0] == 6 and oid[1] == len(oid) - 2):
            raise ValueError(
                f"Not an OID: {oid.hex()}. Check first byte ({oid[0]}) and length {len(oid) - 2} with second byte ({oid[1]})."
            )
        orig_oid = oid
        oid = oid[2:]

        res = []
        res.append(int(oid[0] / 40))
        res.append(oid[0] - (40 * res[0]))
        oid = oid[1:]

        cur = 0
        while oid:
            tmp = oid[0]
            cur <<= 7
            if tmp & 0x80:
                cur |= tmp - 0x80
            else:
                cur |= tmp
                res.append(cur)
                cur = 0
            oid = oid[1:]

        log.debug(
            "Decoded bytes %s as OID %s",
            orig_oid.hex(),
            ".".join(map(lambda x: "%d" % x, res)),
        )
        return ".".join(map(lambda x: "%d" % x, res))

    # Load the private key and the base 64 ciphertext.
    if isinstance(private_key, Path):
        private_key = open(private_key, "rb").read()
    pkey = load_pem_private_key(private_key, password=password)
    if not isinstance(pkey, RSAPrivateKey):
        raise ValueError(f"Unsupported private key type: {type(pkey)}")

    # We grab the beginning of the file so that we can extract the
    # various information we need (RSA-encrypted symmetric key,
    # encryption algorithm, etc). After having decrypted the key
    # we open the file at the right offset (beginning of octet
    # strings containing data) and decrypt the data.
    s = open(archive_path, "rb").read(50 * 1024)

    # Next, we jump to pkcs7-data OID. It is followed by three bytes
    # before the beginning of symmetric encryption method OID
    pkcs7_offset = s.find(pkcs7_data_oid) + len(pkcs7_data_oid) + 2
    oidlen = s[pkcs7_offset + 1]
    sym_enc_oid = decode_oid(s[pkcs7_offset : pkcs7_offset + oidlen + 2])

    # Next elements is IV
    iv_offset = pkcs7_offset + oidlen + 2
    ivlen = s[iv_offset + 1]
    iv = s[iv_offset + 2 : iv_offset + ivlen + 2]

    symkey = None
    cipher = None
    match_rsaes_oaep = rsa_oaep_oid.findall(s)
    match_rsa_encryption = rsa_encryption_oid.findall(s)
    log.debug(
        "Found %d potential recipients with RSAES-OAEP OID and %d potential recipients with rsaEncryption OID",
        len(match_rsaes_oaep),
        len(match_rsa_encryption),
    )
    # First try with RSAES-OAEP OID
    if len(match_rsaes_oaep) > 0:
        for i, match in enumerate(rsa_oaep_oid.finditer(s), start=1):
            # Next we should have 04|82|len|rsaencryptedsymkey
            key_offset = match.end() + 4
            encsymkeylen = struct.unpack(">H", s[key_offset : key_offset + 2])[0]
            encsymkey = s[key_offset + 2 : key_offset + 2 + encsymkeylen]
            log.debug(
                "Found potential RSAES-OAEP OID at offset 0x%x, with encrypted symmetric key length %d",
                match.start(),
                encsymkeylen,
            )
            try:
                symkey = pkey.decrypt(
                    encsymkey,
                    padding=padding.OAEP(
                        mgf=padding.MGF1(algorithm=hash_algo),
                        algorithm=hash_algo,
                        label=None,
                    ),
                )
                cipher = get_cipher(sym_enc_oid, symkey, iv)
                log.debug(
                    "Successfully decrypted symmetric key (length %d) for recipient n°%d found with RSAES-OAEP OID at offset 0x%x",
                    len(symkey),
                    i,
                    match.start(),
                )
                break
            except ValueError as e:
                log.warning(
                    "Failed to decrypt symmetric key for recipient n°%d found with RSAES-OAEP OID at offset 0x%x: %s",
                    i,
                    match.start(),
                    e,
                )
        else:
            log.warning(
                "Failed to decrypt any of the %d symmetric keys found with RSAES-OAEP OID",
                len(match_rsaes_oaep),
            )

    if not symkey and len(match_rsa_encryption) > 0:
        # Try with rsaEncryption OID
        for i, match in enumerate(rsa_encryption_oid.finditer(s), start=1):
            # Next we should have 04|82|len|rsaencryptedsymkey
            key_offset = match.end() + 2
            encsymkeylen = struct.unpack(">H", s[key_offset : key_offset + 2])[0]
            encsymkey = s[key_offset + 2 : key_offset + 2 + encsymkeylen]
            log.debug(
                "Found potential rsaEncryption OID at offset 0x%x, with encrypted symmetric key length %d",
                match.start(),
                encsymkeylen,
            )
            try:
                symkey = pkey.decrypt(encsymkey, padding=padding.PKCS1v15())
                cipher = get_cipher(sym_enc_oid, symkey, iv)
                log.debug(
                    "Successfully decrypted symmetric key (length %d) for recipient n°%d, "
                    "found with rsaEncryption OID at offset 0x%x",
                    len(symkey),
                    i,
                    match.start(),
                )
                break
            except ValueError as e:
                log.debug(
                    "Failed to decrypt symmetric key for recipient n°%d, "
                    "found with rsaEncryption OID at offset 0x%x: %s",
                    i,
                    match.start(),
                    e,
                )
        else:
            log.warning(
                "Failed to decrypt any of the %d symmetric keys found with rsaEncryption OID",
                len(rsa_encryption_oid.findall(s)),
            )

    if not symkey or not cipher:
        return False

    # We should now have all our octet strings providing encrypted
    # content after a A0 80
    content_offset = iv_offset + ivlen + 2
    if s[content_offset : content_offset + 2] != b"\xA0\x80":
        log.error(
            "File does not match what we expected (\\xA0\\x80) at offset %d: %s. Found at %d",
            content_offset,
            s[content_offset - 10 : content_offset + 20].hex(),
            s[813:].find(b"\xA0\x80"),
        )
        return False

    with open(archive_path, "rb") as f:
        f.seek(content_offset + 2)
        log.debug("Writing to %s", output_file)
        # Remove output file if it exists so that unstream does not fail
        if output_file.exists():
            output_file.unlink()

        decryptor = cipher.decryptor()
        try:
            p = subprocess.Popen(  # nosec B603 - unstream_cmd is checked for type and existence, variables are quoted
                [unstream_cmd.resolve(), "-", output_file.resolve()],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            assert p.stdin is not None  # nosec B101 - only for type hinting
            t, c = struct.unpack("BB", f.read(2))
            prev = bytes()
            while t == 0x04:
                if c & 0x80 == 0:
                    oslen = c
                else:
                    oslen = int.from_bytes(f.read(c & 0x7F), byteorder="big")
                # Revisit to deal with incomplete read
                p.stdin.write(prev)
                try:
                    prev = decryptor.update(f.read(oslen))
                except ValueError as e:
                    log.error(
                        "Failed to decrypt %d bytes at offset %d: %s",
                        oslen,
                        f.tell(),
                        e,
                    )
                h = f.read(2)
                if not h:
                    break
                t, c = struct.unpack("BB", h)

            # We need to remove possible padding from last decrypted chunk
            if len(prev) > 1 and len(prev) > prev[-1]:
                prev = prev[: -prev[-1]]
                p.stdin.write(prev)
        except BrokenPipeError:
            pass
        out, err = p.communicate()
        if err:
            for line in err.splitlines():
                log.error("[unstream] %s", line.decode("utf-8"))
        if p.returncode != 0:
            return False
    return True


def decrypt_archive_openssl(
    archive_path: Path,
    private_key: Union[Path, bytes],
    output_file: Path,
    unstream_cmd: Path,
    openssl_cmd: Optional[str],
    password: Union[bytes, None] = None,
    log=None,
) -> bool:
    if not openssl_cmd or not Path(openssl_cmd).exists():
        raise FileNotFoundError("OpenSSL binary could not be found in the PATH")
    openssl_cmd = Path(openssl_cmd).resolve()  # type: ignore[assignment]

    log.debug("Decrypting archive with private key %s using OpenSSL", private_key)

    # Remove output file if it exists so that unstream does not fail
    if output_file.exists():
        output_file.unlink()

    # Create a temporary file for the in-memory private key
    if isinstance(private_key, bytes):
        f_key, tmp_name = mkstemp()
        os.write(f_key, private_key)
        os.close(f_key)
        private_key_path = Path(tmp_name)
    else:
        private_key_path = private_key

    args: Tuple = (
        openssl_cmd,
        "cms",
        "-decrypt",
        "-in",
        archive_path.resolve(),
        "-inform",
        "DER",
        "-inkey",
        private_key_path.resolve(),
        "-binary",
    )
    if password:
        args += (
            "-passin",
            f"pass:{password.decode('utf-8')}",
        )
    openssl_p = subprocess.Popen(  # nosec B603 - unstream_cmd is checked for type and existence, and variables are quoted
        args=args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    unstream_p = subprocess.Popen(  # nosec B603 - unstream_cmd is checked for type and existence, and variables are quoted
        [unstream_cmd.resolve(), "-", output_file.resolve()],
        stdin=openssl_p.stdout,
        stderr=subprocess.PIPE,
    )

    _, err = unstream_p.communicate()
    if err:
        for line in err.splitlines():
            log.error("[unstream stderr] %s", line.decode("utf-8"))

    _, err = openssl_p.communicate()
    if err:
        for line in err.splitlines():
            log.error("[openssl stderr] %s", line.decode("utf-8"))

    # Remove temporary file
    if isinstance(private_key, bytes):
        private_key_path.unlink()

    if (
        openssl_p.returncode == 0
        and unstream_p.returncode == 0
        and output_file.exists()
        and output_file.stat().st_size > 0
    ):
        return True
    else:
        log.error(
            "Decrypting archive %s with openssl (exit code: %d) and unstream (exit code: %d) failed. "
            "Decrypted output size was: %d",
            archive_path,
            openssl_p.returncode,
            unstream_p.returncode,
            output_file.stat().st_size,
        )
        if output_file.exists():
            output_file.unlink()
        return False
