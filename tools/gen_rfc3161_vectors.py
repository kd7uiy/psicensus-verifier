#!/usr/bin/env python3
"""DEV-TIME ONLY. Generates the checked-in RFC 3161 test vectors under verifier/tests/data.

It drives the openssl CLI (3.4 or newer) as an independent oracle: certificates are issued by openssl,
RSA signatures are made by openssl, every positive token is cross-checked with `openssl ts -verify`.
The verifier itself is stdlib-only; its tests only READ the files written here and never call openssl.

Private keys: they live in --keys-dir, which must be OUTSIDE the repository. Nothing private is ever
written under verifier/. With the same keys dir a rerun reproduces every output byte for byte (RSA
PKCS#1 v1.5 is deterministic and all times and serials are fixed). Exceptions: ECDSA signatures are
randomized (the EC-signed certificate and the ECDSA negative token change on every run) and the one natively
made `openssl ts -reply` token carries the time of the run (it is only rewritten with --refresh-native).
If the keys dir is lost, regenerate and commit ALL outputs together.

Usage: python verifier/tools/gen_rfc3161_vectors.py [--keys-dir DIR] [--openssl EXE] [--refresh-native]
"""
import argparse
import base64
import datetime
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
VERIFIER = HERE.parent
REPO = VERIFIER.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(VERIFIER / "src"))

import derkit as d  # noqa: E402

DATA = VERIFIER / "tests" / "data" / "rfc3161"
WORKER_FIX = REPO / "worker" / "src" / "tsa" / "fixtures"
REAL = ("digicert", "globalsign", "certum")

# ----------------------------------------------------------------------------- constants
H = {
    "sha1": ("1.3.14.3.2.26", hashlib.sha1, "1.2.840.113549.1.1.5"),
    "sha256": ("2.16.840.1.101.3.4.2.1", hashlib.sha256, "1.2.840.113549.1.1.11"),
    "sha384": ("2.16.840.1.101.3.4.2.2", hashlib.sha384, "1.2.840.113549.1.1.12"),
    "sha512": ("2.16.840.1.101.3.4.2.3", hashlib.sha512, "1.2.840.113549.1.1.13"),
}
OID_RSA = "1.2.840.113549.1.1.1"
OID_PSS = "1.2.840.113549.1.1.10"
OID_MGF1 = "1.2.840.113549.1.1.8"
OID_ECDSA_SHA256 = "1.2.840.10045.4.3.2"
OID_SIGNED_DATA = "1.2.840.113549.1.7.2"
OID_TSTINFO = "1.2.840.113549.1.9.16.1.4"
OID_DATA = "1.2.840.113549.1.7.1"
OID_CONTENT_TYPE = "1.2.840.113549.1.9.3"
OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"
OID_ESS_V1 = "1.2.840.113549.1.9.16.2.12"
OID_ESS_V2 = "1.2.840.113549.1.9.16.2.47"

NB_ROOT, NA_ROOT = "20220101000000Z", "20420101000000Z"
NB_CA, NA_CA = "20220601000000Z", "20370601000000Z"
NB_SIGNER, NA_SIGNER = "20230601000000Z", "20240601000000Z"
GEN_MS = 1_700_049_600_000  # 2023-11-15T12:00:00Z, inside every valid window above


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


# ----------------------------------------------------------------------------- openssl wrapper
class OpenSSL:
    def __init__(self, exe: str, keys_dir: Path):
        self.exe = exe
        self.keys = keys_dir
        self.work = keys_dir / "work"
        self.work.mkdir(parents=True, exist_ok=True)
        self.cnf = self.work / "base.cnf"
        self.cnf.write_text("[req]\ndistinguished_name=dn\nprompt=no\n[dn]\nCN=unused\n", encoding="ascii")

    def run(self, *args, data: bytes | None = None) -> bytes:
        p = subprocess.run([self.exe, *map(str, args)], input=data, capture_output=True, cwd=self.work)
        if p.returncode != 0:
            raise RuntimeError(f"openssl {' '.join(map(str, args))} failed:\n{p.stderr.decode(errors='replace')}")
        return p.stdout

    def key(self, name: str, kind: str = "rsa2048") -> Path:
        path = self.keys / f"{name}.key"
        if not path.exists():
            if kind.startswith("rsa"):
                self.run("genrsa", "-out", path, kind[3:])
            else:
                self.run("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", path)
        return path

    def sign(self, key: Path, data: bytes, hash_name: str, *opts: str) -> bytes:
        return self.run("dgst", f"-{hash_name}", "-sign", key, *opts, data=data)

    def cert(self, *, cn: str, key: Path, not_before: str, not_after: str, serial: int, ext: list[str],
             issuer: tuple[bytes, Path] | None = None, sig_hash: str = "sha256") -> bytes:
        """Issue a certificate (DER). issuer = (issuer certificate DER, issuer key); None = self-signed."""
        extfile = self.work / "ext.cnf"
        extfile.write_text("[req]\ndistinguished_name=dn\nprompt=no\n[dn]\nCN=unused\n[ext]\n" + "\n".join(ext) + "\n", encoding="ascii")
        subj = f"/O=Psi Census Test/CN={cn}"
        out = self.work / "cert.der"
        if issuer is None:
            self.run("req", "-x509", "-new", "-batch", "-config", extfile, "-key", key, "-subj", subj,
                     "-set_serial", serial, "-not_before", not_before, "-not_after", not_after,
                     "-extensions", "ext", f"-{sig_hash}", "-outform", "DER", "-out", out)
        else:
            csr = self.work / "req.csr"
            self.run("req", "-new", "-batch", "-config", self.cnf, "-key", key, "-subj", subj, "-out", csr)
            ca_der = self.work / "issuer.der"
            ca_der.write_bytes(issuer[0])
            self.run("x509", "-req", "-in", csr, "-CA", ca_der, "-CAform", "DER", "-CAkey", issuer[1],
                     "-set_serial", serial, "-not_before", not_before, "-not_after", not_after,
                     "-extfile", extfile, "-extensions", "ext", f"-{sig_hash}", "-outform", "DER", "-out", out)
        return out.read_bytes()


# ----------------------------------------------------------------------------- PKIs
CA_EXT = ["basicConstraints=critical,CA:TRUE{pl}", "keyUsage=critical,keyCertSign,cRLSign", "subjectKeyIdentifier=hash"]
SIGNER_EXT = [
    "basicConstraints=critical,CA:FALSE",
    "keyUsage=critical,digitalSignature",
    "extendedKeyUsage=critical,timeStamping",
    "subjectKeyIdentifier=hash",
]


def ca_ext(pathlen: int | None = None, aki: bool = True, ku: str = "keyCertSign,cRLSign", bc: str | None = "CA:TRUE") -> list[str]:
    ext = []
    if bc is not None:
        ext.append("basicConstraints=critical," + bc + (f",pathlen:{pathlen}" if pathlen is not None else ""))
    if ku:
        ext.append("keyUsage=critical," + ku)
    ext.append("subjectKeyIdentifier=hash")
    if aki:
        ext.append("authorityKeyIdentifier=keyid")
    return ext


def signer_ext(*, bc="basicConstraints=critical,CA:FALSE", ku="keyUsage=critical,digitalSignature",
               eku="extendedKeyUsage=critical,timeStamping", extra: list[str] | None = None) -> list[str]:
    ext = [x for x in (bc, ku, eku) if x]
    ext += ["subjectKeyIdentifier=hash", "authorityKeyIdentifier=keyid"]
    return ext + (extra or [])


class Pki:
    """root -> [intermediates] -> issuing CA -> signer. Every certificate is a DER blob."""

    def __init__(self, name, root, root_key, chain, ca, ca_key, signer, signer_key, sig_hash="sha256"):
        self.name, self.root, self.root_key = name, root, root_key
        self.chain = chain  # intermediates, top (just below root) first
        self.ca, self.ca_key = ca, ca_key
        self.signer, self.signer_key = signer, signer_key
        self.sig_hash = sig_hash

    @property
    def embedded(self) -> list[bytes]:
        """Certificates a TSA would put in the token: signer, issuing CA, then the intermediates upwards."""
        return [self.signer, self.ca, *reversed(self.chain)]


def build_pki(o: OpenSSL, name: str, *, key_kind="rsa2048", sig_hash="sha256", serial=1000, n_intermediates=0,
              root_nb=NB_ROOT, root_na=NA_ROOT, ca_nb=NB_CA, ca_na=NA_CA, signer_nb=NB_SIGNER, signer_na=NA_SIGNER,
              intermediate_pathlens: list[int] | None = None, ca_pathlen=0, ca_kwargs=None, signer_ext_lines=None,
              signer_key_name=None, ca_key_kind=None, ca_sig_hash=None, int_nb=None, int_na=None, int_kwargs=None,
              root_kwargs=None, ca_extra=None, int_extra=None, root_extra=None) -> Pki:
    rk = o.key(f"{name}_root", key_kind)
    root = o.cert(cn=f"Test Root {name}", key=rk, not_before=root_nb, not_after=root_na, serial=serial,
                  ext=ca_ext(None, aki=False, **(root_kwargs or {})) + (root_extra or []), sig_hash=sig_hash)
    parent, parent_key = root, rk
    chain = []
    pls = intermediate_pathlens or [n_intermediates - i for i in range(n_intermediates)]
    for i in range(n_intermediates):
        ik = o.key(f"{name}_int{i}", key_kind)
        c = o.cert(cn=f"Test Intermediate {name} {i}", key=ik, not_before=int_nb or ca_nb, not_after=int_na or ca_na, serial=serial + 1 + i,
                   ext=ca_ext(pls[i], **(int_kwargs or {})) + (int_extra or []), issuer=(parent, parent_key), sig_hash=sig_hash)
        chain.append(c)
        parent, parent_key = c, ik
    ck = o.key(f"{name}_ca", ca_key_kind or key_kind)
    ca = o.cert(cn=f"Test Issuing CA {name}", key=ck, not_before=ca_nb, not_after=ca_na, serial=serial + 50,
                ext=ca_ext(ca_pathlen, **(ca_kwargs or {})) + (ca_extra or []), issuer=(parent, parent_key), sig_hash=ca_sig_hash or sig_hash)
    sk = o.key(signer_key_name or f"{name}_signer", key_kind)
    signer = o.cert(cn=f"Test TSA Signer {name}", key=sk, not_before=signer_nb, not_after=signer_na, serial=serial + 99,
                    ext=signer_ext_lines or signer_ext(), issuer=(ca, ck), sig_hash=sig_hash)
    return Pki(name, root, rk, chain, ca, ck, signer, sk, sig_hash)


# ----------------------------------------------------------------------------- token builder
def gen_time_string(ms: int) -> str:
    dt = datetime.datetime.fromtimestamp(ms // 1000, datetime.UTC)
    frac = f"{ms % 1000:03d}".rstrip("0")
    return dt.strftime("%Y%m%d%H%M%S") + (("." + frac) if frac else "") + "Z"


def tstinfo(digest: bytes, gen_ms: int, *, imprint_alg="sha256", params_null=True, serial=1, policy="1.2.3.4.1", nonce=None) -> bytes:
    imprint = d.seq(d.alg(H[imprint_alg][0], d.null() if params_null else b""), d.octet(digest))
    parts = [d.integer(1), d.oid(policy), imprint, d.integer(serial), d.gentime(gen_time_string(gen_ms))]
    if nonce is not None:
        parts.append(d.integer(nonce))
    return d.seq(*parts)


def pss_params(hash_name: str) -> bytes:
    oid_h = H[hash_name][0]
    size = hashlib.new(hash_name).digest_size
    return d.seq(d.ctx(0, d.alg(oid_h)), d.ctx(1, d.alg(OID_MGF1, d.alg(oid_h))), d.ctx(2, d.integer(size)))


def build_token(o: OpenSSL, pki: Pki, *, gen_ms=GEN_MS, digest: bytes, sig_hash="sha256", sigalg="rsa_sha",
                ess="v2", sid="issuer_serial", n_signers=1, certs=None, flip_sig_bit=False, md_override=None,
                ess_override=None, content_type_attr=OID_TSTINFO, econtent_type=OID_TSTINFO, status=0,
                signed_attrs=True, imprint_alg="sha256", signer_key=None, signer_cert=None, bare=False,
                sid_serial_delta=0, serial=7, nonce=None) -> bytes:
    signer_cert = signer_cert or pki.signer
    signer_key = signer_key or pki.signer_key
    fields = d.cert_fields(signer_cert)
    tst = tstinfo(digest, gen_ms, imprint_alg=imprint_alg, serial=serial, nonce=nonce)
    encap = d.seq(d.oid(econtent_type), d.ctx(0, d.octet(tst)))
    md = md_override if md_override is not None else H[sig_hash][1](tst).digest()
    attrs = [d.seq(d.oid(OID_CONTENT_TYPE), d.set_(d.oid(content_type_attr))),
             d.seq(d.oid(OID_MESSAGE_DIGEST), d.set_(d.octet(md)))]
    h1 = ess_override if ess_override is not None else hashlib.sha1(signer_cert).digest()
    h2 = ess_override if ess_override is not None else hashlib.sha256(signer_cert).digest()
    if ess in ("v1", "both"):  # ess == "none": no signing-certificate attribute at all
        attrs.append(d.seq(d.oid(OID_ESS_V1), d.set_(d.seq(d.seq(d.seq(d.octet(h1)))))))
    if ess in ("v2", "both"):
        attrs.append(d.seq(d.oid(OID_ESS_V2), d.set_(d.seq(d.seq(d.seq(d.octet(h2)))))))
    attr_set = d.set_of(*attrs)
    # signature
    if sigalg == "ecdsa":
        sig = o.sign(signer_key, attr_set, "sha256")
        sig_alg = d.alg(OID_ECDSA_SHA256, None)
    elif sigalg == "pss":
        sig = o.sign(signer_key, attr_set, sig_hash, "-sigopt", "rsa_padding_mode:pss",
                     "-sigopt", f"rsa_pss_saltlen:{hashlib.new(sig_hash).digest_size}")
        sig_alg = d.seq(d.oid(OID_PSS), pss_params(sig_hash))
    else:
        sig = o.sign(signer_key, attr_set, sig_hash)
        sig_alg = d.alg(OID_RSA if sigalg == "rsa_enc" else H[sig_hash][2])
        if sigalg == "rsa_mismatch":
            other = "sha384" if sig_hash != "sha384" else "sha256"
            sig_alg = d.alg(H[other][2])
    if flip_sig_bit:
        sig = sig[:-1] + bytes([sig[-1] ^ 0x01])
    if sid == "ski":
        sid_der, version = d.ctx(0, fields["ski"], constructed=False), 3
    else:
        serial_der = fields["serial_der"]
        if sid_serial_delta:
            serial_der = d.integer(int.from_bytes(serial_der[2:], "big") + sid_serial_delta)
        sid_der, version = d.seq(fields["issuer"], serial_der), 1
    si_parts = [d.integer(version), sid_der, d.alg(H[sig_hash][0])]
    if signed_attrs:
        si_parts.append(d.tlv(0xA0, attr_set[_hdr(attr_set):]))
    si_parts += [sig_alg, d.octet(sig)]
    signer_info = d.seq(*si_parts)
    embedded = pki.embedded if certs is None else certs
    sd_parts = [d.integer(3), d.set_(d.alg(H[sig_hash][0])), encap]
    if embedded:
        sd_parts.append(d.tlv(0xA0, b"".join(embedded)))
    sd_parts.append(d.set_(*([signer_info] * n_signers)))
    content = d.seq(d.oid(OID_SIGNED_DATA), d.ctx(0, d.seq(*sd_parts)))
    if bare:
        return content
    return d.seq(d.seq(d.integer(status)), content)


def _hdr(tlv_bytes: bytes) -> int:
    """Length of the tag+length header of a DER element."""
    return 2 if tlv_bytes[1] < 0x80 else 2 + (tlv_bytes[1] & 0x7F)


# ----------------------------------------------------------------------------- openssl text helpers
def parse_x509_text(o: OpenSSL, der: bytes) -> dict:
    path = o.work / "probe.der"
    path.write_bytes(der)
    text = o.run("x509", "-inform", "DER", "-in", path, "-noout", "-text").decode().replace("\r\n", "\n")
    serial = o.run("x509", "-inform", "DER", "-in", path, "-noout", "-serial").decode().strip().split("=")[1].lower()

    def when(flag):
        s = o.run("x509", "-inform", "DER", "-in", path, "-noout", flag).decode().strip().split("=")[1]
        return int(datetime.datetime.strptime(s, "%b %d %H:%M:%S %Y GMT").replace(tzinfo=datetime.UTC).timestamp())

    import re

    sigalg = re.search(r"Signature Algorithm: (\S+)", text).group(1)
    keyalg = re.search(r"Public Key Algorithm: (\S+)", text).group(1)
    bits = int(re.search(r"Public-Key: \((\d+) bit\)", text).group(1))
    exts, critical = {}, []
    for m in re.finditer(r"X509v3 (Basic Constraints|Key Usage|Extended Key Usage): ?(critical)?\n\s+([^\n]*)", text):
        name = {"Basic Constraints": "basicConstraints", "Key Usage": "keyUsage", "Extended Key Usage": "extendedKeyUsage"}.get(m.group(1))
        if name:
            exts[name] = m.group(3).strip()
            if m.group(2):
                critical.append(name)
    for m in re.finditer(r"X509v3 (Basic Constraints|Key Usage|Extended Key Usage): critical", text):
        n = {"Basic Constraints": "basicConstraints", "Key Usage": "keyUsage", "Extended Key Usage": "extendedKeyUsage"}.get(m.group(1))
        if n and n not in critical:
            critical.append(n)
    bc = exts.get("basicConstraints")
    return {
        "serial_hex": serial.lstrip("0") or "0",
        "not_before": when("-startdate"),
        "not_after": when("-enddate"),
        "sig_alg": sigalg,
        "key_alg": keyalg,
        "key_bits": bits,
        "is_ca": None if bc is None else ("CA:TRUE" in bc),
        "path_len": None if not bc or "pathlen:" not in bc else int(bc.split("pathlen:")[1]),
        "key_usage": None if "keyUsage" not in exts else sorted(x.strip() for x in exts["keyUsage"].split(",")),
        "eku": None if "extendedKeyUsage" not in exts else sorted(x.strip() for x in exts["extendedKeyUsage"].split(",")),
        "critical": sorted(critical),
        "critical_other": sorted(re.findall(r"\n\s+(\d+(?:\.\d+)+): critical", text)),
    }


def extract_certs(token: bytes) -> list[bytes]:
    """Certificates [0] of a TimeStampResp, using only the generator's own reader."""
    ci = d.children(token, 0)[1]  # [status, ContentInfo]
    sd = d.children(token, d.children(token, ci[1])[1][1])[0]  # ContentInfo -> [0] -> SignedData
    for k in d.children(token, sd[1]):
        if k[0] == 0xA0:
            out, p = [], k[2]
            while p < k[3]:
                t = d.read(token, p)
                out.append(token[t[1] : t[3]])
                p = t[3]
            return out
    return []


# ----------------------------------------------------------------------------- main
def write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def write_json(path: Path, obj) -> None:
    write(path, (json.dumps(obj, indent=2) + "\n").encode("utf-8"))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--keys-dir", default=str(Path(tempfile.gettempdir()) / "psicensus-rfc3161-devkeys"))
    ap.add_argument("--openssl", default=os.environ.get("OPENSSL") or shutil.which("openssl") or "openssl")
    ap.add_argument("--refresh-native", action="store_true", help="remake the openssl-ts native token (new time)")
    args = ap.parse_args(argv)
    keys_dir = Path(args.keys_dir).resolve()
    if REPO in keys_dir.parents or keys_dir == REPO:
        sys.exit("refusing to keep private keys inside the repository; pass --keys-dir outside it")
    keys_dir.mkdir(parents=True, exist_ok=True)
    o = OpenSSL(args.openssl, keys_dir)
    print("openssl:", o.run("version").decode().strip(), "| keys dir:", keys_dir)

    # ------------------------------------------------------------ real tokens and roots (copies)
    certs_expect: list[dict] = []
    real_cases = []
    for name in REAL:
        tsr = (WORKER_FIX / f"{name}.tsr").read_bytes()
        write(DATA / "real" / f"{name}.tsr", tsr)
    write(DATA / "real" / "digest.hex", (WORKER_FIX / "digest.hex").read_bytes())
    root_files = {p.name: p.read_bytes() for p in sorted((WORKER_FIX / "roots").glob("*.der"))}
    for n, b in root_files.items():
        write(DATA / "roots" / f"{sha(b)}.der", b)
    pins = {  # authorities.ts: issuing CA = certificate 2 of the token, root by file name
        "digicert": ("digicert-trusted-root-g4.der", 1),
        "globalsign": ("globalsign-timestamping-root-r45.der", 1),
        "certum": ("certum-trusted-network-ca-2.der", 1),
    }
    digest_hex = (WORKER_FIX / "digest.hex").read_text().strip()
    for name in REAL:
        tsr = (WORKER_FIX / f"{name}.tsr").read_bytes()
        certs = extract_certs(tsr)
        # oracle: the same certificates as `openssl pkcs7 -print_certs` sees them
        (o.work / "t.tsr").write_bytes(tsr)
        o.run("ts", "-reply", "-in", o.work / "t.tsr", "-token_out", "-out", o.work / "t.token")
        pem = o.run("pkcs7", "-inform", "DER", "-in", o.work / "t.token", "-print_certs").decode()
        blocks = [base64.b64decode("".join(b.split("-----")[0].split())) for b in pem.split("-----BEGIN CERTIFICATE-----")[1:]]
        assert blocks == certs, f"{name}: derkit and openssl disagree on the embedded certificates"
        for i, c in enumerate(certs):
            write(DATA / "real" / "certs" / f"{name}_{i}.der", c)
            certs_expect.append({"file": f"real/certs/{name}_{i}.der", "sha256": sha(c), **parse_x509_text(o, c)})
        text = o.run("ts", "-reply", "-in", o.work / "t.tsr", "-text").decode()
        line = [x for x in text.splitlines() if x.startswith("Time stamp:")][0]
        t = datetime.datetime.strptime(line.split(":", 1)[1].strip().replace("  ", " "), "%b %d %H:%M:%S %Y GMT").replace(tzinfo=datetime.UTC)
        root_name, ca_idx = pins[name]
        real_cases.append({
            "name": name, "file": f"real/{name}.tsr", "digest": digest_hex,
            "entry": {"issuing_ca_sha256": [sha(certs[ca_idx])], "root_sha256": sha(root_files[root_name])},
            "expect": {"ok": True, "gen_time_ms": int(t.timestamp()) * 1000},
        })
    for n, b in root_files.items():
        certs_expect.append({"file": f"roots/{sha(b)}.der", "sha256": sha(b), **parse_x509_text(o, b)})
    write_json(DATA / "real" / "expected.json", {"version": 1, "cases": real_cases})

    # ------------------------------------------------------------ synthetic PKIs
    a = build_pki(o, "a", serial=1000)
    b = build_pki(o, "b", key_kind="rsa3072", sig_hash="sha384", serial=2000)
    c1 = build_pki(o, "c1", serial=3000, n_intermediates=1, intermediate_pathlens=[1])
    c2 = build_pki(o, "c2", serial=3100, n_intermediates=2, intermediate_pathlens=[2, 1], sig_hash="sha512")
    c3 = build_pki(o, "c3", serial=3200, n_intermediates=3, intermediate_pathlens=[5, 4, 3], ca_pathlen=2)
    pl = build_pki(o, "pl", serial=3300, n_intermediates=1, intermediate_pathlens=[0], ca_pathlen=0)
    ca_late = build_pki(o, "calate", serial=3400, ca_nb="20240101000000Z")
    root_exp = build_pki(o, "rootexp", serial=3500, root_na="20230601000000Z")
    ca_nca = build_pki(o, "canca", serial=3600, ca_kwargs={"bc": "CA:FALSE", "ku": "keyCertSign,cRLSign"}, ca_pathlen=None)
    ca_noku = build_pki(o, "canoku", serial=3700, ca_kwargs={"ku": "digitalSignature"})
    ca_nobc = build_pki(o, "canobc", serial=3750, ca_kwargs={"bc": None})
    UNK = ["1.2.3.4.5=critical,ASN1:NULL"]
    one = dict(n_intermediates=1, intermediate_pathlens=[1])
    int_exp = build_pki(o, "intexp", serial=3800, int_nb="20220601000000Z", int_na="20230601000000Z", **one)
    int_nca = build_pki(o, "intnca", serial=3810, int_kwargs={"bc": "CA:FALSE"}, n_intermediates=1, intermediate_pathlens=[None])
    int_noku = build_pki(o, "intnoku", serial=3820, int_kwargs={"ku": "digitalSignature"}, **one)
    int_unk = build_pki(o, "intunk", serial=3830, int_extra=UNK, **one)
    ca_unk = build_pki(o, "caunk", serial=3840, ca_extra=UNK)
    root_unk = build_pki(o, "rootunk", serial=3850, root_extra=UNK)
    root_nca = build_pki(o, "rootnca", serial=3860, root_kwargs={"bc": "CA:FALSE"})
    root_noku = build_pki(o, "rootnoku", serial=3870, root_kwargs={"ku": "digitalSignature"})
    # signer variants share root_a / ca_a (and the signer key of a)
    def variant(nm, serial, **kw):
        sk = a.signer_key
        cert = o.cert(cn=f"Test TSA Signer a {nm}", key=sk, not_before=kw.pop("nb", NB_SIGNER), not_after=kw.pop("na", NA_SIGNER),
                      serial=serial, ext=kw.pop("ext"), issuer=(a.ca, a.ca_key))
        return Pki(f"a_{nm}", a.root, a.root_key, [], a.ca, a.ca_key, cert, sk, "sha256")

    v_expired = variant("expired", 4001, nb="20220801000000Z", na="20230601000000Z", ext=signer_ext())
    v_eku_nc = variant("eku_noncritical", 4002, ext=signer_ext(eku="extendedKeyUsage=timeStamping"))
    v_eku_x = variant("eku_extra", 4003, ext=signer_ext(eku="extendedKeyUsage=critical,timeStamping,clientAuth"))
    v_eku_none = variant("eku_missing", 4004, ext=signer_ext(eku=None))
    v_is_ca = variant("signer_is_ca", 4005, ext=signer_ext(bc="basicConstraints=critical,CA:TRUE"))
    v_crit = variant("unknown_critical", 4006, ext=signer_ext(extra=["1.2.3.4.5=critical,ASN1:NULL"]))
    v_ku = variant("ku_no_signing", 4007, ext=signer_ext(ku="keyUsage=critical,keyEncipherment"))
    ec_key = o.key("a_signer_ec", "ec")
    ec_signer_cert = o.cert(cn="Test TSA Signer a ec", key=ec_key, not_before=NB_SIGNER, not_after=NA_SIGNER, serial=4008,
                            ext=signer_ext(), issuer=(a.ca, a.ca_key))
    v_ec = Pki("a_ec_signer", a.root, a.root_key, [], a.ca, a.ca_key, ec_signer_cert, ec_key, "sha256")
    # RSA signer under an EC issuing CA (the CA certificate itself is RSA-signed by root_a)
    ec_ca_key = o.key("ecca_ca", "ec")
    ec_ca = o.cert(cn="Test Issuing CA ec", key=ec_ca_key, not_before=NB_CA, not_after=NA_CA, serial=4100,
                   ext=ca_ext(0), issuer=(a.root, a.root_key))
    ec_signer = o.cert(cn="Test TSA Signer under ec CA", key=a.signer_key, not_before=NB_SIGNER, not_after=NA_SIGNER, serial=4101,
                       ext=signer_ext(), issuer=(ec_ca, ec_ca_key))
    v_ecca = Pki("ecca", a.root, a.root_key, [], ec_ca, ec_ca_key, ec_signer, a.signer_key, "sha256")

    pkis = {p.name: p for p in (a, b, c1, c2, c3, pl, ca_late, root_exp, ca_nca, ca_noku, ca_nobc, int_exp, int_nca, int_noku, int_unk,
                                ca_unk, root_unk, root_nca, root_noku, v_expired, v_eku_nc, v_eku_x,
                                v_eku_none, v_is_ca, v_crit, v_ku, v_ec, v_ecca)}
    trust = {}
    cert_files: dict[str, bytes] = {}
    pki_json: dict = {}

    def flip(cert: bytes) -> bytes:
        """The same certificate with one bit of its signature changed (still parses; its hash differs)."""
        return cert[:-1] + bytes([cert[-1] ^ 0x01])

    # --- extra certificates for path-validation negatives (each has exactly one defect)
    ca_f = flip(a.ca)  # issuing CA whose own signature (by the root) is wrong
    c1_ca_f = flip(c1.ca)  # issuing CA whose signature by the intermediate is wrong
    c1_int_f = flip(c1.chain[0])  # intermediate whose signature by the root is wrong
    root_alt = o.cert(cn="Test Root a ALT NAME", key=a.root_key, not_before=NB_ROOT, not_after=NA_ROOT, serial=5000,
                      ext=ca_ext(None, aki=False))  # the root key under another name
    root_wk = o.cert(cn="Test Root a", key=o.key("a_root_wrongkey"), not_before=NB_ROOT, not_after=NA_ROOT, serial=5001,
                     ext=ca_ext(None, aki=False))  # the root name with another key
    ca_alias = o.cert(cn="Test Issuing CA a ALIAS", key=a.ca_key, not_before=NB_CA, not_after=NA_CA, serial=5002,
                      ext=ca_ext(0), issuer=(a.root, a.root_key))
    signer_alias = o.cert(cn="Test TSA Signer a under alias", key=a.signer_key, not_before=NB_SIGNER, not_after=NA_SIGNER,
                          serial=5003, ext=signer_ext(), issuer=(ca_alias, a.ca_key))  # issuer NAME is the alias, key is the CA's
    int_alias = o.cert(cn="Test Intermediate c1 0 ALIAS", key=o.key("c1_int0"), not_before=NB_CA, not_after=NA_CA, serial=5004,
                       ext=ca_ext(1), issuer=(c1.root, c1.root_key))
    extras = {"a_ca_badsig": ca_f, "c1_ca_badsig": c1_ca_f, "c1_int_badsig": c1_int_f, "a_root_altname": root_alt,
              "a_root_wrongkey": root_wk, "a_ca_alias": ca_alias, "a_signer_alias": signer_alias, "c1_int_alias": int_alias}
    for p in pkis.values():
        trust[sha(p.root)] = p.root
        files = {"root": f"{p.name}_root.der", "ca": f"{p.name}_ca.der", "signer": f"{p.name}_signer.der"}
        for kind, blob in (("root", p.root), ("ca", p.ca), ("signer", p.signer)):
            cert_files[files[kind]] = blob
        for i, blob in enumerate(p.chain):
            cert_files[f"{p.name}_int{i}.der"] = blob
        pki_json[p.name] = {
            **{k + "_file": v for k, v in files.items()},
            **{k + "_sha256": sha(blob) for k, blob in (("root", p.root), ("ca", p.ca), ("signer", p.signer))},
            "intermediates": [f"{p.name}_int{i}.der" for i in range(len(p.chain))],
        }
    for nm, blob in extras.items():
        cert_files[f"{nm}.der"] = blob
    trust[sha(root_alt)] = root_alt
    trust[sha(root_wk)] = root_wk
    for fn, blob in cert_files.items():
        write(DATA / "synth" / "certs" / fn, blob)
        certs_expect.append({"file": f"synth/certs/{fn}", "sha256": sha(blob), **parse_x509_text(o, blob)})
    for hsh, blob in trust.items():
        write(DATA / "synth" / "trust" / f"{hsh}.der", blob)
    write_json(DATA / "synth" / "pki.json", {"version": 1, "pkis": pki_json})

    # ------------------------------------------------------------ token cases
    cases = []

    def entry(p: Pki, ca=None, root=None):
        return {"issuing_ca_sha256": [sha(ca if ca is not None else p.ca)], "root_sha256": sha(root if root is not None else p.root)}

    def case(name, pki, *, expect_reason=None, expect_code="tsa.invalid", entry_=None, digest=None, token_digest=None,
             gen_ms=GEN_MS, **kw):
        dg = digest if digest is not None else hashlib.sha256(name.encode()).digest()
        tok = build_token(o, pki, gen_ms=gen_ms, digest=token_digest if token_digest is not None else dg, **kw)
        fn = f"tokens/{name}.tsr"
        write(DATA / "synth" / fn, tok)
        ok = expect_reason is None
        e = {"ok": True, "gen_time_ms": gen_ms} if ok else {"ok": False, "code": expect_code, "reason": expect_reason}
        oracle = "not-applicable"
        if ok:
            roots_pem = o.work / "roots.pem"
            roots_pem.write_bytes(_pem(pki.root))
            chain_pem = o.work / "untrusted.pem"
            chain_pem.write_bytes(b"".join(_pem(c) for c in [pki.ca, *reversed(pki.chain)]))
            tokfile = o.work / "tok.tsr"
            tokfile.write_bytes(tok if not kw.get("bare") else d.seq(d.seq(d.integer(0)), tok))
            if kw.get("sid") == "ski":
                # openssl's PKCS7-based `ts -verify` only understands issuerAndSerialNumber; use the CMS verifier
                bare_tok = tok if kw.get("bare") else tok[d.children(tok, 0)[1][1]:]
                (o.work / "bare.der").write_bytes(bare_tok)
                o.run("cms", "-verify", "-inform", "DER", "-in", o.work / "bare.der", "-CAfile", roots_pem,
                      "-certfile", chain_pem, "-attime", str(gen_ms // 1000), "-purpose", "timestampsign",
                      "-out", o.work / "cms.out")
                oracle = "openssl-cms-verify-ok"
            else:
                o.run("ts", "-verify", "-in", tokfile, "-digest", dg.hex(), "-CAfile", roots_pem, "-untrusted", chain_pem,
                      "-attime", str(gen_ms // 1000))
                oracle = "openssl-ts-verify-ok"
        cases.append({"name": name, "file": fn, "digest": dg.hex(), "entry": entry_ or entry(pki), "expect": e, "oracle": oracle})

    case("ok_sha256", a)
    case("ok_sha384_pki_b", b, sig_hash="sha384", sigalg="rsa_enc", gen_ms=GEN_MS + 123_456)
    case("ok_sha512", a, sig_hash="sha512")
    case("ok_fraction", a, gen_ms=GEN_MS + 130)
    case("ok_sid_ski", a, sid="ski")
    case("ok_ess_v1", a, ess="v1")
    case("ok_ess_both", a, ess="both")
    case("ok_bare_content_info", a, bare=True)
    case("ok_one_intermediate", c1)
    case("ok_two_intermediates", c2)
    case("ok_embedded_root_ignored", a, certs=[a.signer, a.ca, a.root])
    case("bad_signature_bit", a, expect_reason="signature", flip_sig_bit=True)
    case("bad_message_digest_attr", a, expect_reason="message_digest", md_override=b"\x00" * 32)
    case("bad_ess_cert_id_v2", a, expect_reason="ess_cert_id", ess_override=b"\x11" * 32)
    case("bad_ess_cert_id_v1", a, expect_reason="ess_cert_id", ess="v1", ess_override=b"\x11" * 20)
    case("bad_signer_expired", v_expired, expect_reason="validity")
    case("bad_ca_not_yet_valid", ca_late, expect_reason="validity")
    case("bad_root_expired", root_exp, expect_reason="validity")
    case("bad_ca_not_pinned", a, expect_reason="ca_pin", entry_=entry(a, ca=b.ca))
    case("bad_root_pin_mismatch", a, expect_reason="chain", entry_=entry(a, root=b.root))
    case("bad_eku_noncritical", v_eku_nc, expect_reason="eku")
    case("bad_eku_extra_purpose", v_eku_x, expect_reason="eku")
    case("bad_eku_missing", v_eku_none, expect_reason="eku")
    case("bad_second_signer_info", a, expect_reason="signer_count", n_signers=2)
    case("bad_pss_signer", a, expect_reason="unsupported", sigalg="pss")
    case("bad_ecdsa_signer", v_ec, expect_reason="unsupported", sigalg="ecdsa")
    case("bad_ec_issuing_ca", v_ecca, expect_reason="unsupported")
    case("bad_unknown_critical_ext", v_crit, expect_reason="critical_extension")
    case("bad_signer_is_ca", v_is_ca, expect_reason="ca")
    case("bad_signer_ku_no_signing", v_ku, expect_reason="key_usage")
    case("bad_ca_not_ca", ca_nca, expect_reason="ca")
    case("bad_ca_no_keycertsign", ca_noku, expect_reason="ca")
    case("bad_ca_no_basic_constraints", ca_nobc, expect_reason="ca")
    case("bad_pathlen", pl, expect_reason="ca")
    case("bad_intermediate_expired", int_exp, expect_reason="validity")
    case("bad_intermediate_not_ca", int_nca, expect_reason="ca")
    case("bad_intermediate_no_keycertsign", int_noku, expect_reason="ca")
    case("bad_intermediate_unknown_critical", int_unk, expect_reason="critical_extension")
    case("bad_ca_unknown_critical", ca_unk, expect_reason="critical_extension")
    case("bad_root_unknown_critical", root_unk, expect_reason="critical_extension")
    case("bad_root_not_ca", root_nca, expect_reason="ca")
    case("bad_root_no_keycertsign", root_noku, expect_reason="ca")
    case("bad_three_intermediates", c3, expect_reason="chain")
    case("bad_no_certs", a, expect_reason="signer", certs=[])
    case("bad_sid_not_found", a, expect_reason="signer", sid_serial_delta=1)
    case("bad_content_type_attr", a, expect_reason="content_type", content_type_attr=OID_DATA)
    case("bad_econtent_type", a, expect_reason="content_type", econtent_type=OID_DATA)
    case("bad_wrong_imprint", a, expect_reason="imprint", expect_code="tsa.wrong_imprint", token_digest=b"\x42" * 32)
    case("bad_not_granted", a, expect_reason="not_granted", status=2)
    case("bad_missing_signed_attrs", a, expect_reason="malformed", signed_attrs=False)
    case("bad_unsupported_digest_alg", a, expect_reason="unsupported", sig_hash="sha1")
    case("bad_sigalg_hash_mismatch", a, expect_reason="unsupported", sigalg="rsa_mismatch")
    case("bad_ess_missing", a, expect_reason="ess_cert_id", ess="none")
    case("bad_signer_cert_signature", a, expect_reason="chain", signer_cert=flip(a.signer), certs=[flip(a.signer), a.ca])
    case("bad_ca_cert_signature", a, expect_reason="chain", certs=[a.signer, ca_f], entry_=entry(a, ca=ca_f))
    case("bad_ca_signature_under_intermediate", c1, expect_reason="chain", certs=[c1.signer, c1_ca_f, c1.chain[0]],
         entry_=entry(c1, ca=c1_ca_f))
    case("bad_intermediate_cert_signature", c1, expect_reason="chain", certs=[c1.signer, c1.ca, c1_int_f])
    case("bad_root_name_mismatch", a, expect_reason="chain", entry_=entry(a, root=root_alt))
    case("bad_root_wrong_key", a, expect_reason="chain", entry_=entry(a, root=root_wk))
    case("bad_signer_issuer_name_mismatch", a, expect_reason="ca_pin", signer_cert=signer_alias, certs=[signer_alias, a.ca])
    case("bad_intermediate_name_mismatch", c1, expect_reason="chain", certs=[c1.signer, c1.ca, int_alias])

    # ------------------------------------------------------------ one token made natively by `openssl ts -reply`
    native = DATA / "synth" / "tokens" / "ok_openssl_native.tsr"
    meta = DATA / "synth" / "tokens" / "ok_openssl_native.json"
    if args.refresh_native or not native.exists():
        nk = a.signer_key
        now_signer = o.cert(cn="Test TSA Signer a native", key=nk, not_before="20260101000000Z", not_after="20360101000000Z",
                            serial=4200, ext=signer_ext(), issuer=(a.ca, a.ca_key))
        (o.work / "signer_now.der").write_bytes(now_signer)
        o.run("x509", "-inform", "DER", "-in", o.work / "signer_now.der", "-out", o.work / "signer_now.pem")
        (o.work / "chain.pem").write_bytes(_pem(a.ca) + _pem(a.root))
        (o.work / "serial").write_text("0A\n")
        (o.work / "ts.cnf").write_text(
            "[tsa]\ndefault_tsa=tsa_config\n[tsa_config]\ndir=.\nserial=./serial\ncrypto_device=builtin\n"
            f"signer_cert=./signer_now.pem\ncerts=./chain.pem\nsigner_key={nk.as_posix()}\nsigner_digest=sha256\n"
            "default_policy=1.2.3.4.1\ndigests=sha256\naccuracy=secs:1\nordering=no\ntsa_name=no\ness_cert_id_chain=no\n"
            "ess_cert_id_alg=sha256\n", encoding="ascii")
        dg = hashlib.sha256(b"ok_openssl_native").digest()
        o.run("ts", "-query", "-digest", dg.hex(), "-sha256", "-cert", "-out", o.work / "n.tsq")
        o.run("ts", "-reply", "-config", o.work / "ts.cnf", "-section", "tsa_config", "-queryfile", o.work / "n.tsq", "-out", o.work / "n.tsr")
        tok = (o.work / "n.tsr").read_bytes()
        text = o.run("ts", "-reply", "-in", o.work / "n.tsr", "-text").decode()
        line = [x for x in text.splitlines() if x.startswith("Time stamp:")][0]
        t = datetime.datetime.strptime(line.split(":", 1)[1].strip().replace("  ", " "), "%b %d %H:%M:%S %Y GMT").replace(tzinfo=datetime.UTC)
        write(native, tok)
        write_json(meta, {"digest": dg.hex(), "gen_time_ms": int(t.timestamp()) * 1000, "signer_file": "a_native_signer.der"})
        write(DATA / "synth" / "certs" / "a_native_signer.der", now_signer)
    ns = (DATA / "synth" / "certs" / "a_native_signer.der").read_bytes()
    certs_expect.append({"file": "synth/certs/a_native_signer.der", "sha256": sha(ns), **parse_x509_text(o, ns)})
    write_json(DATA / "x509_expected.json", {"version": 1, "certs": certs_expect})
    nm = json.loads(meta.read_text())
    ntok = native.read_bytes()
    (o.work / "native.tsr").write_bytes(ntok)
    (o.work / "roots.pem").write_bytes(_pem(a.root))
    (o.work / "untrusted.pem").write_bytes(_pem(a.ca))
    o.run("ts", "-verify", "-in", o.work / "native.tsr", "-digest", nm["digest"], "-CAfile", o.work / "roots.pem",
          "-untrusted", o.work / "untrusted.pem", "-attime", str(nm["gen_time_ms"] // 1000))
    cases.append({"name": "ok_openssl_native", "file": "tokens/ok_openssl_native.tsr", "digest": nm["digest"], "entry": entry(a),
                  "expect": {"ok": True, "gen_time_ms": nm["gen_time_ms"]}, "oracle": "openssl-ts-verify-ok"})
    write_json(DATA / "synth" / "expected.json", {"version": 1, "genesis_ms": GEN_MS, "cases": cases})

    # ------------------------------------------------------------ RSA PKCS#1 v1.5 vectors
    rsa_keys, rsa_cases = [], []
    msgs = [b"", b"abc", bytes(range(256)) * 4]
    for ki, bits in enumerate((2048, 3072)):
        key = o.key(f"rsa_vec_{bits}", f"rsa{bits}")
        mod = o.run("rsa", "-in", key, "-noout", "-modulus").decode().strip().split("=")[1].lower()
        n = int(mod, 16)
        rsa_keys.append({"bits": bits, "n": mod, "e": 65537})
        k = (n.bit_length() + 7) // 8

        def raw_sign(em: bytes) -> bytes:
            (o.work / "em.bin").write_bytes(em)
            return o.run("pkeyutl", "-decrypt", "-inkey", key, "-pkeyopt", "rsa_padding_mode:none", "-in", o.work / "em.bin")

        def di(hash_name, digest, null=True):
            return d.seq(d.alg(H[hash_name][0], d.null() if null else b""), d.octet(digest))

        for hn in ("sha256", "sha384", "sha512"):
            for m in msgs:
                rsa_cases.append({"kind": "ok", "key": ki, "hash": hn, "message": m.hex(), "signature": o.sign(key, m, hn).hex(), "expect": True})
        m = b"vector message"
        t256 = di("sha256", hashlib.sha256(m).digest())

        def case_(kind, em, hash_name="sha256"):
            assert len(em) == k, (kind, len(em), k)
            rsa_cases.append({"kind": kind, "key": ki, "hash": hash_name, "message": m.hex(), "signature": raw_sign(em).hex(), "expect": False})

        ps = lambda n_: b"\xff" * n_  # noqa: E731
        case_("short_padding", b"\x00\x01" + ps(7) + b"\x00" + t256 + b"\x5a" * (k - 10 - len(t256)))
        case_("garbage_after_digestinfo", b"\x00\x01" + ps(k - 3 - len(t256) - 4) + b"\x00" + t256 + b"\x01\x02\x03\x04")
        case_("wrong_oid", b"\x00\x01" + ps(k - 3 - len(di("sha384", hashlib.sha256(m).digest()))) + b"\x00" + di("sha384", hashlib.sha256(m).digest()))
        case_("block_type_2", b"\x00\x02" + b"\x7e" * (k - 3 - len(t256)) + b"\x00" + t256)
        pad = bytearray(ps(k - 3 - len(t256)))
        pad[10] = 0xFE
        case_("non_ff_padding", b"\x00\x01" + bytes(pad) + b"\x00" + t256)
        tnn = di("sha256", hashlib.sha256(m).digest(), null=False)
        case_("no_null_params", b"\x00\x01" + ps(k - 3 - len(tnn)) + b"\x00" + tnn)
        case_("leading_nonzero", b"\x01\x01" + ps(k - 3 - len(t256)) + b"\x00" + t256)
        t1 = di("sha1", hashlib.sha1(m).digest())
        case_("sha1_digestinfo", b"\x00\x01" + ps(k - 3 - len(t1)) + b"\x00" + t1)
        t512 = di("sha512", hashlib.sha512(m).digest())
        case_("hash_confusion_sha512_for_sha256", b"\x00\x01" + ps(k - 3 - len(t512)) + b"\x00" + t512)
    write_json(DATA / "rsa_vectors.json", {"version": 1, "keys": rsa_keys, "cases": rsa_cases})

    # ------------------------------------------------------------ A8: sample release with rfc3161 tokens
    from precog_verifier import release as rel
    from precog_verifier import testing

    data = testing.build_sample_release()
    auths = {"tsa-a": (a, "sha256", "rsa_sha"), "tsa-b": (b, "sha384", "rsa_enc")}
    data.manifest["authorities"] = [
        {"id": "tsa-a", "kind": "rfc3161", "name": "Test authority A (synthetic PKI)", **entry(a)},
        {"id": "tsa-b", "kind": "rfc3161", "name": "Test authority B (synthetic PKI)", **entry(b)},
    ]
    for anc in data.anchors:
        for tok in anc["tokens"]:
            pki, sh, sa = auths[tok["tsa_id"]]
            tok["token"] = base64.b64encode(
                build_token(o, pki, gen_ms=tok["gen_time_ms"], digest=bytes.fromhex(anc["anchor_hash"]), sig_hash=sh, sigalg=sa)
            ).decode("ascii")
    out = VERIFIER / "tests" / "data" / "sample_release_rfc3161"
    if out.exists():
        shutil.rmtree(out)
    rel.write_release(data, out)

    print(f"wrote {len(cases)} token cases, {len(rsa_cases)} rsa cases, {len(certs_expect)} certificates, sample release -> {out}")
    return 0


def _pem(der: bytes) -> bytes:
    b64 = base64.b64encode(der).decode()
    lines = "\n".join(b64[i : i + 64] for i in range(0, len(b64), 64))
    return f"-----BEGIN CERTIFICATE-----\n{lines}\n-----END CERTIFICATE-----\n".encode()


if __name__ == "__main__":
    sys.exit(main())
