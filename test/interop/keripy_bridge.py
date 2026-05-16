"""keripy interoperability bridge for the node-keri test suite.

This script is the Python half of the cross-implementation tests. It is driven
by the TypeScript bridge in `bridge.ts`: a sub-command is passed as argv[1], a
JSON request body is read from stdin, and a JSON response is written to stdout.

It uses the reference KERI implementation (keripy, the `keri` PyPI package) to:

  * `gen-kel`    - build a KEL (icp, rot, ixn, rot) with keripy and emit it in
                   node-keri's `SignedKeriEvent` JSON shape.
  * `verify-kel` - replay a node-keri-produced KEL through keripy's `Kevery`
                   and report whether keripy's verifier accepts it.
  * `sign`       - sign a payload with keripy's Ed25519 signer.
  * `verify-sig` - verify a detached Ed25519 signature with keripy.

Profile alignment notes
-----------------------
node-keri implements the "KERI Direct JSON Profile v1": JSON events, Ed25519
keys, single controller, and — critically — SHA2-256 (CESR code `I`) for both
the event SAID (`d`) and the self-addressing identifier prefix (`i`), so that
`d == i` for an inception event.

keripy defaults the event SAID to Blake3-256. To produce events keripy and
node-keri agree on byte-for-byte, this bridge pins keripy's SAID computation to
SHA2-256 via the `saids=` argument of `SerderKERI`, and builds next-key digests
with `Diger(..., code=SHA2_256)`. With that pinning the two implementations
produce identical event bytes for identical key material.

node-keri carries a single non-indexed Ed25519 signature (`Cigar`, CESR code
`0B`) per event. keripy's `Kevery` expects controller signatures to be CESR
*indexed* signatures (`Siger`, code `A...`). The raw 64 signature bytes are the
same in both forms; this bridge converts between them when crossing the
boundary.
"""

import base64
import json
import sys

from keri.core import serdering
from keri.core import eventing, parsing
from keri.core.coring import Cigar, Diger, MtrDex, Verfer, versify
from keri.core.eventing import Ilks, Kevery
from keri.core.indexing import IdxSigDex, Siger
from keri.core.signing import Signer
from keri.db import basing
from keri.kering import Kinds, Version

# SHA2-256: CESR code `I`. node-keri's only digest algorithm.
SHA2 = MtrDex.SHA2_256


def _fail(message):
    """Emit a structured error response and exit non-zero."""
    json.dump({"ok": False, "error": message}, sys.stdout)
    sys.stdout.write("\n")
    sys.exit(1)


def _signer(seed):
    """Deterministic Ed25519 signer from an integer seed (0..223).

    The 32-byte raw seed is `bytes(range(seed, seed + 32))`, which is exactly
    what the TypeScript tests feed to `keyPairFromSeed`, so both sides derive
    the same key material.
    """
    if not isinstance(seed, int) or not (0 <= seed <= 223):
        raise ValueError(f"seed must be an int in [0, 223], got {seed!r}")
    raw = bytes(range(seed, seed + 32))
    return Signer(raw=raw, code=MtrDex.Ed25519_Seed, transferable=True)


def _ndig(signer):
    """Next-key commitment: SHA2-256 digest of the next key's qb64 bytes."""
    return Diger(ser=signer.verfer.qb64b, code=SHA2).qb64


def _vs():
    """A KERI 1.0 JSON version string with a placeholder size."""
    return versify(version=Version, kind=Kinds.json, size=0)


def _said_keri(ked, also_pre=False):
    """Run keripy's `makify` SAID computation pinned to SHA2-256.

    `also_pre=True` additionally pins the `i` prefix (used for inception, where
    the AID is itself the self-addressing SAID and must equal `d`).
    """
    saids = {"d": SHA2}
    if also_pre:
        saids["i"] = SHA2
    return serdering.SerderKERI(sad=ked, makify=True, saids=saids)


def _cmd_gen_kel(req):
    """Build a 4-event KEL (icp, rot, ixn, rot) entirely with keripy.

    Request : {"seeds": [s0, s1, s2, s3], "anchor": <json value, optional>}
    Response: {"aid", "did", "kel": [{"event", "signatures"}, ...]}

    The KEL is emitted in node-keri's `SignedKeriEvent` JSON shape, with each
    event's controller signature as a non-indexed `0B` Ed25519 signature.
    """
    seeds = req.get("seeds", [0, 32, 64, 96])
    if len(seeds) != 4:
        raise ValueError("gen-kel requires exactly 4 seeds")
    s0, s1, s2, s3 = (_signer(s) for s in seeds)
    anchor = req.get("anchor")
    anchors = [anchor] if anchor is not None else []

    # Inception: keys=[s0], pre-rotation commitment to s1. d == i (SHA2-256).
    icp = dict(v=_vs(), t=Ilks.icp, d="", i="", s="0", kt="1",
               k=[s0.verfer.qb64], nt="1", n=[_ndig(s1)],
               bt="0", b=[], c=[], a=[])
    icp_s = _said_keri(icp, also_pre=True)
    pre = icp_s.pre

    # Rotation: reveal s1, commit to s2. Signed by the revealed key s1.
    rot = dict(v=_vs(), t=Ilks.rot, d="", i=pre, s="1", p=icp_s.said, kt="1",
               k=[s1.verfer.qb64], nt="1", n=[_ndig(s2)],
               bt="0", br=[], ba=[], a=[])
    rot_s = _said_keri(rot)

    # Interaction: anchors data under the current key s1.
    ixn = dict(v=_vs(), t=Ilks.ixn, d="", i=pre, s="2", p=rot_s.said, a=anchors)
    ixn_s = _said_keri(ixn)

    # Second rotation: reveal s2, commit to s3. Signed by s2.
    rot2 = dict(v=_vs(), t=Ilks.rot, d="", i=pre, s="3", p=ixn_s.said, kt="1",
                k=[s2.verfer.qb64], nt="1", n=[_ndig(s3)],
                bt="0", br=[], ba=[], a=[])
    rot2_s = _said_keri(rot2)

    def entry(serder, signer):
        # Sign the exact serialized event bytes; emit the non-indexed 0B form.
        cigar = signer.sign(ser=serder.raw)
        return {
            "event": json.loads(serder.raw.decode("utf-8")),
            "signatures": [cigar.qb64],
        }

    kel = [
        entry(icp_s, s0),
        entry(rot_s, s1),
        entry(ixn_s, s1),
        entry(rot2_s, s2),
    ]
    return {"aid": pre, "did": f"did:keri:{pre}", "kel": kel}


def _to_siger(qb64_0b, index):
    """Convert a non-indexed `0B` Ed25519 signature to an indexed `Siger`."""
    raw = Cigar(qb64=qb64_0b).raw
    return Siger(raw=raw, code=IdxSigDex.Ed25519_Sig, index=index, ondex=index)


def _cmd_verify_kel(req):
    """Replay a node-keri KEL through keripy's `Kevery` verifier.

    Request : {"aid": "<expected prefix>", "kel": [{"event", "signatures"}, ...]}
    Response: {"ok", "aid", "sn", "said", "currentKeys"} on acceptance, or
              {"ok": false, "error"} when keripy rejects the log.

    A pass means keripy independently re-derived the AID prefix, recomputed
    every event SAID, validated the digest chain, checked each signature, and
    confirmed every rotation revealed the prior next-key commitment.
    """
    aid = req["aid"]
    kel = req["kel"]

    db = basing.Baser(name="interop", temp=True, reopen=True)
    try:
        kvy = Kevery(db=db, lax=False, local=True)
        for entry in kel:
            serder = serdering.SerderKERI(sad=entry["event"])
            sigers = [_to_siger(sig, i)
                      for i, sig in enumerate(entry["signatures"])]
            msg = eventing.messagize(serder, sigers=sigers)
            parsing.Parser(kvy=kvy).parse(ims=bytearray(msg))

        kever = kvy.kevers.get(aid)
        if kever is None:
            return {"ok": False,
                    "error": f"keripy did not accept a KEL for {aid}; "
                             f"accepted prefixes: {list(kvy.kevers)}"}
        return {
            "ok": True,
            "aid": kever.prefixer.qb64,
            "sn": kever.sn,
            "said": kever.serder.said,
            "currentKeys": [v.qb64 for v in kever.verfers],
        }
    finally:
        db.close(clear=True)


def _cmd_sign(req):
    """Sign a payload with keripy's deterministic Ed25519 signer.

    Request : {"seed": <int>, "payloadB64": "<base64>"}
    Response: {"ok", "publicKey": "D...", "signature": "0B..."}
    """
    signer = _signer(req["seed"])
    payload = base64.b64decode(req["payloadB64"])
    cigar = signer.sign(ser=payload)
    return {"ok": True, "publicKey": signer.verfer.qb64, "signature": cigar.qb64}


def _cmd_verify_sig(req):
    """Verify a detached Ed25519 signature with keripy.

    Request : {"publicKey": "D...", "payloadB64": "<base64>", "signature": "0B..."}
    Response: {"ok": <bool>}
    """
    verfer = Verfer(qb64=req["publicKey"])
    payload = base64.b64decode(req["payloadB64"])
    raw = Cigar(qb64=req["signature"]).raw
    return {"ok": bool(verfer.verify(raw, payload))}


_COMMANDS = {
    "gen-kel": _cmd_gen_kel,
    "verify-kel": _cmd_verify_kel,
    "sign": _cmd_sign,
    "verify-sig": _cmd_verify_sig,
}


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in _COMMANDS:
        _fail(f"usage: keripy_bridge.py <{'|'.join(_COMMANDS)}>")
    raw = sys.stdin.read()
    try:
        req = json.loads(raw) if raw.strip() else {}
    except json.JSONDecodeError as exc:
        _fail(f"invalid JSON request: {exc}")
        return
    try:
        result = _COMMANDS[sys.argv[1]](req)
    except Exception as exc:  # surface any keripy error as a structured failure
        _fail(f"{type(exc).__name__}: {exc}")
        return
    json.dump(result, sys.stdout)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
