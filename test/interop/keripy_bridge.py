"""keripy interoperability bridge for the node-keri test suite.

This script is the Python half of the cross-implementation tests. It is driven
by the TypeScript bridge in `bridge.ts`: a sub-command is passed as argv[1], a
JSON request body is read from stdin, and a JSON response is written to stdout.

It uses the reference KERI implementation (keripy, the `keri` PyPI package) to:

  * `gen-kel`    - build a KEL (icp, rot, ixn, rot) with keripy and emit it as
                   a CESR stream (the wire form node-keri's `verifyKel` reads).
  * `gen-nt-kel` - build a single-event KEL for a *non-transferable* AID with
                   keripy and emit it as a CESR stream. node-keri verifies
                   these (it does not generate them).
  * `verify-kel` - replay a node-keri-produced CESR stream through keripy's
                   `Kevery` and report whether keripy's verifier accepts it.
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

Wire form
---------
A KEL is exchanged as a CESR stream: each event's serialized JSON followed by
its attachment group — a `-A` controller-signature counter and the controller's
indexed signature(s) ("Siger", code `A`). keripy's `eventing.messagize` builds
exactly that frame, and its `parsing.Parser` consumes it, so the bridge speaks
the stream form directly with no per-event JSON wrapper.
"""

import base64
import json
import sys

from keri.core import serdering
from keri.core import eventing, parsing
from keri.core.coring import Cigar, Diger, MtrDex, Verfer, versify
from keri.core.eventing import Ilks, Kevery
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


def _seed_bytes(seed):
    """The 32-byte raw seed for an integer seed (0..223).

    `bytes(range(seed, seed + 32))` is exactly what the TypeScript tests feed
    to `keyPairFromSeed`, so both sides derive the same key material.
    """
    if not isinstance(seed, int) or not (0 <= seed <= 223):
        raise ValueError(f"seed must be an int in [0, 223], got {seed!r}")
    return bytes(range(seed, seed + 32))


def _signer(seed):
    """Deterministic *transferable* Ed25519 signer (verfer code `D`)."""
    return Signer(raw=_seed_bytes(seed), code=MtrDex.Ed25519_Seed,
                  transferable=True)


def _signer_nt(seed):
    """Deterministic *non-transferable* Ed25519 signer (verfer code `B`).

    `transferable=False` is the only difference from `_signer`: the private
    key — and so the raw signature bytes — is identical, only the verfer's
    CESR code changes (`B` instead of `D`).
    """
    return Signer(raw=_seed_bytes(seed), code=MtrDex.Ed25519_Seed,
                  transferable=False)


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
    Response: {"aid", "did", "kel": "<CESR stream>"}

    The KEL is emitted as a CESR stream — each event's JSON followed by a `-A`
    counter and the controller's indexed signature ("Siger", code `A`) — which
    is exactly the wire form node-keri's `verifyKel` consumes.
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

    def frame(serder, signer):
        # Sign the exact serialized event bytes at key index 0, then frame the
        # event with its `-A` counter + indexed Siger via keripy's `messagize`.
        siger = signer.sign(ser=serder.raw, index=0)
        return eventing.messagize(serder, sigers=[siger])

    stream = b"".join([
        frame(icp_s, s0),
        frame(rot_s, s1),
        frame(ixn_s, s1),
        frame(rot2_s, s2),
    ])
    return {
        "aid": pre,
        "did": f"did:keri:{pre}",
        "kel": bytes(stream).decode("utf-8"),
    }


def _cmd_gen_nt_kel(req):
    """Build a single-event KEL for a *non-transferable* identifier with keripy.

    Request : {"seed": <int, optional, default 0>}
    Response: {"aid", "did", "kel": "<CESR stream>"}

    A non-transferable AID is a basic prefix: the `i` field is the controller's
    `B`-coded Ed25519 key itself — not a self-addressing digest — so `d != i`.
    The inception commits to no next key (`nt="0"`, `n=[]`) and the identifier
    can never rotate, so the whole KEL is exactly this one inception event.

    As in `gen-kel`, the event SAID `d` is pinned to SHA2-256 (CESR code `I`)
    so node-keri can recompute it; only `d` is self-addressing here — `i` is
    the fixed basic prefix and is kept verbatim through `makify`.
    """
    seed = req.get("seed", 0)
    s0 = _signer_nt(seed)
    pre = s0.verfer.qb64  # the basic non-transferable prefix == the `B` key

    icp = dict(v=_vs(), t=Ilks.icp, d="", i=pre, s="0", kt="1",
               k=[s0.verfer.qb64], nt="0", n=[],
               bt="0", b=[], c=[], a=[])
    icp_s = _said_keri(icp)  # saids={"d": SHA2}; `i` left as the given prefix

    # Controller signature: an indexed Siger at key index 0, exactly as for a
    # transferable event — `transferable=False` changed the verfer code, not
    # how the controller signs.
    siger = s0.sign(ser=icp_s.raw, index=0)
    stream = eventing.messagize(icp_s, sigers=[siger])
    return {
        "aid": pre,
        "did": f"did:keri:{pre}",
        "kel": bytes(stream).decode("utf-8"),
    }


def _cmd_verify_kel(req):
    """Replay a node-keri CESR-stream KEL through keripy's `Kevery` verifier.

    Request : {"aid": "<expected prefix>", "kel": "<CESR stream>"}
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
        # node-keri's stream is exactly the frame form keripy's Parser expects.
        parsing.Parser(kvy=kvy).parse(ims=bytearray(kel.encode("utf-8")))

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
    "gen-nt-kel": _cmd_gen_nt_kel,
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
