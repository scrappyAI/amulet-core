#!/usr/bin/env python3
from struct import pack
import binascii, pathlib

def frame(op, cidbyte, lc, suite, siglen, extra=b'\x00'):
    return (bytes([op]) +
            bytes([cidbyte])*32 +
            pack('<Q', lc) +
            pack('<H', suite) +
            pack('<H', siglen) +
            b'\xAA'*siglen + extra)

seeds = {
    "S1": frame(0x01, 0x11, 1, 0, 32),
    "S2": frame(0x01, 0x22, 2, 3, 80),
    "S3": frame(0x01, 0x33, 3, 3, 32),
    "S4": frame(0x01, 0x44, 2**64-2, 0, 32),
    "S5": frame(0x01, 0x55, 2**64-1, 0, 32),
    "S6": frame(0x02, 0x66, 10, 0, 32),                    # capability-expiry
    "S7": frame(0x01, 0x77, 7, 0, 32, extra=bytes.fromhex("FFEEDDCCBBAA99887766")),
    "S8": frame(0x01, 0x11, 8, 0, 32),                    # CID collision
    "S9": frame(0x03, 0x88, 9, 0, 32),                    # rights mask
    "S10":frame(0x01, 0x99,10, 2, 32),                    # PQC + 32-B sig
    "S12":frame(0x01, 0xBC,10, 0, 32),
}

outdir = pathlib.Path("fuzz/seeds")
outdir.mkdir(parents=True, exist_ok=True)
for name, blob in seeds.items():
    (outdir / f"{name}.bin").write_bytes(blob)
    print(f"Wrote {name}.bin ({len(blob)} bytes)")
