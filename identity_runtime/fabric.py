"""OES-61440: a fixed, deterministic hierarchy of threshold latches.

"OES-61440" is a name for the shape of this model, nothing more:

    61,440 threshold channels
    = 1,920 membranes x 32 channels      (a membrane trips on >= 17 of 32)
    ->  480 supervisors x 4 membranes    (a supervisor trips on >= 3 of 4)
    ->  120 sectors x 4 supervisors      (a sector trips on >= 2 of 4)
    ->  1 root                           (checkpoint on >= 1 sector;
                                          halt when every sector trips and
                                          >= 95% of all channels trip)

Each channel compares a fixed weighted sum of four action signals with a
fixed threshold. Weights and thresholds are derived from SHA-256 of the
channel index, so every run on every machine gives the same answer. Nothing is
learned or trained. The whole hierarchy amounts to a graded threshold on a
weighted risk score with a little spread; it is a transparent tripwire, not a
safety guarantee, and its numbers are illustrative settings, not calibrated
against any real incident data.
"""

from __future__ import annotations

import hashlib
import struct
from functools import lru_cache

CHANNELS_PER_MEMBRANE = 32
MEMBRANES = 1920
MEMBRANES_PER_SUPERVISOR = 4
SUPERVISORS = MEMBRANES // MEMBRANES_PER_SUPERVISOR  # 480
SUPERVISORS_PER_SECTOR = 4
SECTORS = SUPERVISORS // SUPERVISORS_PER_SECTOR  # 120
TOTAL_CHANNELS = MEMBRANES * CHANNELS_PER_MEMBRANE  # 61,440

MEMBRANE_QUORUM = 17
SUPERVISOR_QUORUM = 3
SECTOR_QUORUM = 2
HALT_CHANNEL_FRACTION = 0.95
THRESHOLD_LOW = 0.30
THRESHOLD_HIGH = 0.50
SIGNALS = ("risk", "capability_risk", "context_mismatch", "lease_utilisation")
FABRIC_VERSION = "oes-61440/1"

assert TOTAL_CHANNELS == 61440 and SECTORS == 120


@lru_cache(maxsize=1)
def _channels() -> tuple[tuple[float, float, float, float, float], ...]:
    out = []
    for i in range(TOTAL_CHANNELS):
        digest = hashlib.sha256(f"{FABRIC_VERSION}:{i}".encode()).digest()
        a, b, c, d, e = (x / 0xFFFFFFFF for x in struct.unpack(">5I", digest[:20]))
        raw = (1.0 + a, 1.0 + b, 0.5 + c, 0.5 + d)
        total = sum(raw)
        w = tuple(x / total for x in raw)
        threshold = THRESHOLD_LOW + (THRESHOLD_HIGH - THRESHOLD_LOW) * e
        out.append((*w, threshold))
    return tuple(out)


def _clamp(x: float) -> float:
    if x != x:  # NaN fails closed: treat as maximum risk
        return 1.0
    return min(1.0, max(0.0, float(x)))


def evaluate(risk: float, capability_risk: float, context_mismatch: float, lease_utilisation: float) -> dict:
    """Run every channel and return the latch counts and the root decision."""
    s = (_clamp(risk), _clamp(capability_risk), _clamp(context_mismatch), _clamp(lease_utilisation))
    channels = _channels()
    tripped_channels = 0
    membrane_trips: list[bool] = []
    for m in range(MEMBRANES):
        count = 0
        base = m * CHANNELS_PER_MEMBRANE
        for w0, w1, w2, w3, t in channels[base : base + CHANNELS_PER_MEMBRANE]:
            if w0 * s[0] + w1 * s[1] + w2 * s[2] + w3 * s[3] > t:
                count += 1
        tripped_channels += count
        membrane_trips.append(count >= MEMBRANE_QUORUM)
    supervisor_trips = [
        sum(membrane_trips[i : i + MEMBRANES_PER_SUPERVISOR]) >= SUPERVISOR_QUORUM
        for i in range(0, MEMBRANES, MEMBRANES_PER_SUPERVISOR)
    ]
    sector_trips = [
        sum(supervisor_trips[i : i + SUPERVISORS_PER_SECTOR]) >= SECTOR_QUORUM
        for i in range(0, SUPERVISORS, SUPERVISORS_PER_SECTOR)
    ]
    sectors = sum(sector_trips)
    return {
        "fabric": FABRIC_VERSION,
        "signals": dict(zip(SIGNALS, s)),
        "tripped_channels": tripped_channels,
        "tripped_membranes": sum(membrane_trips),
        "tripped_supervisors": sum(supervisor_trips),
        "tripped_sectors": sectors,
        "checkpoint": sectors >= 1,
        "halt": sectors == SECTORS and tripped_channels >= HALT_CHANNEL_FRACTION * TOTAL_CHANNELS,
    }
