"""identity-runtime: governed, reversible avatar personalities with leased capabilities.

Research prototype. Classical, deterministic, standard-library-only Python.
"""

from .fabric import evaluate as fabric_evaluate
from .ledger import HashChainLedger, LedgerIntegrityError
from .policy import CAPABILITY_REGISTRY, NEVER_GRANTABLE, PolicyError, compile_policy
from .runtime import ActionError, ApprovalError, IdentityRuntime, LeaseError, UnknownAvatar
from .schema import SCHEMA_ID, validate_manifest
from .simulation import ShadowSimulation

__version__ = "0.1.0"

__all__ = [
    "ActionError",
    "ApprovalError",
    "CAPABILITY_REGISTRY",
    "HashChainLedger",
    "IdentityRuntime",
    "LeaseError",
    "LedgerIntegrityError",
    "NEVER_GRANTABLE",
    "PolicyError",
    "SCHEMA_ID",
    "ShadowSimulation",
    "UnknownAvatar",
    "compile_policy",
    "fabric_evaluate",
    "validate_manifest",
    "__version__",
]
