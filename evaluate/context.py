from pathlib import Path
from dataclasses import dataclass
import base64

_ALL_CTXS = []


@dataclass(frozen=True)
class EvalContext:
    STARTED_CONTAINER_IDS: set[str]
    TEMP_DIR: Path
    TESTCASES_DIR: Path
    CERTS_DIR: Path
    SITES_DIR: Path
    CERTS: dict[str, bytes]

    def __post_init__(self):
        _ALL_CTXS.append(self)

    @classmethod
    def make(cls, testcases_dir: Path, temp_dir: Path):
        assert isinstance(testcases_dir, Path)
        assert isinstance(temp_dir, Path)
        TESTCASES_DIR = testcases_dir
        TEMP_DIR = temp_dir
        CERTS_DIR = testcases_dir / "certs"
        SITES_DIR = testcases_dir / "sites"
        CERTS = {}
        for cert in CERTS_DIR.glob("*.crt"):
            with cert.open("r") as f:
                cert_pem_lines = f.readlines()
                assert cert_pem_lines[0] == "-----BEGIN CERTIFICATE-----\n"
                assert cert_pem_lines[-1] == "-----END CERTIFICATE-----\n"
                cert_pem = "".join(cert_pem_lines[1:-1])
                CERTS[cert.stem] = base64.b64decode(cert_pem)
        return cls(
            STARTED_CONTAINER_IDS=set(),
            TEMP_DIR=TEMP_DIR,
            TESTCASES_DIR=TESTCASES_DIR,
            CERTS_DIR=CERTS_DIR,
            SITES_DIR=SITES_DIR,
            CERTS=CERTS,
        )
