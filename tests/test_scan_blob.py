from pathlib import Path

from emsign_g3.indicators import compromised_intermediates
from emsign_g3.paths import default_certs_dir
from emsign_g3.scan import scan_blob

KNOWN_DV_G3B = "42c4accd12c4f59597925e1a08a7a90102608543809308d50ec427e118ba1493"


def test_scan_blob_finds_dv_g3b_pem():
    pem_path = Path(default_certs_dir()) / "EMDVTLSCAG3B.pem"
    blob = pem_path.read_bytes()
    hits = list(scan_blob(blob))
    assert (KNOWN_DV_G3B, compromised_intermediates()[KNOWN_DV_G3B]) in hits
