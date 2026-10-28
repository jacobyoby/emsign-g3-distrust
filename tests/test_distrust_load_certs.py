import shutil
import subprocess

import pytest

from emsign_g3.distrust import load_certs
from emsign_g3.paths import default_certs_dir

openssl = shutil.which("openssl")


@pytest.mark.skipif(openssl is None, reason="openssl not on PATH")
def test_load_certs_finds_eight_verified_pems():
    certs = load_certs(default_certs_dir())
    assert len(certs) == 8
    names = {c[0] for c in certs}
    assert "EMDVTLSCAG3B" in names


def test_openssl_available_for_distrust_docs():
    if openssl is None:
        pytest.skip("openssl not on PATH")
    r = subprocess.run([openssl, "version"], capture_output=True, text=True)
    assert r.returncode == 0
