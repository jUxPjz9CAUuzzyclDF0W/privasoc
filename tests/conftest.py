import pytest
from cryptography.fernet import Fernet

from privasoc.pseudo import Pseudonymizer, Vault


@pytest.fixture
def vault(tmp_path):
    v = Vault(tmp_path / "vault.db", b"test-hmac-key-0123456789", Fernet.generate_key())
    yield v
    v.close()


@pytest.fixture
def pz(vault):
    return Pseudonymizer(vault)
