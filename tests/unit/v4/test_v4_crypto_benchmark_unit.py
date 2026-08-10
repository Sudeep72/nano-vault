"""Unit tests — Cryptography Performance Lab (real timing measurements, no DB)."""
from app.services.v4.crypto_benchmark_service import crypto_benchmark_service


def test_aes_benchmark_real_measurements():
    result = crypto_benchmark_service.benchmark_aes_gcm(n=20)
    assert result["algorithm"] == "AES-256-GCM"
    assert result["encrypt"]["ops"] == 20
    assert result["encrypt"]["total_ms"] > 0
    assert result["decrypt"]["throughput_ops_per_sec"] > 0


def test_chacha20_benchmark():
    result = crypto_benchmark_service.benchmark_chacha20(n=20)
    assert result["algorithm"] == "ChaCha20-Poly1305"
    assert result["encrypt"]["ops"] == 20


def test_ed25519_benchmark():
    result = crypto_benchmark_service.benchmark_ed25519(n=20)
    assert result["algorithm"] == "Ed25519"
    assert result["sign"]["ops"] == 20
    assert result["verify"]["ops"] == 20


def test_ecdsa_benchmark():
    result = crypto_benchmark_service.benchmark_ecdsa(n=10)
    assert result["algorithm"] == "ECDSA-P256"
    assert result["sign"]["ops"] == 10


def test_rsa_benchmark_small_n():
    result = crypto_benchmark_service.benchmark_rsa4096(n=1)
    assert result["algorithm"] == "RSA-4096"
    assert result["key_generation_ms"] > 0
    assert "note" in result


def test_full_crypto_suite_has_all_five_algorithms():
    result = crypto_benchmark_service.run_crypto_suite()
    assert set(result["results"].keys()) == {
        "aes_256_gcm", "chacha20_poly1305", "rsa_4096", "ed25519", "ecdsa_p256"
    }
    assert result["duration_ms"] > 0
    assert result["memory_peak_kb"] > 0


def test_throughput_differs_between_algorithms():
    """AES should be meaningfully faster than RSA — sanity check that timing is real, not stubbed."""
    aes = crypto_benchmark_service.benchmark_aes_gcm(n=50)
    rsa = crypto_benchmark_service.benchmark_rsa4096(n=1)
    assert aes["encrypt"]["avg_us_per_op"] < rsa["key_generation_ms"] * 1000
