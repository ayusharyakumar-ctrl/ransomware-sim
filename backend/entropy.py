"""Shannon entropy helper.

Entropy measures how random a file's bytes are, on a scale of 0 to 8 bits per byte.
  - Plain text / documents  -> usually 3.5 - 5.5
  - Compressed images/zips  -> usually 7.0 - 7.9
  - Encrypted data          -> very close to 8.0
A sudden jump towards 8.0 after a file is modified is a classic sign of encryption.
"""
import math
from collections import Counter


def shannon_entropy(data: bytes) -> float:
    """Return Shannon entropy of `data` in bits per byte (0.0 - 8.0)."""
    if not data:
        return 0.0
    total = len(data)
    counts = Counter(data)
    entropy = 0.0
    for count in counts.values():
        p = count / total
        entropy -= p * math.log2(p)
    return round(entropy, 3)


def file_entropy(path: str, max_bytes: int = 2_000_000) -> float:
    """Entropy of a file (reads at most `max_bytes` to stay fast)."""
    with open(path, "rb") as f:
        return shannon_entropy(f.read(max_bytes))
