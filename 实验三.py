# challenge9_pkcs7_pad.py
"""Implement PKCS#7 padding."""

def pkcs7_pad(data: bytes, block_size: int) -> bytes:
    """Pad the data to block_size using PKCS#7 padding."""
    pad_len = block_size - (len(data) % block_size)
    if pad_len == 0:
        pad_len = block_size
    return data + bytes([pad_len]) * pad_len

def pkcs7_unpad(data: bytes) -> bytes:
    """Remove PKCS#7 padding; raise ValueError if invalid."""
    pad_len = data[-1]
    if pad_len < 1 or pad_len > len(data):
        raise ValueError("Invalid padding")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid padding")
    return data[:-pad_len]

if __name__ == "__main__":
    s = b"YELLOW SUBMARINE"
    padded = pkcs7_pad(s, 20)
    print(f"Padded: {padded}")
    # Expected: b'YELLOW SUBMARINE\x04\x04\x04\x04'
    unpadded = pkcs7_unpad(padded)
    print(f"Unpadded: {unpadded}")