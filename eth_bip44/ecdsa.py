try:
    import eth_bip44.ecdsa_openssl as _ecdsa
except:
    import eth_bip44.ecdsa_python as _ecdsa

ECPointAffine = _ecdsa.ECPointAffine
EllipticCurve = _ecdsa.EllipticCurve
secp256k1 = _ecdsa.secp256k1
