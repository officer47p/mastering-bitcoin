from ecdsa import ellipticcurve
import hashlib
import base58

# Compressed Public Key Config
compressed_public_key = True


_a = 0x0000000000000000000000000000000000000000000000000000000000000000
_b = 0x0000000000000000000000000000000000000000000000000000000000000007
_p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
_Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
_r = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

curve_secp256k1 = ellipticcurve.CurveFp(_p, _a, _b, 1)
generator_secp256k1 = ellipticcurve.PointJacobi(
    curve_secp256k1, _Gx, _Gy, 1, _r, generator=True
)

def create_private_key_from_passphrase(passphrase):
    priv_key_bytes = hashlib.sha256(passphrase.encode()).digest()
    # print(f"Priv key bytes: {priv_key_bytes}")
    priv_key_hex = priv_key_bytes.hex()
    # print(f"Priv key hex: {priv_key_hex}")
    return priv_key_hex

def create_public_key_from_private_key(priv_key, compressed=False):
    priv_key_as_int = int(priv_key, 16)
    pubkey_point = priv_key_as_int * generator_secp256k1
    point_x = pubkey_point.x()
    point_y = pubkey_point.y()
    if(compressed):
        if(point_y % 2 == 0):
            prefix = "02"
        else:
            prefix = "03"
        public_key_hex = prefix + hex(point_x)[2:]
        return public_key_hex
    else:
        public_key_hex = "04" + hex(point_x)[2:] + hex(point_y)[2:]
        return public_key_hex

def create_public_key_hash(pub_key):
    sha256_hash = hashlib.sha256(bytes.fromhex(pub_key)).digest()
    ripmd160_hash = hashlib.new("ripemd160", sha256_hash).digest()
    return ripmd160_hash.hex()

def create_checksum_from_public_key_hash(payload):
    # 8
    data = bytes.fromhex(payload)
    first_sha256_hash = hashlib.sha256(data).digest()
    second_sha256_hash = hashlib.sha256(first_sha256_hash).digest()
    # print(len(second_sha256_hash))
    return second_sha256_hash[:4].hex()

def create_wallet_address_from_public_key_hash_with_checksum(pubkey_hash):
    return base58.b58encode(bytes.fromhex(pubkey_hash)).decode('utf-8')


private_key = create_private_key_from_passphrase("helloworldparsa")
print(f"Private Key in Hex: {private_key}")

public_key = create_public_key_from_private_key(private_key, compressed=compressed_public_key)
print(f"Public Key in Hex: {public_key}")

public_key_hash = create_public_key_hash(public_key)
print(f"Public Key Hash in Hex: {public_key_hash}")

version = '00'
public_key_hash_with_version = version + public_key_hash
public_key_hash_checksum = create_checksum_from_public_key_hash(public_key_hash_with_version)
print(f"Public Key Hash Checksum in Hex: {public_key_hash_checksum}")

public_key_hash_with_checksum = public_key_hash_with_version + public_key_hash_checksum
print(f"Public Key Hash With Version And Checksum in Hex: {public_key_hash_with_checksum}")

wallet_address = create_wallet_address_from_public_key_hash_with_checksum(public_key_hash_with_checksum)
print(f"Wallet Address in Base58 Encoding: {wallet_address}")





# sk = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1) #this is your sign (private key)
# private_key = sk.to_string().hex()
# print(private_key) #convert your private key to hex
# vk = sk.get_verifying_key() #this is your verification key (public key)
# public_key = vk.to_string().hex()
# print(public_key)