import argparse
import secrets
import binascii
from ecdsa import SECP256k1, SigningKey
import sys

def generate_keypair(bit_size=256):
    # generate integer with bit_size bits, then adjust to 32-byte key for signing
    byte_len = (bit_size + 7) // 8
    # random integer with exactly bit_size bits
    rand_int = secrets.randbits(bit_size)
    # set top bit to ensure value >= 2**(bit_size-1)
    rand_int |= (1 << (bit_size - 1))
    rand_bytes = rand_int.to_bytes(byte_len, 'big')
    # ensure 32-byte length for SigningKey: pad with zeros or truncate
    if byte_len < 32:
        priv = rand_bytes.rjust(32, b'\x00')
    else:
        priv = rand_bytes[-32:]
    sk = SigningKey.from_string(priv, curve=SECP256k1)
    vk = sk.get_verifying_key().to_string()

    # 2) compressed pubkey = prefix + X
    x = vk[:32]
    y = vk[32:]
    prefix = b'\x02' if (y[-1] % 2 == 0) else b'\x03'
    comp_pub = prefix + x

    # hex-encode
    return priv.hex(), comp_pub.hex()

def main():
    p = argparse.ArgumentParser(description="Generate BTC keypairs")
    p.add_argument("-b", "--bits", type=int, default=256,
                   help="bit size of private key (must be a multiple of 8)")
    p.add_argument("-n", "--count", type=int, default=1,
                   help="number of keys to generate")
    p.add_argument("--pub-out", default="public_keys.txt",
                   help="output file for public keys")
    p.add_argument("--all-out", default="private_public_keys.txt",
                   help="output file for priv#pub")
    # Show help if no arguments are provided
    if len(sys.argv) == 1:
        p.print_help()
        sys.exit(0)
    args = p.parse_args()

    with open(args.pub_out, "w") as fpub, open(args.all_out, "w") as fall:
        for _ in range(args.count):
            priv_hex, pub_hex = generate_keypair(args.bits)
            fpub.write(pub_hex + "\n")
            fall.write(f"{priv_hex}#{pub_hex}\n")

    print(f"Wrote {args.count} pubkeys to {args.pub_out} and priv#pub to {args.all_out}")

if __name__ == "__main__":
    main()