import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from packages.tickets import generate_keypair

if __name__ == "__main__":
    keypair = generate_keypair()
    print(f"private_key_hex={keypair['private_key_hex']}")
    print(f"public_key_hex={keypair['public_key_hex']}")
