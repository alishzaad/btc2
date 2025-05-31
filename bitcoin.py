import os
import hashlib
import ecdsa
import base58 # For Bitcoin address encoding
import sys
from colorama import Fore, Style, init

# Initialize colorama
init()

# --- Bitcoin Address Generation Functions ---
def generate_private_key():
    """Generates a random 32-byte private key and returns it as a hex string."""
    return os.urandom(32).hex()

def generate_bitcoin_address(private_hex, compressed=True):
    """
    Generates a Bitcoin P2PKH (Pay-to-Public-Key-Hash) address from a private key.
    """
    # 1. Private key to public key
    sk_bytes = bytes.fromhex(private_hex)
    sk = ecdsa.SigningKey.from_string(sk_bytes, curve=ecdsa.SECP256k1)
    vk = sk.verifying_key

    if compressed:
        # Compressed public key
        # (0x02 if y is even, 0x03 if y is odd) + x-coordinate
        pub_key_bytes = bytes.fromhex(
            ("02" if vk.pubkey.point.y() % 2 == 0 else "03") +
            vk.pubkey.point.x().to_bytes(32, 'big').hex()
        )
    else:
        # Uncompressed public key (0x04 + x-coordinate + y-coordinate)
        pub_key_bytes = b'\x04' + vk.to_string() # vk.to_string() is x and y concatenated

    # 2. SHA-256 hash of the public key
    sha256_pub_key = hashlib.sha256(pub_key_bytes).digest()

    # 3. RIPEMD-160 hash of the SHA-256 hash
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(sha256_pub_key)
    hashed_public_key = ripemd160.digest()

    # 4. Add version byte (0x00 for Mainnet P2PKH)
    version_byte = b'\x00'
    versioned_payload = version_byte + hashed_public_key

    # 5. Perform SHA-256 hash on the extended RIPEMD-160 result
    sha256_1 = hashlib.sha256(versioned_payload).digest()

    # 6. Perform SHA-256 hash on the result of the previous SHA-256 hash
    sha256_2 = hashlib.sha256(sha256_1).digest()

    # 7. Take the first 4 bytes of the second SHA-256 hash as the checksum
    checksum = sha256_2[:4]

    # 8. Add the 4 checksum bytes to the end of the extended RIPEMD-160 hash (versioned payload)
    binary_address = versioned_payload + checksum

    # 9. Convert the result from a byte string to a base58 string
    bitcoin_address = base58.b58encode(binary_address).decode('ascii')

    return bitcoin_address

# --- Main Execution ---
def main():
    try:
        target_address = input("Please enter the target Bitcoin address with a balance: ").strip()
        print("\nStarting scan... (Press Ctrl+C to stop)\n")

        attempt_count = 0

        while True:
            attempt_count += 1
            private_hex = generate_private_key()
            # We'll generate compressed addresses by default as they are more common
            generated_address = generate_bitcoin_address(private_hex, compressed=True)

            status = f"Attempt #{attempt_count} | Private Key: {private_hex[:8]}...{private_hex[-8:]} | Address: {generated_address}"
            print(status, end="\r", flush=True) # Added flush=True for better real-time update

            if generated_address.lower() == target_address.lower():
                print(f"\n\n{Fore.GREEN}!!! SUCCESS !!!{Style.RESET_ALL}")
                print(f"Private key matches the target address!")
                print(f"Private Key (Hex): {private_hex}")
                print(f"Generated Bitcoin Address: {generated_address}")

                with open('found_bitcoin_key.txt', 'w') as f:
                    f.write(f"Target Address: {target_address}\n")
                    f.write(f"Private Key (Hex): {private_hex}\n")
                    f.write(f"Generated Bitcoin Address: {generated_address}\n")

                print(f"\nInformation saved to 'found_bitcoin_key.txt'.")
                print(f"Total attempts: {attempt_count}")
                sys.exit(0)

    except KeyboardInterrupt:
        print(f"\n\nScan stopped by user. Total attempts: {attempt_count}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Fore.RED}Error: {e}{Style.RESET_ALL}")
        sys.exit(1)

if __name__ == "__main__":
    print(f"""
    {Fore.CYAN}
    ██████╗░████████╗░██████╗░██╗░░░░░░██╗██████╗░██╗███╗░░██╗
    ██╔══██╗╚══██╔══╝██╔════╝░██║░░██╗░██║██╔══██╗██║████╗░██║
    ██████╔╝░░░██║░░░██║░░██╗░██║░░███████║██████╔╝██║██╔██╗██║
    ██╔══██╗░░░██║░░░██║░░╚██╗██║░░╚════██║██╔══██╗██║██║╚████║
    ██████╔╝░░░██║░░░╚██████╔╝███████╗░░██║██║░░██║██║██║░╚███║
    ╚═════╝░░░░╚═╝░░░░╚═════╝░╚══════╝░░╚═╝╚═╝░░╚═╝╚═╝╚═╝░░╚══╝
    {Style.RESET_ALL}
    {Fore.YELLOW}Bitcoin Address Finder (Educational Purposes Only){Style.RESET_ALL}
    """)
    print(f"{Fore.RED}WARNING: The probability of finding a specific Bitcoin address with existing funds by random generation is astronomically low.{Style.RESET_ALL}")
    print(f"{Fore.RED}This tool is for educational demonstration of key generation and address derivation only.{Style.RESET_ALL}\n")
    main()
