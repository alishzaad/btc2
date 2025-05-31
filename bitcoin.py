import os
import hashlib
import ecdsa
import base58
import sys
import requests
import time
from colorama import Fore, Style, init

# Initialize colorama
init()

# --- Bitcoin Address Validation ---
def is_valid_bitcoin_address(address):
    """Validates Bitcoin address using base58 checksum check"""
    try:
        decoded = base58.b58decode(address)
        if len(decoded) != 25:
            return False
        checksum = decoded[-4:]
        payload = decoded[:-4]
        calculated_checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
        return checksum == calculated_checksum
    except Exception:
        return False

# --- Bitcoin Address Generation Functions ---
def generate_private_key():
    """Generates a random 32-byte private key and returns it as a hex string."""
    return os.urandom(32).hex()

def generate_bitcoin_address(private_hex, compressed=True):
    """
    Generates a Bitcoin P2PKH (Pay-to-Public-Key-Hash) address from a private key.
    """
    sk_bytes = bytes.fromhex(private_hex)
    sk = ecdsa.SigningKey.from_string(sk_bytes, curve=ecdsa.SECP256k1)
    vk = sk.verifying_key

    # Get public key point
    x = vk.pubkey.point.x()
    y = vk.pubkey.point.y()
    
    if compressed:
        prefix = b'\x02' if y % 2 == 0 else b'\x03'
        pub_key_bytes = prefix + x.to_bytes(32, 'big')
    else:
        pub_key_bytes = b'\x04' + vk.to_string()

    sha256_pub_key = hashlib.sha256(pub_key_bytes).digest()
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(sha256_pub_key)
    hashed_public_key = ripemd160.digest()
    version_byte = b'\x00'
    versioned_payload = version_byte + hashed_public_key
    sha256_1 = hashlib.sha256(versioned_payload).digest()
    sha256_2 = hashlib.sha256(sha256_1).digest()
    checksum = sha256_2[:4]
    binary_address = versioned_payload + checksum
    bitcoin_address = base58.b58encode(binary_address).decode('ascii')
    return bitcoin_address

# --- Blockchain API Check Function (Using BlockCypher) ---
def check_address_on_blockchain(address):
    """
    Checks the given Bitcoin address balance and transaction details using BlockCypher API.
    Returns a string with the information or an error message.
    """
    try:
        api_url = f"https://api.blockcypher.com/v1/btc/main/addrs/{address}/balance"
        response = requests.get(api_url, timeout=10)
        response.raise_for_status()
        
        data = response.json()
        balance_satoshi = data.get('final_balance', 0)
        balance_btc = balance_satoshi / 100_000_000
        tx_count = data.get('n_tx', 0)
        
        return (f"{Fore.CYAN}Blockchain Info for {address}:{Style.RESET_ALL}\n"
                f"  Balance: {balance_btc:.8f} BTC ({balance_satoshi} satoshi)\n"
                f"  Transaction Count: {tx_count}")

    except requests.exceptions.RequestException as e:
        return f"{Fore.YELLOW}API Request Error: {e}{Style.RESET_ALL}"
    except Exception as e:
        return f"{Fore.RED}Error processing blockchain data: {e}{Style.RESET_ALL}"

# --- Main Execution ---
def main():
    try:
        print(f"""
    {Fore.CYAN}
    ██████╗░████████╗░██████╗░██╗░░░░░░██╗██████╗░██╗███╗░░██╗
    ██╔══██╗╚══██╔══╝██╔════╝░██║░░██╗░██║██╔══██╗██║████╗░██║
    ██████╔╝░░░██║░░░██║░░██╗░██║░░███████║██████╔╝██║██╔██╗██║
    ██╔══██╗░░░██║░░░██║░░╚██╗██║░░╚════██║██╔══██╗██║██║╚████║
    ██████╔╝░░░██║░░░╚██████╔╝███████╗░░██║██║░░██║██║██║░╚███║
    ╚═════╝░░░░╚═╝░░░░╚═════╝░╚══════╝░░╚═╝╚═╝░░╚═╝╚═╝╚═╝░░╚══╝
    {Style.RESET_ALL}
    {Fore.YELLOW}Bitcoin Address Finder & Verifier (Educational Purposes Only){Style.RESET_ALL}
    """)
        print(f"{Fore.RED}WARNING: The probability of finding a specific private key for a Bitcoin address by random generation is astronomically low.{Style.RESET_ALL}")
        print(f"{Fore.RED}This tool is for educational demonstration only.{Style.RESET_ALL}\n")
        
        target_address = input("Please enter the target Bitcoin address: ").strip()
        
        # Validate address
        if not is_valid_bitcoin_address(target_address):
            print(f"{Fore.RED}Invalid Bitcoin address. Exiting.{Style.RESET_ALL}")
            sys.exit(1)
            
        print("\nStarting scan... (Press Ctrl+C to stop)\n")
        attempt_count = 0
        last_print = 0
        PRINT_INTERVAL = 1000  # Print every 1000 attempts
        start_time = time.time()

        while True:
            attempt_count += 1
            private_hex = generate_private_key()
            
            # Generate both compressed and uncompressed addresses
            for compressed in [True, False]:
                generated_address = generate_bitcoin_address(private_hex, compressed)

                if attempt_count - last_print >= PRINT_INTERVAL:
                    elapsed = time.time() - start_time
                    speed = attempt_count / elapsed if elapsed > 0 else 0
                    status = (f"Attempt #{attempt_count} | Speed: {speed:.1f} addr/sec | "
                              f"Private: {private_hex[:6]}...{private_hex[-6:]} | Address: {generated_address}")
                    print(status, end="\r", flush=True)
                    last_print = attempt_count

                if generated_address.lower() == target_address.lower():
                    print(f"\n\n{Fore.GREEN}!!! MATCH FOUND !!!{Style.RESET_ALL}")
                    print(f"Private Key (Hex): {private_hex}")
                    print(f"Generated Bitcoin Address: {generated_address}")
                    print(f"Address Type: {'Compressed' if compressed else 'Uncompressed'}")
                    
                    print(f"\n{Fore.BLUE}Verifying address on blockchain...{Style.RESET_ALL}")
                    blockchain_info = check_address_on_blockchain(generated_address)
                    print(blockchain_info)

                    with open('found_key.txt', 'w') as f:
                        f.write(f"Target: {target_address}\n")
                        f.write(f"Private Key: {private_hex}\n")
                        f.write(f"Address: {generated_address}\n")
                        f.write(f"Type: {'Compressed' if compressed else 'Uncompressed'}\n")
                        f.write(f"Blockchain Info:\n{blockchain_info}\n")

                    print(f"\nSaved to 'found_key.txt'. Total attempts: {attempt_count}")
                    sys.exit(0)

    except KeyboardInterrupt:
        elapsed = time.time() - start_time
        speed = attempt_count / elapsed if elapsed > 0 else 0
        print(f"\n\nScan stopped. Total attempts: {attempt_count} | Speed: {speed:.1f} addr/sec")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Fore.RED}Error: {e}{Style.RESET_ALL}")
        sys.exit(1)

if __name__ == "__main__":
    main()
