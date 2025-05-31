import os
import hashlib
import ecdsa
import base58
import sys
import requests # For making API calls
import time     # For potential rate limiting
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
    sk_bytes = bytes.fromhex(private_hex)
    sk = ecdsa.SigningKey.from_string(sk_bytes, curve=ecdsa.SECP256k1)
    vk = sk.verifying_key

    if compressed:
        pub_key_bytes = bytes.fromhex(
            ("02" if vk.pubkey.point.y() % 2 == 0 else "03") +
            vk.pubkey.point.x().to_bytes(32, 'big').hex()
        )
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

# --- Blockchain API Check Function ---
def check_address_on_blockchain(address):
    """
    Checks the given Bitcoin address balance and transaction details using Blockchair API.
    Returns a string with the information or an error message.
    """
    try:
        # It's good practice to wait a bit between API calls if checking many addresses,
        # but here it's only called once upon a successful (highly unlikely) match.
        # time.sleep(1) # Not strictly necessary for a single call on success

        api_url = f"https://api.blockchair.com/bitcoin/dashboards/address/{address}"
        response = requests.get(api_url, timeout=10) # Added timeout
        response.raise_for_status() # Raises an exception for HTTP errors (4XX or 5XX)

        data = response.json()

        if data and data.get('data') and address in data['data']:
            address_info = data['data'][address]['address']
            balance_satoshi = address_info.get('balance', 0)
            balance_btc = balance_satoshi / 100_000_000  # Convert satoshi to BTC
            tx_count = address_info.get('transaction_count', 0)
            
            return (f"{Fore.CYAN}Blockchain Info for {address}:{Style.RESET_ALL}\n"
                    f"  Balance: {balance_btc:.8f} BTC ({balance_satoshi} satoshi)\n"
                    f"  Transaction Count: {tx_count}")
        else:
            return f"{Fore.YELLOW}Could not retrieve blockchain info for {address}. Response might be empty or malformed.{Style.RESET_ALL}"

    except requests.exceptions.RequestException as e:
        return f"{Fore.RED}API Request Error: {e}{Style.RESET_ALL}"
    except Exception as e:
        return f"{Fore.RED}Error processing blockchain data: {e}{Style.RESET_ALL}"

# --- Main Execution ---
def main():
    try:
        target_address = input("Please enter the target Bitcoin address: ").strip()
        if not target_address: # Basic validation
            print(f"{Fore.RED}No target address entered. Exiting.{Style.RESET_ALL}")
            sys.exit(1)
            
        print("\nStarting scan... (Press Ctrl+C to stop)\n")
        attempt_count = 0

        while True:
            attempt_count += 1
            private_hex = generate_private_key()
            generated_address = generate_bitcoin_address(private_hex, compressed=True)

            status = f"Attempt #{attempt_count} | Private Key: {private_hex[:8]}...{private_hex[-8:]} | Address: {generated_address}"
            print(status, end="\r", flush=True)

            if generated_address.lower() == target_address.lower():
                print(f"\n\n{Fore.GREEN}!!! MATHEMATICAL MATCH FOUND !!!{Style.RESET_ALL}")
                print(f"Private Key (Hex): {private_hex}")
                print(f"Generated Bitcoin Address: {generated_address}")
                
                print(f"\n{Fore.BLUE}Attempting to verify address on the blockchain...{Style.RESET_ALL}")
                blockchain_info = check_address_on_blockchain(generated_address)
                print(blockchain_info)

                with open('found_bitcoin_key_with_blockchain_check.txt', 'w') as f:
                    f.write(f"Target Address: {target_address}\n")
                    f.write(f"Private Key (Hex): {private_hex}\n")
                    f.write(f"Generated Bitcoin Address: {generated_address}\n")
                    f.write(f"--- Blockchain Info ---\n{blockchain_info}\n")

                print(f"\nInformation saved to 'found_bitcoin_key_with_blockchain_check.txt'.")
                print(f"Total attempts: {attempt_count}")
                sys.exit(0)

    except KeyboardInterrupt:
        print(f"\n\nScan stopped by user. Total attempts: {attempt_count}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Fore.RED}An unexpected error occurred: {e}{Style.RESET_ALL}")
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
    {Fore.YELLOW}Bitcoin Address Finder & Verifier (Educational Purposes Only){Style.RESET_ALL}
    """)
    print(f"{Fore.RED}WARNING: The probability of finding a specific private key for a Bitcoin address by random generation is astronomically low.{Style.RESET_ALL}")
    print(f"{Fore.RED}This tool is for educational demonstration only.{Style.RESET_ALL}\n")
    main()
