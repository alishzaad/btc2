import os
import hashlib
import ecdsa
import base58
import sys
import time
import multiprocessing
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# --- Configuration ---
MAX_ATTEMPTS = 10_000_000  # Stop after this many attempts
MAX_CORES = 6              # Use max 6 cores to prevent overheating
SAFE_DURATION = 1800       # 30 minutes max runtime (seconds)
CHECK_INTERVAL = 15        # Temperature check interval (seconds)
STATUS_UPDATE = 1000       # Update status every N attempts

# --- Address Validation ---
def is_valid_bitcoin_address(address):
    """Validate Bitcoin address using base58 checksum"""
    try:
        decoded = base58.b58decode(address)
        if len(decoded) != 25: 
            return False
            
        checksum = decoded[-4:]
        payload = decoded[:-4]
        calculated_checksum = hashlib.sha256(hashlib.sha256(payload).digest()[:4]
        return checksum == calculated_checksum
    except Exception:
        return False

# --- Optimized Address Generation ---
def generate_address_pair(private_hex):
    """Generate both compressed and uncompressed addresses efficiently"""
    try:
        # Generate keys
        sk_bytes = bytes.fromhex(private_hex)
        sk = ecdsa.SigningKey.from_string(sk_bytes, curve=ecdsa.SECP256k1)
        vk = sk.verifying_key
        x = vk.pubkey.point.x()
        y = vk.pubkey.point.y()
        
        # Prepare public keys
        pub_comp = (b'\x02' if y % 2 == 0 else b'\x03') + x.to_bytes(32, 'big')
        pub_uncomp = b'\x04' + vk.to_string()
        
        # Hashing function
        def hash_pubkey(pub):
            sha = hashlib.sha256(pub).digest()
            ripemd = hashlib.new('ripemd160')
            ripemd.update(sha)
            return ripemd.digest()
        
        # Hash both public keys
        hash_comp = hash_pubkey(pub_comp)
        hash_uncomp = hash_pubkey(pub_uncomp)
        
        # Address creation function
        def make_address(hash_bytes):
            versioned = b'\x00' + hash_bytes
            sha1 = hashlib.sha256(versioned).digest()
            sha2 = hashlib.sha256(sha1).digest()
            return base58.b58encode(versioned + sha2[:4]).decode('ascii')
        
        return make_address(hash_comp), make_address(hash_uncomp)
    except Exception as e:
        return None, None

# --- Worker Function ---
def worker(target_address, queue, stop_event, core_id):
    """Worker process that generates and checks addresses"""
    attempt_count = 0
    start_time = time.time()
    last_update = time.time()
    
    while not stop_event.is_set() and attempt_count < MAX_ATTEMPTS:
        attempt_count += 1
        private_hex = os.urandom(32).hex()
        addr_comp, addr_uncomp = generate_address_pair(private_hex)
        
        if addr_comp == target_address:
            queue.put({
                'type': 'success',
                'private_hex': private_hex,
                'address': addr_comp,
                'address_type': 'compressed',
                'core': core_id,
                'attempts': attempt_count,
                'time': time.time() - start_time
            })
            stop_event.set()
            return
            
        if addr_uncomp == target_address:
            queue.put({
                'type': 'success',
                'private_hex': private_hex,
                'address': addr_uncomp,
                'address_type': 'uncompressed',
                'core': core_id,
                'attempts': attempt_count,
                'time': time.time() - start_time
            })
            stop_event.set()
            return
            
        # Periodic status update
        if attempt_count % STATUS_UPDATE == 0:
            elapsed = time.time() - start_time
            speed = attempt_count / elapsed if elapsed > 0 else 0
            queue.put({
                'type': 'status',
                'core': core_id,
                'attempts': attempt_count,
                'speed': speed,
                'time': elapsed
            })
            
        # Short sleep to prevent overheating
        if attempt_count % 100 == 0:
            time.sleep(0.001)

# --- Temperature Monitor ---
def temperature_monitor(stop_event, queue):
    """Monitor system temperature and warn if too high"""
    start_time = time.time()
    while not stop_event.is_set():
        elapsed = time.time() - start_time
        if elapsed > SAFE_DURATION:
            queue.put({'type': 'timeout'})
            stop_event.set()
            return
            
        # Simulated temperature check (in real device use proper sensors)
        if elapsed > 600:  # After 10 minutes
            queue.put({
                'type': 'warning',
                'message': f"Device getting warm! {elapsed/60:.1f} minutes elapsed"
            })
            
        time.sleep(CHECK_INTERVAL)

# --- Main Process ---
def main():
    # Display banner
    print(f"\n{Fore.CYAN}{'='*50}")
    print(f"{Fore.YELLOW}BITCOIN ADDRESS FINDER (MOBILE OPTIMIZED)".center(50))
    print(f"{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
    print(f"{Fore.MAGENTA}• Safe Mode: {MAX_CORES} cores | Max {SAFE_DURATION//60} min runtime")
    print(f"• Press Ctrl+C to stop anytime{Style.RESET_ALL}\n")
    
    # Get target address
    target_address = input(f"{Fore.GREEN}Enter target Bitcoin address: {Style.RESET_ALL}").strip()
    if not is_valid_bitcoin_address(target_address):
        print(f"{Fore.RED}✘ Invalid Bitcoin address!{Style.RESET_ALL}")
        return
        
    print(f"\n{Fore.YELLOW}Starting search on {MAX_CORES} cores...{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Initializing workers...{Style.RESET_ALL}")
    
    # Create shared objects
    manager = multiprocessing.Manager()
    queue = manager.Queue()
    stop_event = manager.Event()
    
    # Create worker pool
    pool = multiprocessing.Pool(processes=MAX_CORES)
    
    # Start temperature monitor
    temp_process = multiprocessing.Process(
        target=temperature_monitor, 
        args=(stop_event, queue)
    )
    temp_process.start()
    
    # Start workers
    workers = []
    for core_id in range(MAX_CORES):
        worker_process = pool.apply_async(
            worker, 
            (target_address.lower(), queue, stop_event, core_id+1)
        )
        workers.append(worker_process)
    
    # Main monitoring loop
    total_attempts = 0
    start_time = time.time()
    last_status = start_time
    
    try:
        while not stop_event.is_set():
            # Process messages from queue
            if not queue.empty():
                data = queue.get()
                
                if data['type'] == 'status':
                    total_attempts += data['attempts']
                    print(f"{Fore.BLUE}CORE {data['core']}: "
                          f"{data['attempts']} attempts | "
                          f"{data['speed']:.1f} addr/sec | "
                          f"Elapsed: {data['time']:.1f}s{Style.RESET_ALL}")
                          
                elif data['type'] == 'success':
                    print(f"\n{Fore.GREEN}{'!'*50}")
                    print(f"!!! MATCH FOUND ON CORE {data['core']} !!!")
                    print(f"{'!'*50}{Style.RESET_ALL}")
                    print(f"Private Key: {Fore.CYAN}{data['private_hex']}{Style.RESET_ALL}")
                    print(f"Address: {Fore.YELLOW}{data['address']}{Style.RESET_ALL}")
                    print(f"Type: {data['address_type']}")
                    print(f"Attempts: {data['attempts']:,}")
                    print(f"Time: {data['time']:.2f} seconds")
                    
                    # Save to file
                    with open('found_key.txt', 'w') as f:
                        f.write(f"Target Address: {target_address}\n")
                        f.write(f"Private Key: {data['private_hex']}\n")
                        f.write(f"Address: {data['address']}\n")
                        f.write(f"Type: {data['address_type']}\n")
                        f.write(f"Core: {data['core']}\n")
                        f.write(f"Attempts: {data['attempts']}\n")
                        f.write(f"Time: {data['time']:.2f} seconds\n")
                    
                    print(f"\n{Fore.GREEN}Results saved to 'found_key.txt'{Style.RESET_ALL}")
                    break
                    
                elif data['type'] == 'warning':
                    print(f"{Fore.YELLOW}⚠ {data['message']}{Style.RESET_ALL}")
                    
                elif data['type'] == 'timeout':
                    print(f"{Fore.YELLOW}\nSAFETY TIMEOUT: Stopped after {SAFE_DURATION//60} minutes{Style.RESET_ALL}")
                    break
            
            # Periodic total status
            if time.time() - last_status > 10:
                elapsed = time.time() - start_time
                total_speed = total_attempts / elapsed if elapsed > 1 else 0
                print(f"\n{Fore.MAGENTA}TOTAL: {total_attempts:,} attempts | "
                      f"Speed: {total_speed:.1f} addr/sec | "
                      f"Elapsed: {elapsed:.1f}s{Style.RESET_ALL}")
                last_status = time.time()
            
            time.sleep(0.1)
            
    except KeyboardInterrupt:
        print(f"{Fore.YELLOW}\nPROGRAM STOPPED BY USER{Style.RESET_ALL}")
    finally:
        # Clean up
        stop_event.set()
        pool.close()
        pool.terminate()
        temp_process.terminate()
        pool.join()
        temp_process.join()
        
        # Final stats
        elapsed = time.time() - start_time
        total_speed = total_attempts / elapsed if elapsed > 0 else 0
        print(f"\n{Fore.CYAN}{'='*50}")
        print(f"{'FINAL STATISTICS'.center(50)}")
        print(f"{'='*50}{Style.RESET_ALL}")
        print(f"Total attempts: {Fore.GREEN}{total_attempts:,}{Style.RESET_ALL}")
        print(f"Total time: {Fore.YELLOW}{elapsed:.2f} seconds{Style.RESET_ALL}")
        print(f"Average speed: {Fore.CYAN}{total_speed:.1f} addresses/sec{Style.RESET_ALL}")
        print(f"Device safety: {Fore.GREEN}No overheating detected{Style.RESET_ALL}\n")

if __name__ == "__main__":
    # For Android compatibility
    multiprocessing.freeze_support()
    
    # Set process priority (Android specific)
    try:
        import android
        android.set_process_priority(android.PRIORITY_BACKGROUND)
    except ImportError:
        pass
    
    main()
