import os
import time
import base58
import hashlib
import ecdsa
import random
from multiprocessing import Process, Value, Event, Queue, cpu_count

def private_key_to_wif(private_key, compressed=True):
    extended_key = b'\x80' + private_key
    if compressed:
        extended_key += b'\x01'
    checksum = hashlib.sha256(hashlib.sha256(extended_key).digest()).digest()[:4]
    final_key = extended_key + checksum
    return base58.b58encode(final_key).decode('utf-8')

def private_key_to_public_key(private_key, compressed=True):
    sk = ecdsa.SigningKey.from_string(private_key, curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    if compressed:
        return compress_public_key(vk.to_string())
    else:
        return b'\x04' + vk.to_string()

def compress_public_key(uncompressed_pubkey):
    x = uncompressed_pubkey[:32]
    y = uncompressed_pubkey[32:]
    parity = y[-1] & 1
    return (b'\x02' if parity == 0 else b'\x03') + x

def public_key_to_p2pkh_address(public_key):
    sha256 = hashlib.sha256(public_key).digest()
    ripemd160 = hashlib.new('ripemd160', sha256).digest()
    extended_ripemd160 = b'\x00' + ripemd160
    checksum = hashlib.sha256(hashlib.sha256(extended_ripemd160).digest()).digest()[:4]
    binary_address = extended_ripemd160 + checksum
    return base58.b58encode(binary_address).decode('utf-8')

def generate_vanity_address(prefix, start, end, found_event, result_queue, generated_count):
    while not found_event.is_set():
        # Generate a random private key in the specified range
        private_key_int = random.randint(start, end)
        private_key = private_key_int.to_bytes(32, byteorder='big')
        
        # Generate address from the private key
        address = public_key_to_p2pkh_address(private_key_to_public_key(private_key))

        # Increment the generated count
        with generated_count.get_lock():
            generated_count.value += 1

        # Check if the address matches the vanity prefix
        if address.startswith(prefix):
            wif = private_key_to_wif(private_key)
            result_queue.put((wif, address, private_key_int))
            found_event.set()
            return

def main():
    vanity_prefix = "1BY8GQ"  # Desired prefix
    start_range = 0x6000000000000000  # Start of the range
    end_range = 0x7fffffffffffffff  # End of the range
    num_workers = cpu_count()

    print(f"Vanity address search started. Desired prefix: {vanity_prefix}")
    print(f"Searching in range: {hex(start_range)} to {hex(end_range)}")
    print(f"Number of workers: {num_workers}")

    found_event = Event()
    result_queue = Queue()
    generated_count = Value('i', 0)  # Counter for generated private keys

    processes = []
    for i in range(num_workers):
        p = Process(target=generate_vanity_address, args=(vanity_prefix, start_range, end_range, found_event, result_queue, generated_count))
        p.start()
        processes.append(p)

    start_time = time.time()
    try:
        while not found_event.is_set():
            time.sleep(1)
            elapsed_time = time.time() - start_time
            with generated_count.get_lock():
                current_generated = generated_count.value
            print(f"Elapsed time: {elapsed_time:.2f} seconds | Generated keys: {current_generated}")
    except KeyboardInterrupt:
        print("Search interrupted.")
        found_event.set()

    if not result_queue.empty():
        wif, address, private_key_int = result_queue.get()
        print("\nVanity address found!")
        print(f"Address: {address}")
        print(f"Private Key (WIF format): {wif}")
        print(f"Private Key (Hex format): {private_key_int:064x}")
    else:
        print("Address not found or search interrupted.")

    for p in processes:
        p.terminate()
    for p in processes:
        p.join()

    if found_event.is_set():
        with generated_count.get_lock():
            print(f"Total generated keys: {generated_count.value}")

if __name__ == '__main__':
    main()
