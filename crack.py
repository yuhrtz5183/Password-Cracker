#!/usr/bin/env python3

import hashlib
import argparse
import json
from itertools import product, combinations_with_replacement
from string import digits
from time import time
from typing import Dict, Set, List

from multiprocessing import Pool, cpu_count, Manager


# -------------------------
# Utilities
# -------------------------
def sha1_hex(s: str) -> str:
    """Return lower-case SHA1 hex digest of input string."""
    return hashlib.sha1(s.encode("utf-8", errors="ignore")).hexdigest()


def load_password_hashes(path: str) -> (Dict[str, str], Dict[str, str]):
    hash_to_uid, uid_to_hash = {}, {}
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        for lineno, line in enumerate(f, start=1):
            parts = line.strip().split()
            if len(parts) < 2:
                print(f"[WARN] Malformed line {lineno}: {line.strip()}")
                continue
            uid, h = parts[0], parts[1].lower()
            hash_to_uid[h] = uid
            uid_to_hash[uid] = h
    return hash_to_uid, uid_to_hash


def load_dictionary(path: str) -> List[str]:
    return [line.strip().lower()
            for line in open(path, 'r', encoding='utf-8', errors='ignore')
            if line.strip()]


# -------------------------
# Core Cracking Logic
# -------------------------
tested_candidates: Set[str] = set()  # Avoid duplicate testing


def check_and_crack(candidate: str, remaining: Set[str], found: Dict[str, str]) -> bool:
    candidate = candidate.lower()
    if candidate in tested_candidates:
        return False
    tested_candidates.add(candidate)

    h = sha1_hex(candidate)
    if h in remaining:
        found[h] = candidate
        remaining.remove(h)
        print(f"[{time.strftime('%H:%M:%S')}] [FOUND] {candidate} -> {h}")
        return True
    return False


# -------------------------
# PARALLEL NUMERIC WORKERS
# -------------------------
def numeric_worker(args):
    start, end, target_len, remaining_set = args

    sha1 = hashlib.sha1
    local_found = {}

    for i in range(start, end):
        s = str(i).zfill(target_len)
        h = sha1(s.encode()).hexdigest()

        if h in remaining_set:
            local_found[h] = s

    return local_found


def try_numeric_parallel(remaining: Set[str], found: Dict[str, str]):
    print(f"[NUMERIC] Using {cpu_count()} CPU cores")

    # Convert remaining to a normal Python set (WAY faster than Manager dict)
    remaining_set = set(remaining)

    for length in range(1, 11):
        if not remaining:
            return

        print(f"[{time.strftime('%H:%M:%S')}] [NUMERIC] Trying all {length}-digit combinations...")

        total = 10 ** length
        cores = cpu_count()
        chunk = total // cores
        target_len = length

        # Create ranges for workers
        ranges = []
        for c in range(cores):
            start = c * chunk
            end = (c + 1) * chunk if c < cores - 1 else total
            ranges.append((start, end, target_len, remaining_set))

        with Pool(cores) as pool:
            results = pool.map(numeric_worker, ranges)

        # Merge results
        for r in results:
            for h, pwd in r.items():
                if h in remaining:
                    found[h] = pwd
                    remaining.remove(h)
                    print(f"[FOUND] {pwd} -> {h}")

        if not remaining:
            print(f"[NUMERIC] All passwords found by {length}-digit stage!")
            return

    print(f"[{time.strftime('%H:%M:%S')}] [NUMERIC] Stage complete")


# -------------------------
# Word Digit Insertion
# -------------------------
def generate_digit_insertions(words: List[str], max_digits: int) -> List[str]:
    """Generate all combinations of digits in any position between words."""
    if not words:
        return []

    results = set()
    slots = len(words) + 1  # possible digit slots

    def splits(n, k):
        if k == 1:
            yield (n,)
        else:
            for i in range(n + 1):
                for tail in splits(n - i, k - 1):
                    yield (i,) + tail

    for total_digits in range(0, max_digits + 1):

        for dist in splits(total_digits, slots):
            parts = []

            for idx, word in enumerate(words):
                if dist[idx] > 0:
                    for ds in product(digits, repeat=dist[idx]):
                        parts.append(''.join(ds))
                parts.append(word)

            if dist[-1] > 0:
                for ds in product(digits, repeat=dist[-1]):
                    parts.append(''.join(ds))

            def flatten(parts):
                yield ''.join(parts)

            for cand in flatten(parts):
                results.add(cand)

    return list(results)


# -------------------------
# Word Combinations
# -------------------------
def try_word_combinations(dictionary: List[str], max_words: int, remaining: Set[str],
                          found: Dict[str, str], max_digits: int = 10):

    print(f"[WORDS] Starting word combinations...")

    dict_limit = min(len(dictionary), 200) if max_words >= 3 else len(dictionary)
    dict_subset = dictionary[:dict_limit]

    from itertools import product as cartesian

    for num_words in range(1, max_words + 1):
        if not remaining:
            return

        print(f"[WORDS] Generating {num_words}-word combos...")
        for combo in cartesian(dict_subset, repeat=num_words):
            variants = generate_digit_insertions(list(combo), max_digits)
            for v in variants:
                if not remaining:
                    return
                check_and_crack(v, remaining, found)


def try_repeated_words(dictionary: List[str], remaining: Set[str], found: Dict[str, str], max_digits: int = 10):
    print("[REPEAT] Trying repeated-word patterns...")
    for w in dictionary:
        variants = generate_digit_insertions([w, w], max_digits)
        for v in variants:
            if not remaining:
                return
            check_and_crack(v, remaining, found)


# ----------------
# Main Cracking 
# ----------------
import time

def try_password_patterns(remaining: Set[str], found: Dict[str, str], dictionary: List[str]):
    print(f"[INFO] Starting cracking. Targets: {len(remaining)}, Dictionary: {len(dictionary)}")

    # ---- STAGE 1 ----
    start = time.time()
    print(f"[{time.strftime('%H:%M:%S')}] [STAGE 1] Numeric brute force started")

    try_numeric_parallel(remaining, found)

    end = time.time()
    print(f"[{time.strftime('%H:%M:%S')}] [STAGE 1] Complete (elapsed: {end - start:.2f}s)")

    # ---- STAGE 2 ----
    if remaining:
        start = time.time()
        print(f"[{time.strftime('%H:%M:%S')}] [STAGE 2] Word combinations started")

        try_word_combinations(dictionary, 4, remaining, found)

        end = time.time()
        print(f"[{time.strftime('%H:%M:%S')}] [STAGE 2] Complete (elapsed: {end - start:.2f}s)")

    # ---- STAGE 3 ----
    if remaining:
        start = time.time()
        print(f"[{time.strftime('%H:%M:%S')}] [STAGE 3] Repeated-word patterns started")

        try_repeated_words(dictionary, remaining, found)

        end = time.time()
        print(f"[{time.strftime('%H:%M:%S')}] [STAGE 3] Complete (elapsed: {end - start:.2f}s)")

    print(f"[INFO] Cracking finished. Found: {len(found)}, Remaining: {len(remaining)}")


# -------------------------
# Main Pipeline Wrapper
# -------------------------
def run_pipeline(password_file: str, dictionary_file: str):
    start_time = time.time()
    hash_to_uid, uid_to_hash = load_password_hashes(password_file)
    remaining = set(hash_to_uid.keys())
    found: Dict[str, str] = {}
    dictionary = load_dictionary(dictionary_file)

    try_password_patterns(remaining, found, dictionary)

    elapsed = time() - start_time

    with open("cracked_results.txt", "w", encoding="utf-8") as f:
        for h, pwd in found.items():
            uid = hash_to_uid.get(h, "UNKNOWN")
            f.write(f"{uid}\t{h}\t{pwd}\n")

    stats = {
        "total_hashes": len(hash_to_uid),
        "cracked": len(found),
        "uncracked": len(remaining),
        "percent": len(found) / len(hash_to_uid) * 100 if hash_to_uid else 0,
        "elapsed_seconds": elapsed,
        "dictionary_size": len(dictionary)
    }

    with open("stats.json", "w", encoding="utf-8") as f:
        json.dump(stats, f, indent=2)

    print("\n" + "=" * 40)
    print("Cracking Complete")
    print(f"Cracked {len(found)}/{len(hash_to_uid)} ({stats['percent']:.1f}%)")
    print(f"Time elapsed: {elapsed:.2f}s")
    if remaining:
        print(f"{len(remaining)} passwords remain uncracked")
    else:
        print("✓ ALL PASSWORDS CRACKED!")

    return stats


# -------------------------
# CLI
# -------------------------
def parse_args():
    p = argparse.ArgumentParser(description="Comprehensive Password Cracker")
    p.add_argument("--passwords", "-p", default="passwords.txt")
    p.add_argument("--dictionary", "-d", default="dictionary.txt")
    return p.parse_args()


def main():
    args = parse_args()
    run_pipeline(args.passwords, args.dictionary)


if __name__ == "__main__":
    main()
