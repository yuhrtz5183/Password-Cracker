#!/usr/bin/env python3
"""
crack.py

Password cracking pipeline for the classroom assignment.

Stages:
  1) Numeric-only brute force (range of lengths)
  2) Dictionary-only (each dictionary word)
  3) Dictionary + numeric suffix (parallelizable)
  4) Dictionary + numeric prefix
  5) Dictionary with capitalization variations (capitalized, uppercase, + suffixes)
  6) Dictionary + long numeric suffix (4 digits)
  7) Dictionary + numeric prefix + suffix
  8) Leet speak substitutions
  9) Extended numeric brute force (7-8 digits)
  10) Date formats (YYYYMMDD, MMDDYYYY, DDMMYYYY)
  11) Dictionary + long numeric prefix (4 digits)
  12) Dictionary + special characters
  13) Dictionary words repeated
  14) Dictionary + year suffix (2000-2025)
  15) Dictionary + number in middle
  16) Capitalization + long numeric suffix (4 digits)

Outputs:
  - cracked_results.txt: lines of "userID<TAB>hash<TAB>password"
  - stats.json (summary)
  - optional verbose console logs

Usage:
  python crack.py
  python crack.py --workers 4 --max-suffix 999 --numeric-max-len 6 --verbose
"""

import hashlib
import argparse
import os
import sys
import json
from itertools import product
from string import digits
from multiprocessing import Pool, cpu_count, Manager
from time import time
from typing import Dict, Set, Tuple, List

# -------------------------
# Utilities
# -------------------------
def sha1_hex(s: str) -> str:
    """Return lower-case SHA1 hex digest of input string."""
    return hashlib.sha1(s.encode("utf-8", errors="ignore")).hexdigest()

def load_password_hashes(path: str) -> Tuple[Dict[str,str], Dict[str,str]]:
    """
    Load passwords.txt expected format per-line:
      <userID> <hash>
    Returns two dicts:
      hash_to_uid: hash -> userID
      uid_to_hash: userID -> hash
    """
    hash_to_uid = {}
    uid_to_hash = {}
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        for lineno, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) < 2:
                # try forgiving parse
                print(f"[WARN] line {lineno} malformed: {line}")
                continue
            uid, h = parts[0], parts[1].lower()
            hash_to_uid[h] = uid
            uid_to_hash[uid] = h
    return hash_to_uid, uid_to_hash

def load_dictionary(path: str) -> List[str]:
    words = []
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            w = line.strip()
            if w:
                words.append(w)
    return words

# -------------------------
# Stage implementations
# -------------------------
def numeric_bruteforce_stage(target_hashes: Set[str], max_len: int = 6, verbose=False):
    """
    Try numeric-only passwords from length 1..max_len.
    Returns dict: hash -> password
    """
    found = {}
    remaining = set(target_hashes)
    if verbose:
        print(f"[stage numeric] starting (max_len={max_len}) targets={len(remaining)}")
    for L in range(1, max_len + 1):
        if not remaining:
            break
        if verbose:
            print(f"[stage numeric] trying length {L} (candidates={10**L})")
        # iterate lexicographically 0..9 repeated L times
        for tup in product(digits, repeat=L):
            candidate = ''.join(tup)
            h = sha1_hex(candidate)
            if h in remaining:
                found[h] = candidate
                remaining.remove(h)
                if verbose:
                    print(f"[stage numeric] FOUND hash={h} pwd={candidate} -- remaining {len(remaining)}")
        # small safeguard: if L is very large this stage could be huge; but default L=6
    if verbose:
        print(f"[stage numeric] done found={len(found)}")
    return found

def dictionary_stage(target_hashes: Set[str], dictionary: List[str], verbose=False):
    """
    Try each dictionary word exactly as-is (no transformations).
    Returns dict: hash -> password
    """
    found = {}
    remaining = set(target_hashes)
    if verbose:
        print(f"[stage dict] starting dictionary attack targets={len(remaining)} words={len(dictionary)}")
    for i, w in enumerate(dictionary, start=1):
        if not remaining:
            break
        candidate = w
        h = sha1_hex(candidate)
        if h in remaining:
            found[h] = candidate
            remaining.remove(h)
            if verbose:
                print(f"[stage dict] FOUND hash={h} pwd={candidate} -- remaining {len(remaining)}")
        if verbose and i % 50000 == 0:
            print(f"[stage dict] processed {i}/{len(dictionary)} words, found so far={len(found)}")
    if verbose:
        print(f"[stage dict] done found={len(found)}")
    return found

# Worker func for multiprocessing dictionary+suffix
def _dict_suffix_worker(args):
    """
    Worker receives a tuple:
      (word_chunk, suffix_start, suffix_end, target_hashes_list)
    word_chunk: list of words to try
    suffix range inclusive: [suffix_start, suffix_end]
    target_hashes_list: list (converted to set here)
    Returns list of tuples (hash, password) found by this worker.
    """
    word_chunk, suffix_start, suffix_end, target_list = args
    target_set = set(target_list)
    found_local = []
    for w in word_chunk:
        # try the word itself (no suffix) first
        h0 = sha1_hex(w)
        if h0 in target_set:
            found_local.append((h0, w))
            target_set.remove(h0)
        # try suffixes
        # We format suffix without zero padding (e.g. '1', '23', '007' is '7' unless you want zero-padded)
        for n in range(suffix_start, suffix_end + 1):
            candidate = w + str(n)
            h = sha1_hex(candidate)
            if h in target_set:
                found_local.append((h, candidate))
                target_set.remove(h)
        # small micro-optimization: if no targets remain, stop early
        if not target_set:
            break
    return found_local

def dict_plus_digits_stage(target_hashes: Set[str], dictionary: List[str],
                           max_suffix: int = 999,
                           workers: int = 1,
                           chunk_size_words: int = 500,
                           verbose=False):
    """
    Try dictionary words each appended with numeric suffix from 0..max_suffix.
    Splits dictionary across workers and returns dict: hash -> password
    """
    remaining = set(target_hashes)
    found = {}

    if verbose:
        print(f"[stage dict+suffix] starting (max_suffix={max_suffix}, workers={workers}) targets={len(remaining)}")

    # If workers == 1, just run single-threaded variant to avoid multiprocessing overhead
    if workers <= 1:
        for i, w in enumerate(dictionary, start=1):
            if not remaining:
                break
            # word itself
            h0 = sha1_hex(w)
            if h0 in remaining:
                found[h0] = w
                remaining.remove(h0)
                if verbose:
                    print(f"[stage dict+suffix] FOUND {h0} -> {w} (word only)")
            for n in range(0, max_suffix + 1):
                candidate = w + str(n)
                h = sha1_hex(candidate)
                if h in remaining:
                    found[h] = candidate
                    remaining.remove(h)
                    if verbose:
                        print(f"[stage dict+suffix] FOUND {h} -> {candidate}")
            if verbose and i % 50000 == 0:
                print(f"[stage dict+suffix] processed {i}/{len(dictionary)} words, found so far={len(found)}")
        if verbose:
            print(f"[stage dict+suffix] done found={len(found)}")
        return found

    # Parallel path
    # Break dictionary into chunks of chunk_size_words
    word_chunks = [dictionary[i:i+chunk_size_words] for i in range(0, len(dictionary), chunk_size_words)]
    # For suffix splitting, we can let each worker try entire suffix range - it's simpler but duplicates work across workers,
    # so instead we'll keep suffix range full but split by words (each word chunk is unique), which is fine.
    # Prepare args for pool
    args_list = []
    target_list = list(remaining)
    for chunk in word_chunks:
        args_list.append((chunk, 0, max_suffix, target_list))

    if verbose:
        print(f"[stage dict+suffix] prepared {len(args_list)} chunks for pool")

    with Pool(processes=workers) as pool:
        # map in chunks, aggregate results incrementally and remove found hashes from further consideration
        # To avoid re-checking already-cracked hashes by other workers we collect results and then prune remaining.
        results = pool.imap_unordered(_dict_suffix_worker, args_list)
        for res in results:
            # res is list of (hash, password)
            for h, pwd in res:
                if h not in found and h in remaining:
                    found[h] = pwd
                    remaining.remove(h)
                    if verbose:
                        print(f"[stage dict+suffix] FOUND {h} -> {pwd} (parallel)")
            # early stop when nothing remains
            if not remaining:
                break

    if verbose:
        print(f"[stage dict+suffix] done found={len(found)}")
    return found

def dict_plus_prefix_stage(target_hashes: Set[str], dictionary: List[str],
                           max_prefix: int = 999,
                           verbose=False):
    """
    Try dictionary words with numeric prefix from 0..max_prefix.
    Returns dict: hash -> password
    """
    found = {}
    remaining = set(target_hashes)
    if verbose:
        print(f"[stage dict+prefix] starting (max_prefix={max_prefix}) targets={len(remaining)}")
    for i, w in enumerate(dictionary, start=1):
        if not remaining:
            break
        for n in range(0, max_prefix + 1):
            candidate = str(n) + w
            h = sha1_hex(candidate)
            if h in remaining:
                found[h] = candidate
                remaining.remove(h)
                if verbose:
                    print(f"[stage dict+prefix] FOUND {h} -> {candidate}")
        if verbose and i % 50000 == 0:
            print(f"[stage dict+prefix] processed {i}/{len(dictionary)} words, found so far={len(found)}")
    if verbose:
        print(f"[stage dict+prefix] done found={len(found)}")
    return found

def dict_capitalization_stage(target_hashes: Set[str], dictionary: List[str], verbose=False):
    """
    Try dictionary words with capitalization variations:
    - First letter uppercase
    - All uppercase
    - First letter uppercase + numeric suffix (0-999)
    - All uppercase + numeric suffix (0-999)
    Returns dict: hash -> password
    """
    found = {}
    remaining = set(target_hashes)
    if verbose:
        print(f"[stage dict+cap] starting targets={len(remaining)}")
    for i, w in enumerate(dictionary, start=1):
        if not remaining:
            break
        # First letter uppercase
        w_cap = w.capitalize()
        h = sha1_hex(w_cap)
        if h in remaining:
            found[h] = w_cap
            remaining.remove(h)
            if verbose:
                print(f"[stage dict+cap] FOUND {h} -> {w_cap} (capitalized)")
        # All uppercase
        w_upper = w.upper()
        h = sha1_hex(w_upper)
        if h in remaining:
            found[h] = w_upper
            remaining.remove(h)
            if verbose:
                print(f"[stage dict+cap] FOUND {h} -> {w_upper} (uppercase)")
        # Capitalized + suffix (only if word itself didn't match and we still have targets)
        # Try short suffixes first (0-999), then longer ones if needed
        if w_cap != w and remaining:
            for n in range(0, 1000):
                if not remaining:
                    break
                candidate = w_cap + str(n)
                h = sha1_hex(candidate)
                if h in remaining:
                    found[h] = candidate
                    remaining.remove(h)
                    if verbose:
                        print(f"[stage dict+cap] FOUND {h} -> {candidate} (capitalized+suffix)")
        # Uppercase + suffix (only if different from capitalized and we still have targets)
        if w_upper != w_cap and remaining:
            for n in range(0, 1000):
                if not remaining:
                    break
                candidate = w_upper + str(n)
                h = sha1_hex(candidate)
                if h in remaining:
                    found[h] = candidate
                    remaining.remove(h)
                    if verbose:
                        print(f"[stage dict+cap] FOUND {h} -> {candidate} (uppercase+suffix)")
        if verbose and i % 1000 == 0:
            print(f"[stage dict+cap] processed {i}/{len(dictionary)} words, found so far={len(found)}, remaining={len(remaining)}")
    if verbose:
        print(f"[stage dict+cap] done found={len(found)}")
    return found

def dict_long_suffix_stage(target_hashes: Set[str], dictionary: List[str],
                           max_suffix: int = 9999,
                           verbose=False):
    """
    Try dictionary words with longer numeric suffixes (4 digits).
    Returns dict: hash -> password
    """
    found = {}
    remaining = set(target_hashes)
    if verbose:
        print(f"[stage dict+longsuffix] starting (max_suffix={max_suffix}) targets={len(remaining)}")
    for i, w in enumerate(dictionary, start=1):
        if not remaining:
            break
        for n in range(1000, max_suffix + 1):
            candidate = w + str(n)
            h = sha1_hex(candidate)
            if h in remaining:
                found[h] = candidate
                remaining.remove(h)
                if verbose:
                    print(f"[stage dict+longsuffix] FOUND {h} -> {candidate}")
        if verbose and i % 10000 == 0:
            print(f"[stage dict+longsuffix] processed {i}/{len(dictionary)} words, found so far={len(found)}")
    if verbose:
        print(f"[stage dict+longsuffix] done found={len(found)}")
    return found

def dict_prefix_suffix_stage(target_hashes: Set[str], dictionary: List[str],
                             max_prefix: int = 99,
                             max_suffix: int = 99,
                             verbose=False):
    """
    Try dictionary words with both numeric prefix and suffix (e.g., "123word456").
    Limited range to keep it fast.
    Returns dict: hash -> password
    """
    found = {}
    remaining = set(target_hashes)
    if verbose:
        print(f"[stage dict+prefix+suffix] starting (max_prefix={max_prefix}, max_suffix={max_suffix}) targets={len(remaining)}")
    for i, w in enumerate(dictionary, start=1):
        if not remaining:
            break
        for p in range(0, max_prefix + 1):
            if not remaining:
                break
            for s in range(0, max_suffix + 1):
                if not remaining:
                    break
                candidate = str(p) + w + str(s)
                h = sha1_hex(candidate)
                if h in remaining:
                    found[h] = candidate
                    remaining.remove(h)
                    if verbose:
                        print(f"[stage dict+prefix+suffix] FOUND {h} -> {candidate}")
        if verbose and i % 1000 == 0:
            print(f"[stage dict+prefix+suffix] processed {i}/{len(dictionary)} words, found so far={len(found)}")
    if verbose:
        print(f"[stage dict+prefix+suffix] done found={len(found)}")
    return found

def leet_speak_stage(target_hashes: Set[str], dictionary: List[str], verbose=False):
    """
    Try dictionary words with common leet speak substitutions:
    a->4, e->3, i->1, o->0, s->5, t->7
    Returns dict: hash -> password
    """
    found = {}
    remaining = set(target_hashes)
    leet_map = {'a': '4', 'e': '3', 'i': '1', 'o': '0', 's': '5', 't': '7',
                 'A': '4', 'E': '3', 'I': '1', 'O': '0', 'S': '5', 'T': '7'}
    
    if verbose:
        print(f"[stage leet] starting targets={len(remaining)}")
    
    for i, w in enumerate(dictionary, start=1):
        if not remaining:
            break
        # Try leet substitution
        leet_word = ''.join(leet_map.get(c, c) for c in w)
        if leet_word != w:
            h = sha1_hex(leet_word)
            if h in remaining:
                found[h] = leet_word
                remaining.remove(h)
                if verbose:
                    print(f"[stage leet] FOUND {h} -> {leet_word}")
            # Try leet + suffix
            for n in range(0, 100):
                if not remaining:
                    break
                candidate = leet_word + str(n)
                h = sha1_hex(candidate)
                if h in remaining:
                    found[h] = candidate
                    remaining.remove(h)
                    if verbose:
                        print(f"[stage leet] FOUND {h} -> {candidate}")
        if verbose and i % 5000 == 0:
            print(f"[stage leet] processed {i}/{len(dictionary)} words, found so far={len(found)}")
    if verbose:
        print(f"[stage leet] done found={len(found)}")
    return found

def date_formats_stage(target_hashes: Set[str], verbose=False):
    """
    Try common date formats:
    - YYYYMMDD (2000-2099, months 01-12, days 01-31)
    - MMDDYYYY
    - DDMMYYYY
    Returns dict: hash -> password
    """
    found = {}
    remaining = set(target_hashes)
    if verbose:
        print(f"[stage dates] starting targets={len(remaining)}")
    
    # YYYYMMDD format (2000-2099)
    for year in range(2000, 2100):
        if not remaining:
            break
        for month in range(1, 13):
            if not remaining:
                break
            for day in range(1, 32):
                if not remaining:
                    break
                # YYYYMMDD
                candidate = f"{year}{month:02d}{day:02d}"
                h = sha1_hex(candidate)
                if h in remaining:
                    found[h] = candidate
                    remaining.remove(h)
                    if verbose:
                        print(f"[stage dates] FOUND {h} -> {candidate} (YYYYMMDD)")
                # MMDDYYYY
                candidate2 = f"{month:02d}{day:02d}{year}"
                h2 = sha1_hex(candidate2)
                if h2 in remaining:
                    found[h2] = candidate2
                    remaining.remove(h2)
                    if verbose:
                        print(f"[stage dates] FOUND {h2} -> {candidate2} (MMDDYYYY)")
                # DDMMYYYY
                candidate3 = f"{day:02d}{month:02d}{year}"
                h3 = sha1_hex(candidate3)
                if h3 in remaining:
                    found[h3] = candidate3
                    remaining.remove(h3)
                    if verbose:
                        print(f"[stage dates] FOUND {h3} -> {candidate3} (DDMMYYYY)")
        if verbose and year % 10 == 0:
            print(f"[stage dates] processed years up to {year}, found so far={len(found)}, remaining={len(remaining)}")
    if verbose:
        print(f"[stage dates] done found={len(found)}")
    return found

def dict_long_prefix_stage(target_hashes: Set[str], dictionary: List[str],
                          max_prefix: int = 9999,
                          verbose=False):
    """
    Try dictionary words with longer numeric prefixes (4 digits).
    Returns dict: hash -> password
    """
    found = {}
    remaining = set(target_hashes)
    if verbose:
        print(f"[stage dict+longprefix] starting (max_prefix={max_prefix}) targets={len(remaining)}")
    for i, w in enumerate(dictionary, start=1):
        if not remaining:
            break
        for n in range(1000, max_prefix + 1):
            candidate = str(n) + w
            h = sha1_hex(candidate)
            if h in remaining:
                found[h] = candidate
                remaining.remove(h)
                if verbose:
                    print(f"[stage dict+longprefix] FOUND {h} -> {candidate}")
        if verbose and i % 10000 == 0:
            print(f"[stage dict+longprefix] processed {i}/{len(dictionary)} words, found so far={len(found)}")
    if verbose:
        print(f"[stage dict+longprefix] done found={len(found)}")
    return found

def dict_special_chars_stage(target_hashes: Set[str], dictionary: List[str], verbose=False):
    """
    Try dictionary words with common special characters appended.
    Returns dict: hash -> password
    """
    found = {}
    remaining = set(target_hashes)
    special_chars = ['!', '@', '#', '$', '%', '&', '*', '?']
    if verbose:
        print(f"[stage dict+special] starting targets={len(remaining)}")
    for i, w in enumerate(dictionary, start=1):
        if not remaining:
            break
        for char in special_chars:
            candidate = w + char
            h = sha1_hex(candidate)
            if h in remaining:
                found[h] = candidate
                remaining.remove(h)
                if verbose:
                    print(f"[stage dict+special] FOUND {h} -> {candidate}")
        # Also try capitalized + special
        w_cap = w.capitalize()
        if w_cap != w:
            for char in special_chars:
                candidate = w_cap + char
                h = sha1_hex(candidate)
                if h in remaining:
                    found[h] = candidate
                    remaining.remove(h)
                    if verbose:
                        print(f"[stage dict+special] FOUND {h} -> {candidate} (capitalized)")
        if verbose and i % 5000 == 0:
            print(f"[stage dict+special] processed {i}/{len(dictionary)} words, found so far={len(found)}")
    if verbose:
        print(f"[stage dict+special] done found={len(found)}")
    return found

def dict_repeated_stage(target_hashes: Set[str], dictionary: List[str], verbose=False):
    """
    Try dictionary words repeated (e.g., "wordword").
    Returns dict: hash -> password
    """
    found = {}
    remaining = set(target_hashes)
    if verbose:
        print(f"[stage dict+repeated] starting targets={len(remaining)}")
    for i, w in enumerate(dictionary, start=1):
        if not remaining:
            break
        # Word repeated twice
        candidate = w + w
        h = sha1_hex(candidate)
        if h in remaining:
            found[h] = candidate
            remaining.remove(h)
            if verbose:
                print(f"[stage dict+repeated] FOUND {h} -> {candidate}")
        if verbose and i % 5000 == 0:
            print(f"[stage dict+repeated] processed {i}/{len(dictionary)} words, found so far={len(found)}")
    if verbose:
        print(f"[stage dict+repeated] done found={len(found)}")
    return found

def dict_year_suffix_stage(target_hashes: Set[str], dictionary: List[str], verbose=False):
    """
    Try dictionary words with year suffixes (2000-2025).
    Returns dict: hash -> password
    """
    found = {}
    remaining = set(target_hashes)
    if verbose:
        print(f"[stage dict+year] starting targets={len(remaining)}")
    for i, w in enumerate(dictionary, start=1):
        if not remaining:
            break
        for year in range(2000, 2026):
            candidate = w + str(year)
            h = sha1_hex(candidate)
            if h in remaining:
                found[h] = candidate
                remaining.remove(h)
                if verbose:
                    print(f"[stage dict+year] FOUND {h} -> {candidate}")
        # Also try capitalized
        w_cap = w.capitalize()
        if w_cap != w:
            for year in range(2000, 2026):
                candidate = w_cap + str(year)
                h = sha1_hex(candidate)
                if h in remaining:
                    found[h] = candidate
                    remaining.remove(h)
                    if verbose:
                        print(f"[stage dict+year] FOUND {h} -> {candidate} (capitalized)")
        if verbose and i % 1000 == 0:
            print(f"[stage dict+year] processed {i}/{len(dictionary)} words, found so far={len(found)}")
    if verbose:
        print(f"[stage dict+year] done found={len(found)}")
    return found

def dict_number_in_middle_stage(target_hashes: Set[str], dictionary: List[str], verbose=False):
    """
    Try dictionary words with numbers inserted in the middle (e.g., "w123ord").
    Only for short common numbers to keep it fast.
    Returns dict: hash -> password
    """
    found = {}
    remaining = set(target_hashes)
    common_numbers = ['0', '1', '12', '123', '1234', '2024', '2023', '2022']
    if verbose:
        print(f"[stage dict+middle] starting targets={len(remaining)}")
    for i, w in enumerate(dictionary, start=1):
        if not remaining:
            break
        if len(w) >= 2:  # Need at least 2 chars to insert in middle
            # Insert number after first char
            for num in common_numbers:
                candidate = w[0] + num + w[1:]
                h = sha1_hex(candidate)
                if h in remaining:
                    found[h] = candidate
                    remaining.remove(h)
                    if verbose:
                        print(f"[stage dict+middle] FOUND {h} -> {candidate}")
        if verbose and i % 5000 == 0:
            print(f"[stage dict+middle] processed {i}/{len(dictionary)} words, found so far={len(found)}")
    if verbose:
        print(f"[stage dict+middle] done found={len(found)}")
    return found

# -------------------------
# Orchestration
# -------------------------
def run_pipeline(password_file: str,
                 dictionary_file: str,
                 numeric_max_len: int = 6,
                 max_suffix: int = 999,
                 workers: int = 1,
                 chunk_size_words: int = 500,
                 verbose: bool = False):
    start_time = time()

    if not os.path.exists(password_file):
        raise FileNotFoundError(password_file)
    if not os.path.exists(dictionary_file):
        raise FileNotFoundError(dictionary_file)

    hash_to_uid, uid_to_hash = load_password_hashes(password_file)
    targets_set = set(hash_to_uid.keys())
    total_hashes = len(targets_set)

    if verbose:
        print(f"[main] Loaded {total_hashes} target hashes.")

    cracked: Dict[str, str] = {}   # mapping hash -> recovered password

    # Stage 1: numeric-only
    t0 = time()
    stage1 = numeric_bruteforce_stage(targets_set - set(cracked.keys()), max_len=numeric_max_len, verbose=verbose)
    cracked.update(stage1)
    if verbose:
        print(f"[main] Stage1 finished in {time()-t0:.2f}s, cracked={len(stage1)}")

    # Stage 2: dictionary-only
    dictionary = load_dictionary(dictionary_file)
    t1 = time()
    remaining_after_stage1 = targets_set - set(cracked.keys())
    stage2 = dictionary_stage(remaining_after_stage1, dictionary, verbose=verbose)
    cracked.update(stage2)
    if verbose:
        print(f"[main] Stage2 finished in {time()-t1:.2f}s, cracked={len(stage2)}")

    # Stage 3: dictionary + suffix (parallel if requested)
    remaining = targets_set - set(cracked.keys())
    t2 = time()
    if remaining:
        stage3 = dict_plus_digits_stage(remaining, dictionary, max_suffix=max_suffix,
                                        workers=workers, chunk_size_words=chunk_size_words, verbose=verbose)
        cracked.update(stage3)
        if verbose:
            print(f"[main] Stage3 finished in {time()-t2:.2f}s, cracked={len(stage3)}")
    else:
        if verbose:
            print("[main] no remaining hashes for stage3")

    # Stage 4: dictionary + prefix
    remaining = targets_set - set(cracked.keys())
    t3 = time()
    if remaining:
        stage4 = dict_plus_prefix_stage(remaining, dictionary, max_prefix=999, verbose=verbose)
        cracked.update(stage4)
        if verbose:
            print(f"[main] Stage4 finished in {time()-t3:.2f}s, cracked={len(stage4)}")
    else:
        if verbose:
            print("[main] no remaining hashes for stage4")

    # Stage 5: dictionary with capitalization variations
    remaining = targets_set - set(cracked.keys())
    t4 = time()
    if remaining:
        stage5 = dict_capitalization_stage(remaining, dictionary, verbose=verbose)
        cracked.update(stage5)
        if verbose:
            print(f"[main] Stage5 finished in {time()-t4:.2f}s, cracked={len(stage5)}")
    else:
        if verbose:
            print("[main] no remaining hashes for stage5")

    # Stage 6: dictionary + long suffix (4 digits)
    remaining = targets_set - set(cracked.keys())
    t5 = time()
    if remaining:
        stage6 = dict_long_suffix_stage(remaining, dictionary, max_suffix=9999, verbose=verbose)
        cracked.update(stage6)
        if verbose:
            print(f"[main] Stage6 finished in {time()-t5:.2f}s, cracked={len(stage6)}")
    else:
        if verbose:
            print("[main] no remaining hashes for stage6")

    # Stage 7: dictionary + prefix + suffix
    remaining = targets_set - set(cracked.keys())
    t6 = time()
    if remaining:
        stage7 = dict_prefix_suffix_stage(remaining, dictionary, max_prefix=99, max_suffix=99, verbose=verbose)
        cracked.update(stage7)
        if verbose:
            print(f"[main] Stage7 finished in {time()-t6:.2f}s, cracked={len(stage7)}")
    else:
        if verbose:
            print("[main] no remaining hashes for stage7")

    # Stage 8: leet speak
    remaining = targets_set - set(cracked.keys())
    t7 = time()
    if remaining:
        stage8 = leet_speak_stage(remaining, dictionary, verbose=verbose)
        cracked.update(stage8)
        if verbose:
            print(f"[main] Stage8 finished in {time()-t7:.2f}s, cracked={len(stage8)}")
    else:
        if verbose:
            print("[main] no remaining hashes for stage8")

    # Stage 9: Try longer numeric passwords (7-8 digits only)
    remaining = targets_set - set(cracked.keys())
    t8 = time()
    if remaining:
        # Only check lengths 7-8 (stage 1 already did 1-6)
        found_extended = {}
        remaining_extended = set(remaining)
        if verbose:
            print(f"[main] Stage9: trying numeric lengths 7-8, targets={len(remaining_extended)}")
        for L in range(7, 9):  # 7 and 8 only
            if not remaining_extended:
                break
            if verbose:
                print(f"[main] Stage9: trying length {L} (candidates={10**L})")
            for tup in product(digits, repeat=L):
                if not remaining_extended:
                    break
                candidate = ''.join(tup)
                h = sha1_hex(candidate)
                if h in remaining_extended:
                    found_extended[h] = candidate
                    remaining_extended.remove(h)
                    if verbose:
                        print(f"[main] Stage9 FOUND hash={h} pwd={candidate} -- remaining {len(remaining_extended)}")
        cracked.update(found_extended)
        if verbose:
            print(f"[main] Stage9 finished in {time()-t8:.2f}s, cracked={len(found_extended)}")
    else:
        if verbose:
            print("[main] no remaining hashes for stage9")

    # Stage 10: Date formats
    remaining = targets_set - set(cracked.keys())
    t9 = time()
    if remaining:
        stage10 = date_formats_stage(remaining, verbose=verbose)
        cracked.update(stage10)
        if verbose:
            print(f"[main] Stage10 finished in {time()-t9:.2f}s, cracked={len(stage10)}")
    else:
        if verbose:
            print("[main] no remaining hashes for stage10")

    # Stage 11: Dictionary + long prefix (4 digits)
    remaining = targets_set - set(cracked.keys())
    t10 = time()
    if remaining:
        stage11 = dict_long_prefix_stage(remaining, dictionary, max_prefix=9999, verbose=verbose)
        cracked.update(stage11)
        if verbose:
            print(f"[main] Stage11 finished in {time()-t10:.2f}s, cracked={len(stage11)}")
    else:
        if verbose:
            print("[main] no remaining hashes for stage11")

    # Stage 12: Dictionary + special characters
    remaining = targets_set - set(cracked.keys())
    t11 = time()
    if remaining:
        stage12 = dict_special_chars_stage(remaining, dictionary, verbose=verbose)
        cracked.update(stage12)
        if verbose:
            print(f"[main] Stage12 finished in {time()-t11:.2f}s, cracked={len(stage12)}")
    else:
        if verbose:
            print("[main] no remaining hashes for stage12")

    # Stage 13: Dictionary words repeated
    remaining = targets_set - set(cracked.keys())
    t12 = time()
    if remaining:
        stage13 = dict_repeated_stage(remaining, dictionary, verbose=verbose)
        cracked.update(stage13)
        if verbose:
            print(f"[main] Stage13 finished in {time()-t12:.2f}s, cracked={len(stage13)}")
    else:
        if verbose:
            print("[main] no remaining hashes for stage13")

    # Stage 14: Dictionary + year suffix
    remaining = targets_set - set(cracked.keys())
    t13 = time()
    if remaining:
        stage14 = dict_year_suffix_stage(remaining, dictionary, verbose=verbose)
        cracked.update(stage14)
        if verbose:
            print(f"[main] Stage14 finished in {time()-t13:.2f}s, cracked={len(stage14)}")
    else:
        if verbose:
            print("[main] no remaining hashes for stage14")

    # Stage 15: Dictionary + number in middle
    remaining = targets_set - set(cracked.keys())
    t14 = time()
    if remaining:
        stage15 = dict_number_in_middle_stage(remaining, dictionary, verbose=verbose)
        cracked.update(stage15)
        if verbose:
            print(f"[main] Stage15 finished in {time()-t14:.2f}s, cracked={len(stage15)}")
    else:
        if verbose:
            print("[main] no remaining hashes for stage15")

    # Stage 16: Capitalization + long suffix (4 digits) - slow, run last
    remaining = targets_set - set(cracked.keys())
    t15 = time()
    if remaining:
        found_cap_long = {}
        remaining_cap = set(remaining)
        if verbose:
            print(f"[main] Stage16: capitalization + long suffix, targets={len(remaining_cap)}")
        for i, w in enumerate(dictionary, start=1):
            if not remaining_cap:
                break
            w_cap = w.capitalize()
            w_upper = w.upper()
            # Try capitalized + 4-digit suffix
            if w_cap != w:
                for n in range(1000, 10000):
                    if not remaining_cap:
                        break
                    candidate = w_cap + str(n)
                    h = sha1_hex(candidate)
                    if h in remaining_cap:
                        found_cap_long[h] = candidate
                        remaining_cap.remove(h)
                        if verbose:
                            print(f"[main] Stage16 FOUND {h} -> {candidate} (capitalized+longsuffix)")
            # Try uppercase + 4-digit suffix
            if w_upper != w_cap:
                for n in range(1000, 10000):
                    if not remaining_cap:
                        break
                    candidate = w_upper + str(n)
                    h = sha1_hex(candidate)
                    if h in remaining_cap:
                        found_cap_long[h] = candidate
                        remaining_cap.remove(h)
                        if verbose:
                            print(f"[main] Stage16 FOUND {h} -> {candidate} (uppercase+longsuffix)")
            if verbose and i % 1000 == 0:
                print(f"[main] Stage16 processed {i}/{len(dictionary)} words, found so far={len(found_cap_long)}")
        cracked.update(found_cap_long)
        if verbose:
            print(f"[main] Stage16 finished in {time()-t15:.2f}s, cracked={len(found_cap_long)}")
    else:
        if verbose:
            print("[main] no remaining hashes for stage16")

    total_cracked = len(cracked)
    elapsed = time() - start_time

    # Write cracked results
    out_lines = []
    for h, pwd in cracked.items():
        uid = hash_to_uid.get(h, "UNKNOWN")
        out_lines.append(f"{uid}\t{h}\t{pwd}\n")
    with open("cracked_results.txt", "w", encoding="utf-8") as out_f:
        out_f.writelines(out_lines)

    # Stats
    stats = {
        "total_hashes": total_hashes,
        "cracked": total_cracked,
        "percent": (total_cracked / total_hashes * 100.0) if total_hashes > 0 else 0.0,
        "elapsed_seconds": elapsed,
        "stages": {
            "numeric_max_len": numeric_max_len,
            "max_suffix": max_suffix,
            "workers": workers,
            "dict_words": len(dictionary)
        }
    }
    with open("stats.json", "w", encoding="utf-8") as s:
        json.dump(stats, s, indent=2)

    # Print summary
    print("=== SUMMARY ===")
    print(f"Total hashes: {total_hashes}")
    print(f"Total cracked: {total_cracked} ({stats['percent']:.2f}%)")
    print(f"Elapsed time: {elapsed:.2f} s")
    print("Wrote cracked_results.txt and stats.json")
    return stats

# -------------------------
# Command-line interface
# -------------------------
def parse_args():
    p = argparse.ArgumentParser(description="Classroom password cracking pipeline (SHA-1).")
    p.add_argument("--passwords", "-p", default="passwords.txt", help="path to passwords.txt")
    p.add_argument("--dictionary", "-d", default="dictionary.txt", help="path to dictionary.txt")
    p.add_argument("--numeric-max-len", type=int, default=6, help="max length for numeric brute-force stage (default 6)")
    p.add_argument("--max-suffix", type=int, default=999, help="max numeric suffix to append to dictionary words (default 999)")
    p.add_argument("--workers", type=int, default=1, help="number of parallel workers for dict+suffix stage (default 1)")
    p.add_argument("--chunk-size", type=int, default=500, help="dictionary chunk size per worker (default 500)")
    p.add_argument("--verbose", action="store_true", help="verbose progress output")
    return p.parse_args()

def main():
    args = parse_args()
    if args.workers > cpu_count():
        print(f"[warn] requested workers {args.workers} > cpu_count {cpu_count()}, capping to cpu_count")
        args.workers = cpu_count()
    try:
        run_pipeline(password_file=args.passwords,
                     dictionary_file=args.dictionary,
                     numeric_max_len=args.numeric_max_len,
                     max_suffix=args.max_suffix,
                     workers=args.workers,
                     chunk_size_words=args.chunk_size,
                     verbose=args.verbose)
    except Exception as e:
        print(f"[error] {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
