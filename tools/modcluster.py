#!/usr/bin/env python3
"""
modcluster.py -- Recover translation-unit boundaries from a stripped binary.

Why this matters more than it sounds
------------------------------------
Measured on Sopwith, knowing which source file each function came from -- and
therefore the order the linker placed the modules in -- is worth more than
every content-similarity heuristic combined: identification precision rises
from 0.70 to 0.80 when the module order is known rather than guessed.

The order is normally lost. This recovers it from the binary alone.

The signal
----------
A C compiler emits one object file per source file, and the linker lays those
objects down contiguously. Functions from the same source file therefore sit
next to each other in the binary AND share file-scope variables, because that
is what file-scope means. So a module boundary is a point in the
address-ordered function list where the set of globals being touched changes
over.

In a 16-bit real-mode binary a global access is `mov ax,[0x1234]`, with the
segment supplied by DS at run time. A disassembler cannot resolve that to an
address, but it does not need to: the raw displacement is a perfectly good
identity for the variable.

What comes out
--------------
A segmentation of the function list into candidate modules. Combined with a
handful of identified functions, each segment can be voted onto a source file,
which yields the link order that `match.py --module-order` wants.

Usage:
    python modcluster.py functions.json --report
    python modcluster.py functions.json --json segments.json --window 5
"""

import argparse
import json
import math
import sys
from collections import Counter, defaultdict
from pathlib import Path


def linear(addr):
    seg, off = addr.split(":")
    return (int(seg, 16) << 4) + int(off, 16)


def idf_weights(sets):
    df = Counter()
    for s in sets:
        for v in s:
            df[v] += 1
    n = max(1, len(sets))
    return {v: math.log(1.0 + n / c) for v, c in df.items()}


def weighted_overlap(a, b, w):
    """Weighted Jaccard. Zero when either side is empty -- absence of evidence
    is treated as absence of cohesion, which is what we want at a boundary."""
    if not a or not b:
        return 0.0
    inter = sum(w.get(v, 1.0) for v in a & b)
    union = sum(w.get(v, 1.0) for v in a | b)
    return inter / union if union else 0.0


class ModuleSegmenter:
    def __init__(self, functions, window=3, min_segment=2, call_weight=0.65):
        self.funcs = sorted(functions, key=lambda f: linear(f["entry"]))
        self.window = window
        self.min_segment = min_segment
        self.call_weight = call_weight
        self.refs = [set(f.get("data_refs", [])) for f in self.funcs]
        self.weights = idf_weights(self.refs)
        self.index_of = {f["entry"]: i for i, f in enumerate(self.funcs)}

    def call_cut(self):
        """Number of call edges spanning each gap.

        Classic minimum-cut reasoning on a linear ordering: a module boundary
        is a place few edges reach across.

        Worth stating plainly, because it contradicts the usual intuition:
        measured on Sopwith only 9% of call edges stay inside their module
        (28 internal against 269 crossing). The modules are organised by role
        -- movement, display, collision -- so they call each other constantly.
        The cut signal still works, because it is the *local* density that
        dips at a seam, not the global one. Empirically it is the strongest
        boundary signal available: precision 0.44 against 0.19 for chance,
        and clearly ahead of data-reference cohesion at 0.32.
        """
        n = len(self.funcs)
        cut = [0] * n
        for i, f in enumerate(self.funcs):
            for c in f.get("calls", []):
                j = self.index_of.get(c)
                if j is None or j == i:
                    continue
                lo, hi = (i, j) if i < j else (j, i)
                for pos in range(lo + 1, hi + 1):
                    cut[pos] += 1
        return cut

    def cohesion(self):
        """Cohesion across each gap between consecutive functions.

        Low cohesion means the code before and after the gap works on
        different data, which is what a module boundary looks like.

        Functions with no usable data references -- leaf helpers, assembly
        routines, anything working purely in registers -- are stepped over
        rather than treated as evidence. An earlier version let them
        contribute empty sets, which drove cohesion to zero around them and
        put every cut next to a ref-less function instead of at a module
        boundary. Measured, that scored *worse than random* (precision 0.20
        against a 0.28 chance baseline).
        """
        n = len(self.funcs)
        informative = [i for i in range(n) if self.refs[i]]

        scores = []
        for i in range(1, n):
            left_idx = [j for j in informative if j < i][-self.window:]
            right_idx = [j for j in informative if j >= i][:self.window]
            left = set().union(*[self.refs[j] for j in left_idx]) if left_idx else set()
            right = set().union(*[self.refs[j] for j in right_idx]) if right_idx else set()
            scores.append(weighted_overlap(left, right, self.weights))
        return scores

    def segment(self, expected=None, threshold=0.10):
        """Cut at the weakest gaps.

        With `expected` set, take the N-1 weakest gaps; that is the right mode
        when a makefile tells you how many modules there are. Otherwise cut
        every gap whose cohesion falls below `threshold`.
        """
        n = len(self.funcs)
        if n <= 1:
            return [list(range(n))]

        cohesion = self.cohesion()            # index i covers the gap before i+1
        cut = self.call_cut()                 # index b covers the gap before b

        # Normalise the cut against its local neighbourhood rather than the
        # global peak. Densely-called regions and sparsely-called ones (the
        # library tail, typically) have wildly different absolute cut counts,
        # and a global scale puts every boundary in the sparse region: on the
        # shipped Sopwith that produced one segment of 257 functions and
        # twenty-five of two. What identifies a seam is a dip relative to its
        # surroundings.
        span = max(4, len(cut) // 20)
        local = []
        for b in range(len(cut)):
            lo, hi = max(0, b - span), min(len(cut), b + span + 1)
            window = cut[lo:hi]
            local.append(sum(window) / max(1, len(window)))

        scores = []
        for i in range(len(cohesion)):
            b = i + 1
            rel = cut[b] / local[b] if local[b] > 0 else 1.0
            scores.append(self.call_weight * min(rel, 2.0) / 2.0
                          + (1.0 - self.call_weight) * cohesion[i])

        candidates = sorted(range(len(scores)), key=lambda i: scores[i])
        if expected:
            wanted = max(0, expected - 1)
        else:
            wanted = sum(1 for s in scores if s < threshold)

        # Keep cuts apart, but only just. Without any spacing rule the
        # lowest-scoring gaps bunch together and leave one enormous segment
        # (92 functions on the shipped Sopwith); too strict a rule discards
        # genuine boundaries, since real modules are often only two or three
        # functions long. Measured: n/(4*expected) holds precision at 0.52 and
        # recall at 0.70 while capping the worst segment at 62, where
        # n/(2*expected) dropped them to 0.32 and 0.41.
        spacing = self.min_segment
        if expected and expected > 1:
            spacing = max(spacing, n // (4 * expected))

        cuts = []
        for i in candidates:
            if len(cuts) >= wanted:
                break
            boundary = i + 1                      # gap i sits before function i+1
            if all(abs(boundary - c) >= spacing for c in cuts) \
               and boundary >= spacing \
               and n - boundary >= spacing:
                cuts.append(boundary)

        cuts.sort()
        segments, start = [], 0
        for c in cuts + [n]:
            segments.append(list(range(start, c)))
            start = c
        return [s for s in segments if s]

    def describe(self, segments):
        out = []
        for idx, seg in enumerate(segments):
            entries = [self.funcs[i]["entry"] for i in seg]
            shared = set().union(*[self.refs[i] for i in seg]) if seg else set()
            out.append({
                "index": idx,
                "first": entries[0],
                "last": entries[-1],
                "functions": len(seg),
                "entries": entries,
                "distinct_globals": len(shared),
            })
        return out


def vote_module_order(segments_desc, anchors, src_by_name):
    """Assign each segment to a source file by majority vote of its anchors.

    Voting over a whole segment is more robust than looking at anchors
    individually: a segment of a dozen functions can absorb several wrong
    anchors and still land on the right file.
    """
    entry_to_source = {v: k for k, v in anchors.items()}
    order, assignments = [], []
    for seg in segments_desc:
        votes = Counter()
        for entry in seg["entries"]:
            sname = entry_to_source.get(entry)
            if sname and sname in src_by_name:
                votes[src_by_name[sname].get("file")] += 1
        winner = votes.most_common(1)[0][0] if votes else None
        assignments.append({
            "segment": seg["index"], "first": seg["first"],
            "functions": seg["functions"], "file": winner,
            "votes": dict(votes),
        })
        if winner and winner not in order:
            order.append(winner)
    return order, assignments


def evaluate_segmentation(segments, funcs, truth_modules):
    """Score boundary detection against the modules a linker map records."""
    true_module = []
    for f in funcs:
        true_module.append(truth_modules.get(f["entry"]))

    true_bounds = set()
    for i in range(1, len(funcs)):
        a, b = true_module[i - 1], true_module[i]
        if a and b and a != b:
            true_bounds.add(i)

    found = set()
    pos = 0
    for seg in segments[:-1]:
        pos += len(seg)
        found.add(pos)

    # A boundary landing within one function of the truth is a hit: an
    # unidentified function sitting on the seam should not count as a miss.
    hits = sum(1 for b in found if any(abs(b - t) <= 1 for t in true_bounds))
    precision = hits / max(1, len(found))
    recall = sum(1 for t in true_bounds
                 if any(abs(b - t) <= 1 for b in found)) / max(1, len(true_bounds))
    return {"true_boundaries": len(true_bounds), "found_boundaries": len(found),
            "hits": hits, "precision": round(precision, 3),
            "recall": round(recall, 3)}


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("functions_json")
    ap.add_argument("--window", type=int, default=3,
                    help="functions each side of a gap to compare (3 measured best)")
    ap.add_argument("--min-segment", type=int, default=2)
    ap.add_argument("--expected", type=int, help="known number of modules")
    ap.add_argument("--threshold", type=float, default=0.10)
    ap.add_argument("--map-json", help="mapparse.py --json output, to score accuracy")
    ap.add_argument("--json", help="write segments here")
    args = ap.parse_args()

    data = json.loads(Path(args.functions_json).read_text(encoding="utf-8"))
    funcs = [f for f in data["functions"] if not f.get("thunk")]

    seg = ModuleSegmenter(funcs, window=args.window, min_segment=args.min_segment)
    segments = seg.segment(expected=args.expected, threshold=args.threshold)
    desc = seg.describe(segments)

    print(f"functions      : {len(funcs)}")
    print(f"segments found : {len(segments)}")
    print(f"sizes          : {[len(s) for s in segments]}")

    if args.map_json:
        m = json.loads(Path(args.map_json).read_text(encoding="utf-8"))
        truth_modules = {s["address"]: s["module"] for s in m["symbols"]
                         if s.get("module")}
        ev = evaluate_segmentation(segments, seg.funcs, truth_modules)
        print(f"\nboundary detection vs linker map:")
        print(f"  true boundaries  : {ev['true_boundaries']}")
        print(f"  found boundaries : {ev['found_boundaries']}")
        print(f"  precision        : {ev['precision']}")
        print(f"  recall           : {ev['recall']}")

    if args.json:
        Path(args.json).write_text(json.dumps(desc, indent=2), encoding="utf-8")
        print(f"\nwrote {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
