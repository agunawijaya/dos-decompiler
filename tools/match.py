#!/usr/bin/env python3
"""
match.py -- Identify which binary function corresponds to which source function.

This is the core of the methodology. Stripped 1980s binaries carry no symbol
table, so every function arrives as FUN_1000_1a2b. Recovering identity is what
turns a wall of pseudocode into a readable program.

Two modes, one engine:

  VALIDATION  (source is known)  Match against the real source to measure how
              accurate the pipeline is. This is how the methodology earns
              trust before being pointed at a game with no source.

  RECOVERY    (source is lost)   Match against any reference corpus you have:
              a later port, a sibling game by the same author, or a
              hand-written model of what you expect to find. Whatever matches
              gives you real names for free.

The signal used, in order of discriminating power:

  1. Rare constants. A function mentioning 0xB800 and 0x2000 is touching CGA
     memory. Weighted by inverse document frequency, so a constant appearing
     in one function counts far more than one appearing in fifty.
  2. Call-graph neighbourhood. Once a few functions are pinned down, their
     callers and callees constrain each other. This is iterated to a fixed
     point -- the step that lifts accuracy from "some" to "most".
  3. Size. Instruction count against source line count: weak on its own, but
     useful for breaking ties.

Usage:
    python match.py source-inventory.json ghidra-functions.json
    python match.py src.json bin.json --exclude-file swnetio.c --report out.md
"""

import argparse
import json
import math
import sys
from collections import Counter, defaultdict
from pathlib import Path

# Constants so common they identify nothing. Segment registers' worth of noise:
# stack frame offsets, small loop bounds, and the ubiquitous CGA/DOS values that
# appear in every second function.
NOISE_CONSTANTS = {0x10, 0x18, 0x20, 0x28, 0x30, 0x38, 0x40, 0xFF, 0xFFFF}


def normalize_string(s):
    """Compare string literals on content, not on incidental punctuation.

    A C source literal and the bytes a disassembler recovers differ in escape
    handling, trailing whitespace and terminator conventions. Folding case and
    dropping non-alphanumerics makes the comparison robust without making it
    so loose that unrelated strings collide.
    """
    return "".join(ch for ch in s.lower() if ch.isalnum())


def idf(sets):
    """Inverse document frequency for every value across a list of sets."""
    df = defaultdict(int)
    for s in sets:
        for v in s:
            df[v] += 1
    n = max(1, len(sets))
    return {v: math.log(1.0 + n / c) for v, c in df.items()}


def weighted_jaccard(a, b, weights):
    if not a or not b:
        return 0.0
    inter = a & b
    union = a | b
    wi = sum(weights.get(v, 1.0) for v in inter)
    wu = sum(weights.get(v, 1.0) for v in union)
    return wi / wu if wu else 0.0


class Matcher:
    def __init__(self, src, binr, exclude_files=(), exclude_entries=()):
        self.exclude_files = set(f.lower() for f in exclude_files)
        # Binary functions known not to be program code -- C runtime library
        # routines identified by libsig.py. Leaving them in lets a source
        # function be "matched" to a library routine it merely resembles.
        self.exclude_entries = set(exclude_entries)

        self.src = [f for f in src["functions"]
                    if f.get("file", "").lower() not in self.exclude_files]
        self.bin = [f for f in binr["functions"]
                    if not f.get("thunk")
                    and f["entry"] not in self.exclude_entries]

        self.src_by_name = {f["name"]: f for f in self.src}
        self.bin_by_entry = {f["entry"]: f for f in self.bin}

        # Constant sets, noise removed.
        self.src_consts = {
            f["name"]: set(f.get("constants", [])) - NOISE_CONSTANTS
            for f in self.src}
        self.bin_consts = {
            f["entry"]: set(f.get("scalars", [])) - NOISE_CONSTANTS
            for f in self.bin}

        self.const_w = idf(list(self.src_consts.values())
                           + list(self.bin_consts.values()))

        # String literals pass through the compiler unchanged, so they are the
        # closest thing to a shared identifier the two sides have.
        self.src_strings = {f["name"]: {normalize_string(s)
                                        for s in f.get("strings", [])}
                            for f in self.src}
        self.bin_strings = {f["entry"]: {normalize_string(s)
                                         for s in f.get("strings", [])}
                            for f in self.bin}
        self.string_w = idf(list(self.src_strings.values())
                            + list(self.bin_strings.values()))

        # Call graphs, restricted to edges whose target we actually know.
        self.src_calls = {
            f["name"]: {c for c in f.get("calls", []) if c in self.src_by_name}
            for f in self.src}
        self.bin_calls = {
            f["entry"]: {c for c in f.get("calls", []) if c in self.bin_by_entry}
            for f in self.bin}

        self.src_callers = defaultdict(set)
        for name, callees in self.src_calls.items():
            for c in callees:
                self.src_callers[c].add(name)
        self.bin_callers = defaultdict(set)
        for entry, callees in self.bin_calls.items():
            for c in callees:
                self.bin_callers[c].add(entry)

        # Weight of the control-flow shape term, swept on Sopwith. 0.9 gives
        # the best F1, 1.2 the better precision (0.875 against 0.869 with an
        # inferred module order, 0.897 against 0.867 with a known one) for
        # 2.5 points of recall. Precision is chosen deliberately: a wrong name
        # propagates into every later reading of the code, a missing one does
        # not. Above 1.5 the term starts to dominate and both fall away.
        self.shape_weight = 1.2

        self.mapping = {}       # source name -> binary entry
        self.reverse = {}       # binary entry -> source name
        self.scores = {}        # source name -> score at time of assignment
        self.rounds = []

    # -- size ------------------------------------------------------------
    def size_similarity(self, s, b):
        """Source lines vs instruction count.

        Rough rule for 1980s C at these optimization levels: one source line
        becomes roughly 2-4 instructions. Score how close the ratio is to that
        band rather than demanding an exact figure.
        """
        lines = s.get("body_lines") or 0
        insns = b.get("instruction_count") or 0
        if lines <= 0 or insns <= 0:
            return 0.0
        ratio = insns / lines
        if 1.0 <= ratio <= 6.0:
            return 1.0 - abs(math.log(ratio / 2.5)) / math.log(6.0)
        return 0.0

    # -- control-flow shape ----------------------------------------------
    @staticmethod
    def _ratio(a, b):
        """1.0 when two counts agree, falling off as they diverge."""
        if a <= 0 and b <= 0:
            return None                     # no evidence either way
        if a <= 0 or b <= 0:
            return 0.0
        return min(a, b) / max(a, b)

    def shape_similarity(self, s, b):
        """Compare decision structure rather than content.

        A compiler is free to fold constants, pool strings and reorder data,
        but it cannot discard an `if` or a loop -- each has to become a branch
        or a back edge. So cyclomatic complexity and loop count are among the
        few features that mean the same thing on both sides.

        Counted textually in the source and from the basic-block graph in the
        binary, so the agreement is approximate. Treated as one term among
        several, never as a decision on its own.
        """
        shape = s.get("shape") or {}
        parts = [p for p in (
            self._ratio(shape.get("cyclomatic", 0), b.get("cyclomatic", 0)),
            self._ratio(shape.get("loops", 0), b.get("loops", 0)),
            self._ratio(shape.get("returns", 0), b.get("returns", 0)),
        ) if p is not None]
        return sum(parts) / len(parts) if parts else 0.0

    # -- neighbourhood ---------------------------------------------------
    def neighbour_similarity(self, sname, bentry):
        """How much of this function's already-identified neighbourhood agrees."""
        def agree(src_side, bin_side):
            mapped = {self.mapping[n] for n in src_side if n in self.mapping}
            if not mapped and not bin_side:
                return None                      # no evidence either way
            if not mapped:
                return 0.0
            hit = len(mapped & bin_side)
            return hit / max(1, len(mapped))

        parts = [p for p in (
            agree(self.src_calls.get(sname, set()), self.bin_calls.get(bentry, set())),
            agree(self.src_callers.get(sname, set()), self.bin_callers.get(bentry, set())),
        ) if p is not None]
        return sum(parts) / len(parts) if parts else 0.0

    # -- combined --------------------------------------------------------
    def pair_score(self, s, b, neighbour_weight):
        cs = weighted_jaccard(self.src_consts[s["name"]],
                              self.bin_consts[b["entry"]], self.const_w)
        nb = self.neighbour_similarity(s["name"], b["entry"])
        sz = self.size_similarity(s, b)

        ss = self.src_strings[s["name"]]
        bs = self.bin_strings[b["entry"]]
        st = weighted_jaccard(ss, bs, self.string_w)
        # Strings are near-proof when both sides have them and they agree, and
        # near-disproof when both sides have them and they do not. When only
        # one side has strings the evidence is absent, not negative -- the
        # compiler may have pooled the literal into a caller.
        if ss and bs:
            w_string = 2.5
        else:
            w_string, st = 0.0, 0.0

        # Degree agreement is a cheap structural sanity check: a source
        # function calling 7 things should not map to a leaf.
        sd, bd = len(self.src_calls[s["name"]]), len(self.bin_calls[b["entry"]])
        deg = 1.0 - abs(sd - bd) / max(1, max(sd, bd)) if (sd or bd) else 0.5

        sh = self.shape_similarity(s, b)

        w_const = 1.0
        w_size = 0.35
        w_deg = 0.35
        w_shape = self.shape_weight
        total_w = (w_const + neighbour_weight + w_size + w_deg + w_string
                   + w_shape)
        return (w_const * cs + neighbour_weight * nb + w_string * st
                + w_size * sz + w_deg * deg + w_shape * sh) / total_w

    def run(self, rounds=6, threshold=0.42, seed=None):
        """Greedy assignment, re-scored each round as the mapping grows."""
        if seed:
            for sname, bentry in seed.items():
                if sname in self.src_by_name and bentry in self.bin_by_entry:
                    self.mapping[sname] = bentry
                    self.reverse[bentry] = sname
                    self.scores[sname] = 1.0

        for rnd in range(rounds):
            # Neighbourhood evidence is worthless in round 0 (nothing is
            # mapped yet) and dominant later, so ramp its weight.
            nw = 0.0 if rnd == 0 and not seed else min(2.0, 0.6 * rnd + 0.6)

            # Early rounds decide with the least evidence, and every wrong
            # decision then propagates through the neighbourhood term. So
            # demand more certainty early and relax as the map fills in.
            round_threshold = threshold + max(0.0, 0.18 * (2 - rnd))

            candidates = []
            for s in self.src:
                if s["name"] in self.mapping:
                    continue
                for b in self.bin:
                    if b["entry"] in self.reverse:
                        continue
                    sc = self.pair_score(s, b, nw)
                    if sc >= round_threshold:
                        candidates.append((sc, s["name"], b["entry"]))

            candidates.sort(reverse=True)
            assigned = 0
            for sc, sname, bentry in candidates:
                if sname in self.mapping or bentry in self.reverse:
                    continue
                self.mapping[sname] = bentry
                self.reverse[bentry] = sname
                self.scores[sname] = sc
                assigned += 1

            self.rounds.append({"round": rnd, "neighbour_weight": round(nw, 2),
                                "threshold": round(round_threshold, 3),
                                "assigned": assigned,
                                "total_mapped": len(self.mapping)})
            if assigned == 0:
                break
        return self.mapping

    # -- output ----------------------------------------------------------
    def result(self):
        mapped = []
        for sname, bentry in sorted(self.mapping.items(),
                                    key=lambda kv: -self.scores[kv[0]]):
            s = self.src_by_name[sname]
            b = self.bin_by_entry[bentry]
            mapped.append({
                "source": sname,
                "file": s.get("file"),
                "kind": s.get("kind"),
                "binary": bentry,
                "binary_name": b.get("name"),
                "score": round(self.scores[sname], 3),
                "source_lines": s.get("body_lines"),
                "binary_instructions": b.get("instruction_count"),
            })
        return {
            "rounds": self.rounds,
            "source_functions": len(self.src),
            "binary_functions": len(self.bin),
            "mapped": len(self.mapping),
            "unmapped_source": sorted(f["name"] for f in self.src
                                      if f["name"] not in self.mapping),
            "unmapped_binary": sorted(f["entry"] for f in self.bin
                                      if f["entry"] not in self.reverse),
            "mapping": mapped,
        }


def linear(addr):
    seg, off = addr.split(":")
    return (int(seg, 16) << 4) + int(off, 16)


class Aligner:
    """Order-aware matching.

    A linker lays modules down in order and a compiler emits a module's
    functions in the order they were written. So the binary's functions, read
    by increasing address, are very nearly the source's functions read in
    file-then-line order. Two consequences:

      * a correct mapping is almost monotonic, and
      * an isolated match that jumps backwards is probably wrong.

    Pairwise scoring cannot see any of that -- it judges each candidate in
    isolation. Sequence alignment can, so this stage replaces greedy pairing
    with a global alignment (Needleman-Wunsch) over the two ordered lists.

    The catch is that the module order is a property of the lost link script.
    It is recovered rather than assumed: the high-confidence pairs found by
    the greedy matcher are used to locate each source file in the binary, and
    the files are then sorted by where their anchors landed.
    """

    GAP = -0.25   # cost of leaving a function unmatched

    def __init__(self, matcher, anchors, segments=None, use_segments=False):
        self.m = matcher
        self.anchors = anchors
        self.segments = segments
        self.use_segments = use_segments

    def infer_module_order(self):
        # Segment-derived ordering was implemented and measured, and it is
        # worse. See _order_from_segments. Anchor positions win, so they are
        # the default and segments stay opt-in for experimentation.
        if self.segments and self.use_segments:
            order = self._order_from_segments()
            if order:
                return order
        return self._order_from_anchor_positions()

    def _order_from_segments(self):
        """Use recovered module segments to clean anchors, then order by position.

        MEASURED RESULT: worse than not doing it. Two variants were tried
        against Sopwith's answer key, both against a 0.696 baseline from plain
        anchor positions:

            order files by first segment voting for them   precision 0.405
            drop anchors disagreeing with segment majority precision 0.225

        The segmentation itself is sound -- modcluster.py detects module
        boundaries at precision 0.52 against a 0.19 chance baseline. The
        problem is downstream: with ~25 segments over ~290 functions there are
        only one to three anchors per segment, so a "majority" is noise, and
        discarding minority anchors throws away the aggregate position
        evidence that the median ordering depends on.

        The bottleneck is anchor accuracy, not grouping. Recorded so the idea
        is not retried from scratch.
        """
        entry_to_source = {v: k for k, v in self.anchors.items()}
        keep = {}
        for seg in self.segments:
            votes = Counter()
            members = []
            for entry in seg.get("entries", []):
                sname = entry_to_source.get(entry)
                f = self.m.src_by_name.get(sname) if sname else None
                if f:
                    votes[f.get("file")] += 1
                    members.append((sname, entry, f.get("file")))
            if not votes:
                continue
            winner, top = votes.most_common(1)[0]
            # With only one vote there is no majority to speak of, so keep it
            # rather than throw away the only evidence the segment has.
            for sname, entry, fname in members:
                if top <= 1 or fname == winner:
                    keep[sname] = entry

        if len(keep) < 3:
            return None
        return self._order_from_anchor_positions(anchors=keep)

    def _order_from_anchor_positions(self, anchors=None):
        """Order source files by where their anchored functions sit."""
        anchors = self.anchors if anchors is None else anchors
        positions = defaultdict(list)
        for sname, bentry in anchors.items():
            f = self.m.src_by_name.get(sname)
            if f:
                positions[f.get("file")].append(linear(bentry))
        order = {}
        for fname, addrs in positions.items():
            addrs.sort()
            order[fname] = addrs[len(addrs) // 2]     # median resists outliers
        # Files with no anchor cannot be placed; they go last, in name order,
        # and will mostly align to gaps rather than corrupt the good part.
        unplaced = sorted({f.get("file") for f in self.m.src} - set(order))
        ranked = sorted(order, key=lambda k: order[k])
        return ranked + unplaced

    def ordered_source(self):
        file_rank = {f: i for i, f in enumerate(self.infer_module_order())}
        return sorted(
            self.m.src,
            key=lambda f: (file_rank.get(f.get("file"), 10 ** 6),
                           f.get("line") or 0))

    def ordered_binary(self):
        return sorted(self.m.bin, key=lambda f: linear(f["entry"]))

    def align(self, floor=0.20):
        S = self.ordered_source()
        B = self.ordered_binary()
        n, mlen = len(S), len(B)

        # Score matrix. Neighbour weight is zero here: ordering already carries
        # the structural information that term was standing in for.
        sim = [[0.0] * mlen for _ in range(n)]
        raw = [[0.0] * mlen for _ in range(n)]      # unpinned, for reporting
        for i, s in enumerate(S):
            for j, b in enumerate(B):
                v = self.m.pair_score(s, b, 0.0)
                raw[i][j] = v
                # Anchors are pinned high so the alignment stays attached to
                # what we already believe. This value drives the dynamic
                # program ONLY -- reporting it as the confidence would turn
                # "the greedy pass picked this" into "this is certain", which
                # is how a wrong name acquires an authoritative-looking score.
                if self.anchors.get(s["name"]) == b["entry"]:
                    v = 1.0
                sim[i][j] = v if v >= floor else -0.05

        # Needleman-Wunsch.
        dp = [[0.0] * (mlen + 1) for _ in range(n + 1)]
        for i in range(1, n + 1):
            dp[i][0] = dp[i - 1][0] + self.GAP
        for j in range(1, mlen + 1):
            dp[0][j] = dp[0][j - 1] + self.GAP
        for i in range(1, n + 1):
            row, prev = dp[i], dp[i - 1]
            simrow = sim[i - 1]
            for j in range(1, mlen + 1):
                row[j] = max(prev[j - 1] + simrow[j - 1],
                             prev[j] + self.GAP,
                             row[j - 1] + self.GAP)

        # Traceback.
        pairs, i, j = {}, n, mlen
        while i > 0 and j > 0:
            if dp[i][j] == dp[i - 1][j - 1] + sim[i - 1][j - 1]:
                if sim[i - 1][j - 1] > 0:
                    pairs[S[i - 1]["name"]] = (B[j - 1]["entry"],
                                               raw[i - 1][j - 1])
                i -= 1
                j -= 1
            elif dp[i][j] == dp[i - 1][j] + self.GAP:
                i -= 1
            else:
                j -= 1
        return pairs

    def align_iterative(self, floor=0.25, passes=4):
        """Alternate between recovering the module order and aligning to it.

        MEASURED RESULT: this does not help. On Sopwith it converges to the
        same mapping as a single pass (precision 0.70) and is worse when
        started without anchors (0.49). The reason is that refeeding an
        alignment's own output reinforces whatever order error it started
        with rather than correcting it.

        Kept because the negative result is worth having in the open: if you
        are tempted to add an expectation-maximisation loop here, it has been
        tried. The bottleneck is the initial module order, and the fix is to
        recover module boundaries from the binary directly -- see
        knowledge/03-what-works.md.
        """
        best = self.align(floor=floor)
        for _ in range(passes - 1):
            self.anchors = {k: v[0] for k, v in best.items()}
            nxt = self.align(floor=floor)
            if {k: v[0] for k, v in nxt.items()} == \
               {k: v[0] for k, v in best.items()}:
                break
            best = nxt
        return best


def evaluate(res, truth):
    """Compare the mapping against a known-correct map, when one exists."""
    correct = wrong = missing = 0
    errors = []
    got = {m["source"]: m["binary"] for m in res["mapping"]}
    for sname, bentry in truth.items():
        if sname not in got:
            missing += 1
        elif got[sname] == bentry:
            correct += 1
        else:
            wrong += 1
            errors.append((sname, bentry, got[sname]))
    total = len(truth)
    return {
        "truth_size": total,
        "correct": correct,
        "wrong": wrong,
        "missing": missing,
        "precision": round(correct / max(1, correct + wrong), 3),
        "recall": round(correct / max(1, total), 3),
        "errors": errors[:40],
    }


def render(res, ev=None):
    out = []
    A = out.append
    A("# Function identification report")
    A("")
    A(f"- source functions considered : {res['source_functions']}")
    A(f"- binary functions considered : {res['binary_functions']}")
    A(f"- mapped                      : {res['mapped']}")
    A(f"- unmapped source             : {len(res['unmapped_source'])}")
    A(f"- unmapped binary             : {len(res['unmapped_binary'])}")
    A("")
    A("## Convergence")
    A("")
    A("| round | neighbour weight | newly assigned | total |")
    A("|------:|-----------------:|---------------:|------:|")
    for r in res["rounds"]:
        A(f"| {r['round']} | {r['neighbour_weight']} | {r['assigned']} | {r['total_mapped']} |")
    A("")
    if ev:
        A("## Accuracy against ground truth")
        A("")
        A(f"- known pairs : {ev['truth_size']}")
        A(f"- correct     : {ev['correct']}")
        A(f"- wrong       : {ev['wrong']}")
        A(f"- missing     : {ev['missing']}")
        A(f"- precision   : {ev['precision']}")
        A(f"- recall      : {ev['recall']}")
        if ev["errors"]:
            A("")
            A("Mismatches (source -> expected / got):")
            for name, exp, got in ev["errors"]:
                A(f"  - `{name}`  expected `{exp}`  got `{got}`")
        A("")
    A("## Mapping (highest confidence first)")
    A("")
    A("| score | source | file | binary | src lines | bin insns |")
    A("|------:|--------|------|--------|----------:|----------:|")
    for m in res["mapping"]:
        A(f"| {m['score']} | `{m['source']}` | {m['file']} | `{m['binary']}` "
          f"| {m['source_lines']} | {m['binary_instructions']} |")
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("source_json", help="output of srcinv.py --json")
    ap.add_argument("binary_json", help="functions.json from ExportDecompiledC")
    ap.add_argument("--exclude-file", action="append", default=[],
                    help="source file not linked into the binary (repeatable)")
    ap.add_argument("--exclude-library", metavar="FILE",
                    help="libsig.py detections; those binary functions are C "
                         "runtime code and are removed from consideration")
    ap.add_argument("--threshold", type=float, default=0.45,
                    help="greedy anchor threshold (0.45 measured best on Sopwith)")
    ap.add_argument("--rounds", type=int, default=8)
    ap.add_argument("--align", action="store_true",
                    help="add the order-aware alignment pass (recommended)")
    ap.add_argument("--align-floor", type=float, default=0.25,
                    help="minimum similarity for an aligned pair (0.25 measured best)")
    ap.add_argument("--shape-weight", type=float, default=None,
                    help="weight of the control-flow shape term (default 1.2; "
                         "0.9 trades precision for recall)")
    ap.add_argument("--module-order", metavar="FILE",
                    help="JSON list of source files in link order. Supplying the "
                         "true order raised precision from 0.70 to 0.86 on Sopwith, "
                         "so provide it whenever a makefile or link script reveals it.")
    ap.add_argument("--seed", help="JSON file of known source->binary pairs")
    ap.add_argument("--truth", help="JSON file of correct pairs, to score accuracy")
    ap.add_argument("--report", help="write a markdown report here")
    ap.add_argument("--json", help="write the raw mapping here")
    args = ap.parse_args()

    src = json.loads(Path(args.source_json).read_text(encoding="utf-8"))
    binr = json.loads(Path(args.binary_json).read_text(encoding="utf-8"))

    seed = json.loads(Path(args.seed).read_text(encoding="utf-8")) if args.seed else None

    lib_entries = []
    if args.exclude_library:
        hits = json.loads(Path(args.exclude_library).read_text(encoding="utf-8"))
        lib_entries = [h["entry"] for h in hits]

    m = Matcher(src, binr, args.exclude_file, lib_entries)
    if args.shape_weight is not None:
        m.shape_weight = args.shape_weight
    m.run(rounds=args.rounds, threshold=args.threshold, seed=seed)

    if args.align:
        anchors = dict(m.mapping)
        aligner = Aligner(m, anchors)
        if args.module_order:
            order = json.loads(Path(args.module_order).read_text(encoding="utf-8"))
            aligner.infer_module_order = lambda: list(order) + sorted(
                {f.get("file") for f in m.src} - set(order))
        pairs = aligner.align(floor=args.align_floor)
        m.mapping, m.reverse, m.scores = {}, {}, {}
        for sname, (bentry, sc) in pairs.items():
            m.mapping[sname] = bentry
            m.reverse[bentry] = sname
            m.scores[sname] = sc
        m.rounds.append({"round": "align", "neighbour_weight": 0.0,
                         "threshold": args.align_floor,
                         "assigned": len(pairs), "total_mapped": len(pairs)})

    res = m.result()

    ev = None
    if args.truth:
        truth = json.loads(Path(args.truth).read_text(encoding="utf-8"))
        # A linker map lists data symbols alongside code. Scoring against those
        # would understate recall for a tool that only ever claims to identify
        # functions, so keep only names that the source says are functions and
        # that actually landed in the binary's code segments.
        src_names = {f["name"] for f in m.src}
        bin_entries = set(m.bin_by_entry)
        truth = {k: v for k, v in truth.items()
                 if k in src_names and v in bin_entries}
        ev = evaluate(res, truth)
        res["evaluation"] = ev

    text = render(res, ev)
    if args.report:
        Path(args.report).write_text(text, encoding="utf-8")
        print(f"wrote {args.report}")
    else:
        print(text)
    if args.json:
        Path(args.json).write_text(json.dumps(res, indent=2), encoding="utf-8")
        print(f"wrote {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
