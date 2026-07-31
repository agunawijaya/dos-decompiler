/* RecoverFunctions.java -- find the functions Ghidra's auto-analysis missed.
 *
 * Why this is necessary
 * ---------------------
 * Ghidra discovers functions by following control flow from the entry point.
 * That works well on modern binaries and badly on 1980s games, because a game
 * loop dispatches through function-pointer tables held in data structures
 * (Sopwith stores ob_drawf and ob_movef inside every object). Code reached
 * only through such a pointer is never walked, so it is never turned into a
 * function, so the decompiler never sees it. Measured on Sopwith, plain
 * auto-analysis recovered fewer than half of the real function entry points.
 *
 * What it does
 * ------------
 * Scans executable memory for the stack-frame prologue that every C compiler
 * of the era emits, and defines a function wherever one is found that is not
 * already inside a known function body:
 *
 *     55        push bp
 *     8B EC     mov  bp,sp        (Microsoft C, Open Watcom, Lattice, Turbo C)
 *     C8 xx xx 00   enter n,0     (186+ compilers; rarer, but used)
 *
 * Leaf functions that never touch bp are deliberately NOT guessed at from
 * bytes -- that produces false positives in data. They are instead recovered
 * from call targets, which is evidence rather than a guess.
 *
 * The prologue scan is a heuristic and is reported as such: the script prints
 * how many functions it added so the number can be checked against a linker
 * map when one exists.
 *
 * @category DOS.Decompile
 */

import java.util.ArrayList;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;

public class RecoverFunctions extends GhidraScript {

    @Override
    public void run() throws Exception {
        int fromCalls = recoverFromCallTargets();
        int fromPointers = recoverFromCodePointers();
        List<Address> prologues = findPrologues();
        int split = splitOverlongFunctions(prologues);
        int fromPrologues = recoverFromPrologues();

        int total = currentProgram.getFunctionManager().getFunctionCount();
        println("RecoverFunctions: " + prologues.size() + " prologues seen, +"
                + fromCalls + " from call targets, +" + fromPointers + " from code pointers, "
                + split + " over-long functions split, +"
                + fromPrologues + " new from prologues, " + total + " functions total");
    }

    /* Any address that something CALLs is a function entry point. This is
     * evidence, not inference, so it runs first and its results are trusted. */
    private int recoverFromCallTargets() throws Exception {
        List<Address> targets = new ArrayList<>();
        InstructionIterator it = currentProgram.getListing().getInstructions(true);
        while (it.hasNext() && !monitor.isCancelled()) {
            Instruction ins = it.next();
            for (Reference ref : ins.getReferencesFrom()) {
                RefType t = ref.getReferenceType();
                if (t.isCall() && ref.getToAddress().isMemoryAddress()) {
                    targets.add(ref.getToAddress());
                }
            }
        }

        int added = 0;
        for (Address a : targets) {
            if (monitor.isCancelled()) {
                break;
            }
            if (getFunctionAt(a) != null) {
                continue;
            }
            if (createFunctionAt(a)) {
                added++;
            }
        }
        return added;
    }

    /* A prologue sitting inside an existing function body, but not at its
     * entry, means Ghidra ran two functions together: it never saw a call to
     * the second one, so the first appeared to fall straight through into it.
     * Splitting them is the single highest-value correction on this class of
     * binary -- on Sopwith it is the difference between one unreadable
     * 900-instruction blob and half a dozen recognisable movement routines. */
    private int splitOverlongFunctions(List<Address> prologues) throws Exception {
        int split = 0;
        for (Address a : prologues) {
            if (monitor.isCancelled()) {
                break;
            }
            Function containing = getFunctionContaining(a);
            if (containing == null || containing.getEntryPoint().equals(a)) {
                continue;
            }
            Address ownerEntry = containing.getEntryPoint();
            try {
                currentProgram.getFunctionManager().removeFunction(ownerEntry);
                boolean a1 = createFunctionAt(ownerEntry);
                boolean a2 = createFunctionAt(a);
                if (a2) {
                    split++;
                } else if (!a1) {
                    // Recreate whatever we can rather than leaving a hole.
                    createFunctionAt(ownerEntry);
                }
            } catch (Exception e) {
                println("  split failed at " + a + ": " + e.getMessage());
            }
        }
        return split;
    }

    /* The technique that actually matters on 1980s game binaries.
     *
     * A game loop dispatches through function pointers held in structures
     * (ob_movef, ob_drawf) and installs interrupt handlers by address. In a
     * small-model real-mode program those pointers are plain 16-bit near
     * offsets, so the code that stores them does it with an immediate:
     *
     *     mov  word ptr [bx+0x3a], 0x1587      ; ob_movef = moveplyr
     *
     * Ghidra's flow analysis never follows an integer, so every routine
     * reachable only this way stays undisassembled. Measured on Sopwith, 48
     * real functions -- movement handlers, drawing handlers, the keyboard and
     * timer interrupt service routines -- were invisible for exactly this
     * reason.
     *
     * So: treat any immediate that lands inside the code segment as a
     * candidate entry point. False positives are filtered by requiring the
     * bytes to disassemble cleanly and not already belong to a function.
     */
    private int recoverFromCodePointers() throws Exception {
        // Ghidra's MZ loader marks every segment executable, data included.
        // Trusting that flag creates functions inside sprite tables. Restrict
        // to blocks that demonstrably hold code: the one containing the entry
        // point, plus any block that already contains defined functions.
        List<MemoryBlock> codeBlocks = new ArrayList<>();
        Address entry = currentProgram.getSymbolTable().getExternalEntryPointIterator().hasNext()
                ? currentProgram.getSymbolTable().getExternalEntryPointIterator().next()
                : currentProgram.getImageBase();
        for (MemoryBlock b : currentProgram.getMemory().getBlocks()) {
            if (!b.isExecute() || !b.isInitialized()) {
                continue;
            }
            boolean holdsEntry = b.contains(entry);
            boolean holdsCode = false;
            for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
                if (b.contains(f.getEntryPoint())) {
                    holdsCode = true;
                    break;
                }
            }
            if (holdsEntry || holdsCode) {
                codeBlocks.add(b);
            }
        }
        if (codeBlocks.isEmpty()) {
            return 0;
        }

        List<Address> candidates = new ArrayList<>();
        InstructionIterator it = currentProgram.getListing().getInstructions(true);
        while (it.hasNext() && !monitor.isCancelled()) {
            Instruction ins = it.next();
            for (int op = 0; op < ins.getNumOperands(); op++) {
                ghidra.program.model.scalar.Scalar s = ins.getScalar(op);
                if (s == null) {
                    continue;
                }
                long v = s.getUnsignedValue();
                // 0 and tiny values are counters, not addresses.
                if (v < 0x10 || v > 0xFFFF) {
                    continue;
                }
                for (MemoryBlock b : codeBlocks) {
                    if (v < b.getSize()) {
                        candidates.add(b.getStart().add(v));
                    }
                }
            }
        }

        int added = 0;
        for (Address a : candidates) {
            if (monitor.isCancelled()) {
                break;
            }
            if (getFunctionAt(a) != null || getFunctionContaining(a) != null) {
                continue;
            }
            if (createFunctionAt(a)) {
                added++;
            }
        }
        return added;
    }

    private List<Address> findPrologues() throws Exception {
        List<Address> found = new ArrayList<>();
        for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
            if (!block.isExecute() || !block.isInitialized()) {
                continue;
            }
            byte[] bytes = new byte[(int) Math.min(block.getSize(), Integer.MAX_VALUE)];
            block.getBytes(block.getStart(), bytes);
            for (int i = 0; i + 3 < bytes.length; i++) {
                boolean hit =
                        (bytes[i] == 0x55 && bytes[i + 1] == (byte) 0x8B
                                && bytes[i + 2] == (byte) 0xEC)
                        || (bytes[i] == (byte) 0xC8 && bytes[i + 3] == 0x00);
                if (hit) {
                    found.add(block.getStart().add(i));
                }
            }
        }
        return found;
    }

    private int recoverFromPrologues() throws Exception {
        int added = 0;
        for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
            if (!block.isExecute() || !block.isInitialized()) {
                continue;
            }
            monitor.setMessage("scanning " + block.getName());

            Address start = block.getStart();
            Address end = block.getEnd();
            long length = block.getSize();
            byte[] bytes = new byte[(int) Math.min(length, Integer.MAX_VALUE)];
            block.getBytes(start, bytes);

            for (int i = 0; i + 3 < bytes.length; i++) {
                if (monitor.isCancelled()) {
                    break;
                }
                boolean hit =
                        (bytes[i] == 0x55 && bytes[i + 1] == (byte) 0x8B
                                && bytes[i + 2] == (byte) 0xEC)
                        || (bytes[i] == (byte) 0xC8 && bytes[i + 3] == 0x00);
                if (!hit) {
                    continue;
                }

                Address a = start.add(i);
                if (a.compareTo(end) > 0) {
                    break;
                }
                // Already accounted for? Then this is the real prologue of a
                // function we know about, which is the common case.
                Function containing = getFunctionContaining(a);
                if (containing != null) {
                    continue;
                }
                if (createFunctionAt(a)) {
                    added++;
                }
            }
        }
        return added;
    }

    /** Disassemble if needed, then define a function. Returns true on success. */
    private boolean createFunctionAt(Address a) {
        try {
            if (getInstructionAt(a) == null) {
                if (!disassemble(a)) {
                    return false;
                }
            }
            Function f = createFunction(a, null);
            return f != null;
        } catch (Exception e) {
            // A prologue-shaped byte sequence inside data will fail to
            // disassemble cleanly. That is the expected way for a false
            // positive to be rejected, so it is not an error.
            return false;
        }
    }
}
