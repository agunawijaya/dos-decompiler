/* ExportDecompiledC.java -- headless export of Ghidra's decompiler output.
 *
 * Writes, into the directory given as the first script argument:
 *   decompiled.c    every function Ghidra could decompile, in address order
 *   functions.json  a machine-readable inventory used by the scoring harness
 *   failures.txt    functions the decompiler refused, with the reason
 *
 * Written in Java rather than Python on purpose: a .java GhidraScript is
 * compiled by Ghidra itself at run time and needs no interpreter installed,
 * so the package stays self-contained.
 *
 * @category DOS.Decompile
 */

import java.io.File;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import java.util.Set;
import java.util.TreeSet;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.scalar.Scalar;

public class ExportDecompiledC extends GhidraScript {

    private static final int TIMEOUT_SECONDS = 120;

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        File outDir = new File(args.length > 0 ? args[0] : "decompiled");
        if (!outDir.exists() && !outDir.mkdirs()) {
            printerr("cannot create output directory: " + outDir);
            return;
        }

        DecompInterface ifc = new DecompInterface();
        // Headless has no tool to inherit options from, so use the defaults
        // explicitly rather than grabbing from a tool that does not exist.
        DecompileOptions opts = new DecompileOptions();
        ifc.setOptions(opts);
        ifc.toggleCCode(true);
        ifc.toggleSyntaxTree(true);
        if (!ifc.openProgram(currentProgram)) {
            printerr("decompiler failed to open program: " + ifc.getLastMessage());
            return;
        }

        List<String> failures = new ArrayList<>();
        List<String> records = new ArrayList<>();
        int ok = 0, bad = 0;

        PrintWriter c = new PrintWriter(new File(outDir, "decompiled.c"), StandardCharsets.UTF_8);
        c.println("/* Decompiled by Ghidra " + ghidra.framework.Application.getApplicationVersion());
        c.println(" * program : " + currentProgram.getName());
        c.println(" * language: " + currentProgram.getLanguageID());
        c.println(" * NOTE: machine output. Every line is a hypothesis, not a fact.");
        c.println(" */");
        c.println();

        FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
        while (it.hasNext() && !monitor.isCancelled()) {
            Function f = it.next();
            monitor.setMessage("decompiling " + f.getName());

            DecompileResults res = ifc.decompileFunction(f, TIMEOUT_SECONDS, monitor);
            String addr = f.getEntryPoint().toString();
            long size = f.getBody().getNumAddresses();

            if (res != null && res.decompileCompleted() && res.getDecompiledFunction() != null) {
                c.println("/* ---- " + f.getName() + " @ " + addr
                        + "  (" + size + " bytes) ---- */");
                c.println(res.getDecompiledFunction().getC());
                c.println();
                ok++;
            } else {
                String why = (res == null) ? "null result" : res.getErrorMessage();
                failures.add(addr + "  " + f.getName() + "  : " + why);
                bad++;
            }

            records.add(functionRecord(f, addr, size,
                    res != null && res.decompileCompleted()));
        }
        c.close();
        ifc.dispose();

        PrintWriter j = new PrintWriter(new File(outDir, "functions.json"), StandardCharsets.UTF_8);
        j.println("{");
        j.println("  \"program\": " + quote(currentProgram.getName()) + ",");
        j.println("  \"language\": " + quote(currentProgram.getLanguageID().toString()) + ",");
        j.println("  \"image_base\": " + quote(currentProgram.getImageBase().toString()) + ",");
        j.println("  \"decompiled_ok\": " + ok + ",");
        j.println("  \"decompiled_failed\": " + bad + ",");
        j.println("  \"functions\": [");
        for (int i = 0; i < records.size(); i++) {
            j.println("    " + records.get(i) + (i + 1 < records.size() ? "," : ""));
        }
        j.println("  ]");
        j.println("}");
        j.close();

        if (!failures.isEmpty()) {
            PrintWriter fw = new PrintWriter(new File(outDir, "failures.txt"), StandardCharsets.UTF_8);
            for (String s : failures) {
                fw.println(s);
            }
            fw.close();
        }

        println("ExportDecompiledC: " + ok + " decompiled, " + bad + " failed -> " + outDir);
    }

    private String functionRecord(Function f, String addr, long size, boolean okFlag) {
        StringBuilder sb = new StringBuilder();
        sb.append("{");
        sb.append("\"name\": ").append(quote(f.getName())).append(", ");
        sb.append("\"entry\": ").append(quote(addr)).append(", ");
        sb.append("\"size\": ").append(size).append(", ");
        sb.append("\"thunk\": ").append(f.isThunk()).append(", ");
        sb.append("\"external\": ").append(f.isExternal()).append(", ");
        sb.append("\"calling_convention\": ")
          .append(quote(String.valueOf(f.getCallingConventionName()))).append(", ");
        sb.append("\"return_type\": ")
          .append(quote(f.getReturnType().getDisplayName())).append(", ");
        sb.append("\"param_count\": ").append(f.getParameterCount()).append(", ");
        sb.append("\"params\": [");
        Parameter[] ps = f.getParameters();
        for (int i = 0; i < ps.length; i++) {
            sb.append(quote(ps[i].getDataType().getDisplayName() + " " + ps[i].getName()));
            if (i + 1 < ps.length) {
                sb.append(", ");
            }
        }
        sb.append("], ");
        sb.append("\"decompiled\": ").append(okFlag).append(", ");
        appendFingerprint(sb, f);
        sb.append("}");
        return sb.toString();
    }

    /* The fingerprint is what makes a function identifiable without symbols:
     * who it calls, which unusual constants it mentions, which interrupts and
     * I/O ports it touches. Names change between builds; these rarely do. */
    private void appendFingerprint(StringBuilder sb, Function f) {
        Set<String> callees = new TreeSet<>();
        try {
            for (Function callee : f.getCalledFunctions(monitor)) {
                callees.add(callee.getEntryPoint().toString());
            }
        } catch (Exception e) {
            // getCalledFunctions can throw on damaged flow; an empty callee
            // set is a truthful answer here, not a silent failure.
        }

        // String literals a function touches are the strongest identifier of
        // all: a routine that references "Sopwith" is the title screen, in any
        // build, under any name.
        Set<String> strings = new TreeSet<>();
        Set<String> dataRefs = new TreeSet<>();
        Set<Long> scalars = new TreeSet<>();
        Set<Long> interrupts = new TreeSet<>();
        Set<Long> ports = new TreeSet<>();
        int instructionCount = 0;
        Set<String> mnemonics = new TreeSet<>();

        InstructionIterator ii = currentProgram.getListing()
                .getInstructions(f.getBody(), true);
        while (ii.hasNext()) {
            Instruction ins = ii.next();
            instructionCount++;
            String mn = ins.getMnemonicString().toUpperCase();
            mnemonics.add(mn);

            for (ghidra.program.model.symbol.Reference ref : ins.getReferencesFrom()) {
                if (!ref.getToAddress().isMemoryAddress()) {
                    continue;
                }
                ghidra.program.model.listing.Data d =
                        currentProgram.getListing().getDataAt(ref.getToAddress());
                if (d != null && d.hasStringValue()) {
                    Object v = d.getValue();
                    if (v != null) {
                        String s = v.toString().trim();
                        if (s.length() >= 3) {
                            strings.add(s);
                        }
                    }
                }
            }

            // Which global variables a function touches reveals which
            // translation unit it came from: file-scope data is shared inside
            // a module and rarely across modules.
            //
            // Ghidra creates almost no data references here -- in real mode a
            // direct access is "mov ax,[0x1234]" with the segment living in DS
            // at run time, so static analysis cannot resolve a target address
            // and emits no reference (measured: 2 of 289 functions had any).
            // The displacement itself is still perfectly usable as an
            // identifier, so take it straight from the operand.
            for (int op = 0; op < ins.getNumOperands(); op++) {
                String rep = ins.getDefaultOperandRepresentation(op);
                if (rep == null || rep.indexOf('[') < 0) {
                    continue;               // not a memory operand
                }
                for (Object o : ins.getOpObjects(op)) {
                    if (o instanceof Scalar) {
                        long v = ((Scalar) o).getUnsignedValue();
                        // Small values are stack-frame offsets relative to BP,
                        // not globals; they say nothing about the module.
                        if (v >= 0x20 && v <= 0xFFFF && rep.indexOf("BP") < 0
                                && rep.indexOf("SP") < 0) {
                            dataRefs.add(String.format("%04x", v));
                        }
                    }
                }
            }

            for (int op = 0; op < ins.getNumOperands(); op++) {
                Scalar s = ins.getScalar(op);
                if (s == null) {
                    continue;
                }
                long v = s.getUnsignedValue();
                if (mn.equals("INT")) {
                    interrupts.add(v);
                } else if (mn.equals("IN") || mn.equals("OUT")) {
                    ports.add(v);
                }
                // Constants below 0x10 appear everywhere and carry no
                // identifying information; skip them to keep the fingerprint
                // discriminating.
                if (v >= 0x10) {
                    scalars.add(v);
                }
            }
        }

        sb.append("\"instruction_count\": ").append(instructionCount).append(", ");
        appendControlFlow(sb, f);
        sb.append("\"calls\": ").append(strArray(callees)).append(", ");
        sb.append("\"scalars\": ").append(longArray(scalars)).append(", ");
        sb.append("\"interrupts\": ").append(longArray(interrupts)).append(", ");
        sb.append("\"io_ports\": ").append(longArray(ports)).append(", ");
        sb.append("\"strings\": ").append(strArray(strings)).append(", ");
        sb.append("\"data_refs\": ").append(strArray(dataRefs)).append(", ");
        sb.append("\"mnemonics\": ").append(strArray(mnemonics));
    }

    /* Shape of the function's control-flow graph.
     *
     * Constants and strings are what a compiler is most free to move around;
     * the decision structure is what it must preserve. An `if` in the source
     * has to become a conditional branch in the binary, a loop has to become a
     * back edge. So cyclomatic complexity and loop count survive compilation
     * far better than any byte-level feature, and can be compared against the
     * same quantities counted in C source.
     */
    private void appendControlFlow(StringBuilder sb, Function f) {
        int blocks = 0, edges = 0, backEdges = 0, returns = 0, indirect = 0;
        try {
            ghidra.program.model.block.BasicBlockModel model =
                    new ghidra.program.model.block.BasicBlockModel(currentProgram);
            ghidra.program.model.block.CodeBlockIterator it =
                    model.getCodeBlocksContaining(f.getBody(), monitor);
            while (it.hasNext()) {
                ghidra.program.model.block.CodeBlock block = it.next();
                blocks++;
                int outgoing = 0;
                ghidra.program.model.block.CodeBlockReferenceIterator dests =
                        block.getDestinations(monitor);
                while (dests.hasNext()) {
                    ghidra.program.model.block.CodeBlockReference ref = dests.next();
                    ghidra.program.model.address.Address to =
                            ref.getDestinationAddress();
                    if (!f.getBody().contains(to)) {
                        continue;         // a call leaving the function
                    }
                    outgoing++;
                    edges++;
                    // An edge going backwards inside the function closes a
                    // loop. Counting these is the cheapest reliable loop count.
                    if (to.compareTo(block.getFirstStartAddress()) <= 0) {
                        backEdges++;
                    }
                }
                if (outgoing == 0) {
                    returns++;
                }
            }
        } catch (Exception e) {
            // A damaged or unusual function yields no graph. Reporting zeros
            // is honest: the matcher treats a zero as "no evidence".
        }

        ghidra.program.model.listing.InstructionIterator ii =
                currentProgram.getListing().getInstructions(f.getBody(), true);
        while (ii.hasNext()) {
            ghidra.program.model.listing.Instruction ins = ii.next();
            String mn = ins.getMnemonicString().toUpperCase();
            if ((mn.equals("JMP") || mn.equals("CALL"))
                    && ins.getNumOperands() > 0
                    && ins.getScalar(0) == null) {
                indirect++;               // jump table or call through pointer
            }
        }

        // McCabe: edges - nodes + 2. Equivalent to counting decision points.
        int cyclomatic = blocks > 0 ? edges - blocks + 2 : 0;

        sb.append("\"blocks\": ").append(blocks).append(", ");
        sb.append("\"edges\": ").append(edges).append(", ");
        sb.append("\"loops\": ").append(backEdges).append(", ");
        sb.append("\"returns\": ").append(returns).append(", ");
        sb.append("\"indirect_jumps\": ").append(indirect).append(", ");
        sb.append("\"cyclomatic\": ").append(Math.max(0, cyclomatic)).append(", ");
    }

    /** True when the address lies in a block that holds defined functions.
     *
     * Ghidra's MZ loader marks every segment executable, so isExecute() cannot
     * distinguish code from data. Presence of a defined function is evidence
     * rather than a flag, so that is what is used.
     */
    private boolean inCodeSegment(ghidra.program.model.address.Address a) {
        ghidra.program.model.mem.MemoryBlock blk = currentProgram.getMemory().getBlock(a);
        if (blk == null) {
            return false;
        }
        if (codeBlockNames == null) {
            codeBlockNames = new TreeSet<>();
            for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
                ghidra.program.model.mem.MemoryBlock b =
                        currentProgram.getMemory().getBlock(f.getEntryPoint());
                if (b != null) {
                    codeBlockNames.add(b.getName());
                }
            }
        }
        return codeBlockNames.contains(blk.getName());
    }

    private Set<String> codeBlockNames = null;

    private String strArray(Set<String> items) {
        StringBuilder sb = new StringBuilder("[");
        boolean first = true;
        for (String s : items) {
            if (!first) {
                sb.append(", ");
            }
            sb.append(quote(s));
            first = false;
        }
        return sb.append("]").toString();
    }

    private String longArray(Set<Long> items) {
        StringBuilder sb = new StringBuilder("[");
        boolean first = true;
        for (Long v : items) {
            if (!first) {
                sb.append(", ");
            }
            sb.append(v);
            first = false;
        }
        return sb.append("]").toString();
    }

    private String quote(String s) {
        if (s == null) {
            return "null";
        }
        StringBuilder sb = new StringBuilder("\"");
        for (char ch : s.toCharArray()) {
            switch (ch) {
                case '"':  sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n");  break;
                case '\r': sb.append("\\r");  break;
                case '\t': sb.append("\\t");  break;
                default:
                    if (ch < 0x20) {
                        sb.append(String.format("\\u%04x", (int) ch));
                    } else {
                        sb.append(ch);
                    }
            }
        }
        return sb.append('"').toString();
    }
}
