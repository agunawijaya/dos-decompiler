/* ApplyNames.java -- write recovered names back into the Ghidra database.
 *
 * Takes the mapping produced by tools/match.py (or any JSON of the same
 * shape) and renames the corresponding functions, so that a re-export
 * produces C where the calls read `swmove()` instead of `FUN_1000_02f6()`.
 * That single change is most of the difference between output nobody can
 * follow and output a person can actually work through.
 *
 * Two safeguards, because a wrong name is worse than no name -- it is a lie
 * that survives into every later reading of the code:
 *
 *   * A confidence floor. Pairs scoring below it are skipped.
 *   * Every applied name carries its score in a plate comment, and names
 *     below a "certain" level are suffixed so that uncertainty stays visible
 *     in the decompiled output rather than being quietly forgotten.
 *
 * Usage (headless):
 *   -postScript ApplyNames.java mapping.json [minScore] [certainScore]
 *
 * mapping.json is match.py's --json output: {"mapping": [{"source": ...,
 * "binary": "1000:02f6", "score": 0.83}, ...]}
 *
 * @category DOS.Decompile
 */

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;

public class ApplyNames extends GhidraScript {

    /** Above this, a routine is long enough that evidence from one part of it
     *  says little about the rest. Chosen to sit well above the size of the
     *  small BIOS and DOS wrappers that evidence-based naming identifies
     *  reliably. */
    private static final long LONG_ROUTINE_BYTES = 200;

    /* Deliberately a regex over the JSON rather than a parser: a GhidraScript
     * compiled at run time has no dependency management, and the shape of
     * this file is fixed and simple. */
    private static final Pattern ENTRY = Pattern.compile(
            "\\{\\s*\"source\"\\s*:\\s*\"([^\"]+)\"[^}]*?"
            + "\"binary\"\\s*:\\s*\"([^\"]+)\"[^}]*?"
            + "\"score\"\\s*:\\s*([0-9.]+)");

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            printerr("usage: ApplyNames.java mapping.json [minScore] [certainScore]");
            return;
        }
        double minScore = args.length > 1 ? Double.parseDouble(args[1]) : 0.45;
        double certain  = args.length > 2 ? Double.parseDouble(args[2]) : 0.70;

        String json = new String(Files.readAllBytes(Paths.get(args[0])),
                                 StandardCharsets.UTF_8);
        Matcher m = ENTRY.matcher(json);

        int applied = 0, uncertain = 0, skipped = 0, missing = 0, longNamed = 0;
        while (m.find() && !monitor.isCancelled()) {
            String name = m.group(1);
            String addrText = m.group(2);
            double score = Double.parseDouble(m.group(3));

            if (score < minScore) {
                skipped++;
                continue;
            }

            Address addr = resolveAddress(addrText);
            if (addr == null) {
                missing++;
                continue;
            }
            Function f = getFunctionAt(addr);
            if (f == null) {
                missing++;
                continue;
            }

            boolean sure = score >= certain;
            String applyName = sure ? name : name + "__maybe";

            // A long routine named from evidence found near its start is a
            // documented way to be confidently wrong. A sibling project
            // reconstructing Tapper recorded two such cases side by side:
            // erase_bar_list_a and erase_bar_list_b, both named from their
            // opening lines, both actually doing far more further down --
            // including killing the player. Being a plausible-looking pair
            // made each seem to confirm the other.
            long size = f.getBody().getNumAddresses();
            boolean longRoutine = size >= LONG_ROUTINE_BYTES;

            try {
                f.setName(applyName, SourceType.ANALYSIS);
                StringBuilder note = new StringBuilder(String.format(
                        "identified as %s (confidence %.3f)", name, score));
                if (!sure) {
                    note.append("\nLOW CONFIDENCE -- verify before relying on "
                                + "this name.");
                }
                if (longRoutine) {
                    note.append(String.format(
                            "\nLONG ROUTINE (%d bytes) -- this name reflects "
                            + "evidence found somewhere inside it, not a reading "
                            + "of the whole. Read through to the RET before "
                            + "trusting it; a routine this size often does "
                            + "several things, and the last one is what kills "
                            + "you.", size));
                    longNamed++;
                }
                f.setComment(note.toString());
                applied++;
                if (!sure) {
                    uncertain++;
                }
            } catch (Exception e) {
                printerr("could not rename " + addrText + " to " + name
                         + ": " + e.getMessage());
                missing++;
            }
        }

        println(String.format(
                "ApplyNames: %d renamed (%d marked low-confidence, "
                + "%d flagged as long routines), %d below floor %.2f, "
                + "%d unresolved",
                applied, uncertain, longNamed, skipped, minScore, missing));
    }

    private Address resolveAddress(String text) {
        try {
            return currentProgram.getAddressFactory().getAddress(text);
        } catch (Exception e) {
            return null;
        }
    }
}
