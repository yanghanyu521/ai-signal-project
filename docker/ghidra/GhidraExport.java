// @category AI Signal
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

import ghidra.app.decompiler.*;
import ghidra.app.script.GhidraScript;
import ghidra.framework.Application;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Reference;

public class GhidraExport extends GhidraScript {
    private String q(String value) {
        if (value == null) return "null";
        StringBuilder out = new StringBuilder("\"");
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '\\': out.append("\\\\"); break;
                case '"': out.append("\\\""); break;
                case '\n': out.append("\\n"); break;
                case '\r': out.append("\\r"); break;
                case '\t': out.append("\\t"); break;
                default:
                    if (c < 0x20) out.append(String.format("\\u%04x", (int)c));
                    else out.append(c);
            }
        }
        return out.append('"').toString();
    }

    private String array(Collection<String> values) {
        StringBuilder out = new StringBuilder("[");
        boolean first = true;
        for (String value : values) {
            if (!first) out.append(',');
            first = false;
            out.append(q(value));
        }
        return out.append(']').toString();
    }

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1) throw new IllegalArgumentException("output JSONL path required");
        try (PrintWriter out = new PrintWriter(new OutputStreamWriter(
                new FileOutputStream(args[0]), StandardCharsets.UTF_8))) {
            out.println("{\"record_type\":\"metadata\",\"tool\":\"ghidra\",\"version\":"
                + q(Application.getApplicationVersion()) + ",\"language\":"
                + q(currentProgram.getLanguageID().getIdAsString()) + "}");

            DecompInterface decompiler = new DecompInterface();
            decompiler.toggleCCode(true);
            decompiler.toggleSyntaxTree(false);
            decompiler.openProgram(currentProgram);
            int functionCount = 0;
            FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
            while (functions.hasNext() && functionCount++ < 20000 && !monitor.isCancelled()) {
                Function function = functions.next();
                if (function.isExternal()) continue;
                DecompileResults result = decompiler.decompileFunction(function, 60, monitor);
                String code = result.decompileCompleted() && result.getDecompiledFunction() != null
                    ? result.getDecompiledFunction().getC() : "";
                List<String> calls = new ArrayList<>();
                for (Function called : function.getCalledFunctions(monitor)) {
                    calls.add(called.getName(true));
                }
                out.println("{\"record_type\":\"function\",\"name\":" + q(function.getName(true))
                    + ",\"address\":" + q(function.getEntryPoint().toString())
                    + ",\"body_start\":" + q(function.getBody().getMinAddress().toString())
                    + ",\"body_end\":" + q(function.getBody().getMaxAddress().toString())
                    + ",\"calls\":" + array(calls) + ",\"content\":" + q(code)
                    + ",\"decompile_completed\":" + result.decompileCompleted() + "}");
            }
            decompiler.dispose();

            int stringCount = 0;
            DataIterator data = currentProgram.getListing().getDefinedData(true);
            while (data.hasNext() && stringCount < 20000 && !monitor.isCancelled()) {
                Data item = data.next();
                if (!item.hasStringValue()) continue;
                Object value = item.getValue();
                if (value == null) continue;
                List<String> references = new ArrayList<>();
                for (Reference reference : currentProgram.getReferenceManager().getReferencesTo(item.getAddress())) {
                    references.add(reference.getFromAddress().toString());
                }
                out.println("{\"record_type\":\"string\",\"address\":" + q(item.getAddress().toString())
                    + ",\"references\":" + array(references) + ",\"content\":" + q(value.toString()) + "}");
                stringCount++;
            }

            FunctionIterator externals = currentProgram.getFunctionManager().getExternalFunctions();
            while (externals.hasNext() && !monitor.isCancelled()) {
                Function function = externals.next();
                out.println("{\"record_type\":\"import\",\"name\":" + q(function.getName(true)) + "}");
            }
        }
    }
}
