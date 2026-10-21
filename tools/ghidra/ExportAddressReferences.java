// Export incoming address-reference candidates for bounded offline followup.
// @category NXResearch
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.lang.Register;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import com.google.gson.GsonBuilder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class ExportAddressReferences extends GhidraScript {
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) throw new IllegalArgumentException("output path and target addresses required");
        Map<String,Object> result = new LinkedHashMap<>();
        result.put("program",currentProgram.getName());
        result.put("source_sha256",currentProgram.getExecutableSHA256());
        result.put("address_convention","Ghidra program VAs only; translate through recorded ELF mapping before claiming original VAs");
        result.put("method","Incoming references known to this saved Ghidra database; not an exhaustive indirect-call or pointer scan");
        result.put("static_only",true);
        List<Object> targets = new ArrayList<>();
        for (int i=1;i<args.length;i++) {
            Address target = toAddr(args[i]);
            Map<String,Object> item = new LinkedHashMap<>();
            item.put("target_va",target.toString());
            Register mode = currentProgram.getRegister("TMode");
            item.put("thumb_mode_context",mode == null ? null : currentProgram.getProgramContext().getValue(mode,target,false));
            List<Object> incoming = new ArrayList<>();
            ReferenceIterator refs = currentProgram.getReferenceManager().getReferencesTo(target);
            while (refs.hasNext()) {
                Reference ref = refs.next();
                Map<String,Object> row = new LinkedHashMap<>();
                row.put("from_va",ref.getFromAddress().toString());
                row.put("type",ref.getReferenceType().toString());
                row.put("operand_index",ref.getOperandIndex());
                Function fn = currentProgram.getFunctionManager().getFunctionContaining(ref.getFromAddress());
                row.put("containing_function",fn == null ? null : fn.getName(true));
                row.put("containing_function_va",fn == null ? null : fn.getEntryPoint().toString());
                incoming.add(row);
            }
            item.put("incoming",incoming);
            targets.add(item);
        }
        result.put("targets",targets);
        Path output=Path.of(args[0]);
        Files.createDirectories(output.toAbsolutePath().getParent());
        Files.writeString(output,new GsonBuilder().setPrettyPrinting().create().toJson(result)+"\n",StandardCharsets.UTF_8);
        println("NX_REFERENCE_EXPORT targets="+(args.length-1));
    }
}
