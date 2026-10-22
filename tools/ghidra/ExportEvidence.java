// Export static evidence after headless auto-analysis. Never executes the target.
//@category NXReborn
import ghidra.app.util.headless.HeadlessScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.util.opinion.ElfLoader;
import ghidra.framework.Application;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.data.StringDataInstance;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.io.*;
import java.util.*;
import java.util.regex.Pattern;
import java.security.MessageDigest;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

public class ExportEvidence extends HeadlessScript {
    private String elfVa(Address address) {
        Long original=ElfLoader.getElfOriginalImageBase(currentProgram);
        if(original==null || !address.getAddressSpace().equals(currentProgram.getAddressFactory().getDefaultAddressSpace())) return null;
        if(currentProgram.getMemory().getBlock(address)==null || !currentProgram.getMemory().getBlock(address).isLoaded()) return null;
        return "0x"+Long.toHexString(address.getOffset()-currentProgram.getImageBase().getOffset()+original);
    }
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) throw new IllegalArgumentException("output directory required");
        String sha = currentProgram.getExecutableSHA256();
        Path out = Paths.get(args[0], currentProgram.getName() + "-" + sha.substring(0,12));
        Files.createDirectories(out);
        Files.deleteIfExists(out.resolve("summary.json"));
        Gson gson = new GsonBuilder().disableHtmlEscaping().create();
        Pattern targets = Pattern.compile(args.length > 1 ? args[1] :
            "(?i)(captureSaveDone|SIFListener|runFromCapture|UI_Capture_File_Write_Done|UI_BT_Send_Contents|DMS|SendFileThruGet|RetriveFilePath|GetFilePathFromURI|DlnaGetContentUri|StartHTTPServer|createFileTransfer|jpegResize|WiFi.*(Start|Stop)|Wifi.*(Start|Stop)|fw_upgrade)");
        int budget = args.length > 2 ? Integer.parseInt(args[2]) : 35;
        int decompileTimeout = args.length > 4 ? Integer.parseInt(args[4]) : 20;
        if (budget < 0 || decompileTimeout <= 0) throw new IllegalArgumentException("Invalid decompile budget/timeout");
        int count = 0, attempted = 0, completed = 0, eligible = 0;
        DecompInterface dec = new DecompInterface();
        DecompileOptions options = new DecompileOptions();
        int payloadOverride = args.length > 5 ? Integer.parseInt(args[5]) : 0;
        if (payloadOverride < 0) throw new IllegalArgumentException("Invalid decompile response size");
        if (payloadOverride > 0) options.setMaxPayloadMBytes(payloadOverride);
        dec.setOptions(options);
        dec.openProgram(currentProgram);
        try (BufferedWriter functions = Files.newBufferedWriter(out.resolve("functions.jsonl.partial"),StandardCharsets.UTF_8);
             BufferedWriter edges = Files.newBufferedWriter(out.resolve("calls.jsonl.partial"),StandardCharsets.UTF_8);
             BufferedWriter decompiled = Files.newBufferedWriter(out.resolve("decompiled.jsonl.partial"),StandardCharsets.UTF_8)) {
            FunctionIterator iterator = currentProgram.getFunctionManager().getFunctions(true);
            while (iterator.hasNext() && !monitor.isCancelled()) {
                Function f = iterator.next(); count++;
                Map<String,Object> row = new LinkedHashMap<>();
                row.put("va",f.getEntryPoint().toString()); row.put("name",f.getName(true));
                row.put("elf_va",elfVa(f.getEntryPoint()));
                row.put("signature",f.getSignature().toString()); row.put("thunk",f.isThunk());
                row.put("signature_source",f.getSignatureSource().toString());
                row.put("abi_verified",false);
                row.put("external",f.isExternal()); row.put("body_addresses",f.getBody().getNumAddresses());
                functions.write(gson.toJson(row)); functions.newLine();
                for (Function called : f.getCalledFunctions(monitor)) {
                    Map<String,String> edge = new LinkedHashMap<>();
                    edge.put("caller_va",f.getEntryPoint().toString()); edge.put("caller",f.getName(true));
                    edge.put("caller_elf_va",elfVa(f.getEntryPoint()));
                    edge.put("callee_va",called.getEntryPoint().toString()); edge.put("callee",called.getName(true));
                    edge.put("callee_elf_va",elfVa(called.getEntryPoint()));
                    edges.write(gson.toJson(edge)); edges.newLine();
                }
                boolean matches = !f.isThunk() && !f.isExternal() && targets.matcher(f.getName(true)).find();
                if(matches) eligible++;
                if (matches && attempted < budget) {
                    attempted++;
                    DecompileResults result = dec.decompileFunction(f,decompileTimeout,monitor);
                    Map<String,Object> d = new LinkedHashMap<>();
                    d.put("va",f.getEntryPoint().toString()); d.put("name",f.getName(true));
                    d.put("elf_va",elfVa(f.getEntryPoint()));
                    d.put("signature_source",f.getSignatureSource().toString());
                    d.put("signature_warning","Inferred signature/types require independent ABI validation");
                    d.put("completed",result.decompileCompleted()); d.put("error",result.getErrorMessage());
                    if (result.decompileCompleted()) {
                        completed++; d.put("c",result.getDecompiledFunction().getC());
                        List<String> instructions = new ArrayList<>();
                        InstructionIterator ins = currentProgram.getListing().getInstructions(f.getBody(),true);
                        while(ins.hasNext()) { Instruction i=ins.next(); instructions.add(i.getAddress()+" "+i.toString()); }
                        d.put("instructions",instructions);
                    }
                    decompiled.write(gson.toJson(d)); decompiled.newLine();
                }
            }
        } finally { dec.dispose(); }
        int strings = 0;
        try (BufferedWriter writer = Files.newBufferedWriter(out.resolve("strings.jsonl.partial"),StandardCharsets.UTF_8)) {
            DataIterator data = currentProgram.getListing().getDefinedData(true);
            while(data.hasNext() && !monitor.isCancelled()) {
                Data d=data.next(); StringDataInstance instance=StringDataInstance.getStringDataInstance(d);
                if(instance==null || !StringDataInstance.isString(d)) continue;
                Map<String,Object> row=new LinkedHashMap<>();
                row.put("va",d.getAddress().toString()); row.put("value",instance.getStringValue());
                row.put("elf_va",elfVa(d.getAddress()));
                row.put("address_space",d.getAddress().getAddressSpace().getName());
                row.put("loaded_memory",currentProgram.getMemory().getBlock(d.getAddress())!=null && currentProgram.getMemory().getBlock(d.getAddress()).isLoaded());
                List<String> refs=new ArrayList<>();
                ReferenceIterator ri=currentProgram.getReferenceManager().getReferencesTo(d.getAddress());
                while(ri.hasNext()) refs.add(ri.next().getFromAddress().toString());
                row.put("reference_vas",refs); writer.write(gson.toJson(row)); writer.newLine(); strings++;
            }
        }
        Map<String,Object> summary=new LinkedHashMap<>();
        summary.put("program",currentProgram.getName()); summary.put("sha256",sha);
        summary.put("language",currentProgram.getLanguageID().toString());
        summary.put("compiler_spec",currentProgram.getCompilerSpec().getCompilerSpecID().toString());
        summary.put("image_base",currentProgram.getImageBase().toString()); summary.put("functions",count);
        Long originalBase=ElfLoader.getElfOriginalImageBase(currentProgram);
        summary.put("elf_original_image_base",originalBase==null?null:"0x"+Long.toHexString(originalBase));
        summary.put("address_convention","va/instructions/C use Ghidra program VA; elf_va converts to original ELF link-time VA. Neither is a file offset.");
        summary.put("strings",strings); summary.put("decompile_budget",budget);
        summary.put("decompile_attempted",attempted); summary.put("decompile_completed",completed);
        summary.put("decompile_timeout_seconds",decompileTimeout);
        summary.put("decompile_max_payload_mb",options.getMaxPayloadMBytes());
        summary.put("decompile_pattern",targets.pattern()); summary.put("matched_functions",eligible);
        summary.put("decompile_omitted_by_budget",eligible-attempted);
        summary.put("ghidra_version",Application.getApplicationVersion());
        summary.put("exporter_version","2026-10-21.3");
        summary.put("export_schema_version",2);
        summary.put("run_id",args.length>3?args[3]:"manual-unspecified");
        summary.put("static_only",true); summary.put("scope","auto-analysis; selected decompilation, not full semantic verification");
        summary.put("auto_analysis_timed_out",analysisTimeoutOccurred());
        summary.put("auto_analysis_enabled_this_run",isHeadlessAnalysisEnabled());
        summary.put("unresolved_calls","Direct call edges only; indirect/vtable calls may be missing. External programs are not executed.");
        monitor.checkCancelled();
        summary.put("export_completed",true);
        for(String name : new String[]{"functions.jsonl","calls.jsonl","decompiled.jsonl","strings.jsonl"})
            Files.move(out.resolve(name+".partial"),out.resolve(name),StandardCopyOption.REPLACE_EXISTING,StandardCopyOption.ATOMIC_MOVE);
        Map<String,Object> artifacts=new LinkedHashMap<>();
        for(String name : new String[]{"functions.jsonl","calls.jsonl","decompiled.jsonl","strings.jsonl"}) {
            Path artifact=out.resolve(name);
            Map<String,Object> info=new LinkedHashMap<>();
            info.put("bytes",Files.size(artifact));
            info.put("sha256",HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(artifact))));
            artifacts.put(name,info);
        }
        summary.put("artifacts",artifacts);
        Files.writeString(out.resolve("summary.json"),new GsonBuilder().setPrettyPrinting().create().toJson(summary));
        println("NX_EXPORT "+gson.toJson(summary));
    }
}
