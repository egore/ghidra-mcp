package com.xebyte.core;

import com.xebyte.headless.DirectThreadingStrategy;
import com.xebyte.headless.HeadlessProgramProvider;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import org.junit.*;

import static org.junit.Assert.*;

/** {@code const}/{@code volatile} in a prototype or type name are dropped instead of failing the parse. */
public class FunctionPrototypeQualifiersGhidraTest {
    private ProgramBuilder builder;
    private ProgramDB program;
    private FunctionService service;
    private Function function;

    @BeforeClass public static void initialize() throws Exception { OverrideServiceGhidraTest.initialize(); }

    @Before public void setUp() throws Exception {
        builder = new ProgramBuilder("prototype-qualifiers", ProgramBuilder._X86, "windows", this);
        program = builder.getProgram();
        builder.createMemory(".text", "0x1000", 0x100);
        builder.setBytes("0x1000", "c3");
        builder.disassemble("0x1000", 1);
        function = builder.createFunction("0x1000");
        // The parser only sees types already in the program, and a fresh program has no void yet.
        builder.withTransaction(() -> program.getDataTypeManager().resolve(
            ghidra.program.model.data.VoidDataType.dataType,
            ghidra.program.model.data.DataTypeConflictHandler.DEFAULT_HANDLER));
        HeadlessProgramProvider provider = new HeadlessProgramProvider();
        provider.setCurrentProgram(program);
        provider.trackOpenProgram(program);
        service = new FunctionService(provider, new DirectThreadingStrategy());
    }

    @After public void tearDown() { builder.dispose(); }

    private Response set(String prototype) {
        return service.setFunctionPrototypeEndpoint(function, prototype, "", program);
    }

    @Test public void constCharPointerParameterIsAppliedAsCharPointer() {
        Response response = set("void __fastcall ExecuteStarChatCommand(const char *commandText)");
        assertTrue(response.toJson(), response instanceof Response.Ok);
        assertTrue(response.toJson(), response.toJson().contains("const/volatile"));
        assertEquals("__fastcall", function.getCallingConventionName());
        Parameter parameter = function.getParameter(0);
        assertEquals("commandText", parameter.getName());
        assertEquals("char *", parameter.getDataType().getName());
    }

    @Test public void everyQualifierPlacementIsAccepted() {
        for (String prototype : new String[] {
                "int f(char const *p)", "int f(char * const p)", "int f(volatile int *p)",
                "const int f(const char * const p, const volatile int q)"}) {
            Response response = set(prototype);
            assertTrue(prototype + " -> " + response.toJson(), response instanceof Response.Ok);
        }
        assertEquals("int", function.getReturnType().getName());
        assertEquals("char *", function.getParameter(0).getDataType().getName());
        assertEquals("int", function.getParameter(1).getDataType().getName());
    }

    @Test public void unqualifiedPrototypeIsUnchangedAndCarriesNoWarning() {
        Response response = set("int g(char *p)");
        assertTrue(response.toJson(), response instanceof Response.Ok);
        assertFalse(response.toJson(), response.toJson().contains("const/volatile"));
    }

    @Test public void unknownTypeStillFailsAndNamesTheUnqualifiedType() {
        Response response = set("void h(const NoSuchType *p)");
        assertTrue(response.toJson(), response instanceof Response.Err);
        assertTrue(response.toJson(), response.toJson().contains("NoSuchType"));
    }

    @Test public void resolveDataTypeIgnoresQualifiersButPrefersAnExactName() {
        ghidra.program.model.data.DataTypeManager dtm = program.getDataTypeManager();
        DataType plain = ServiceUtils.resolveDataType(dtm, "char *");
        assertNotNull(plain);
        assertEquals(plain.getName(), ServiceUtils.resolveDataType(dtm, "const char *").getName());
        assertEquals(plain.getName(), ServiceUtils.resolveDataType(dtm, "char const *").getName());
        assertNull(ServiceUtils.resolveDataType(dtm, "const NoSuchType *"));

        int tx = dtm.startTransaction("add");
        try {
            dtm.addDataType(new ghidra.program.model.data.StructureDataType("Box<char const *>", 4),
                ghidra.program.model.data.DataTypeConflictHandler.DEFAULT_HANDLER);
        } finally {
            dtm.endTransaction(tx, true);
        }
        DataType exact = ServiceUtils.resolveDataType(dtm, "Box<char const *>");
        assertNotNull(exact);
        assertEquals("Box<char const *>", exact.getName());
    }
}
