package com.xebyte.offline;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import junit.framework.TestCase;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** The offline bridge must check the same new-tool contract that the server publishes. */
public class OverrideSchemaSnapshotTest extends TestCase {

    public void testOverrideToolsMatchTheProductionScanner() throws Exception {
        Map<String, JsonObject> published = toolsByPath(
            JsonParser.parseString(ServiceFactory.buildGuiScanner().generateSchema()).getAsJsonObject());
        Map<String, JsonObject> recorded = toolsByPath(JsonParser.parseString(
            ProjectSource.readProjectFile("tests/conformance/snapshots/mcp_schema.snap")).getAsJsonObject());

        for (String path : List.of("/adjust_pointer_offset", "/get_call_site_prototype",
                "/get_stack_depth_change", "/remove_stack_depth_change", "/set_call_site_prototype",
                "/set_function_calling_convention", "/set_stack_depth_change")) {
            assertNotNull(path + " missing from the production scanner", published.get(path));
            assertNotNull(path + " missing from the recorded schema", recorded.get(path));
            assertEquals(path + " recorded schema differs from the production scanner",
                published.get(path), recorded.get(path));
        }
    }

    private static Map<String, JsonObject> toolsByPath(JsonObject schema) {
        Map<String, JsonObject> tools = new LinkedHashMap<>();
        for (JsonElement element : schema.getAsJsonArray("tools")) {
            JsonObject tool = element.getAsJsonObject();
            String path = tool.get("path").getAsString();
            assertNull("Duplicate schema path: " + path, tools.put(path, tool));
        }
        return tools;
    }
}
