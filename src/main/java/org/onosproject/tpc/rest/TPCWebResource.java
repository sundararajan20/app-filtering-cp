package org.onosproject.tpc.rest;

import com.fasterxml.jackson.databind.JsonNode;
import org.onosproject.rest.AbstractWebResource;
import org.onosproject.tpc.TPCService;
import org.onosproject.tpc.common.AppFilteringEntry;

import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import static org.onlab.util.Tools.readTreeFromStream;

@Path("tpc")
public class TPCWebResource extends AbstractWebResource {
    @GET
    @Path("flush")
    public Response flushFlowRules() {
        get(TPCService.class).flushFlowRules();
        return Response.noContent().build();
    }

    @GET
    @Path("turn_on_checking")
    public Response turnOnChecking() {
        get(TPCService.class).turnOnChecking();
        return Response.noContent().build();
    }

    @GET
    @Path("turn_off_checking")
    public Response turnOffChecking() {
        get(TPCService.class).turnOffChecking();
        return Response.noContent().build();
    }

    /**
     * Post application filtering rules.
     *
     * @return 204 NoContent
     */
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Path("add_rules")
    public Response postAppFilteringRules(InputStream stream) {
        List<AppFilteringEntry> appFilteringEntries = jsonToAppFilteringEntries(stream);
        get(TPCService.class).postApplicationFilteringRules(appFilteringEntries);
        return Response.noContent().build();
    }

    private List<AppFilteringEntry> jsonToAppFilteringEntries(InputStream stream) throws IllegalArgumentException {
        List<AppFilteringEntry> attackEntries = new ArrayList<>();

        JsonNode node;
        try {
            node = readTreeFromStream(mapper(), stream);
        } catch (IOException e) {
            throw new IllegalArgumentException("Unable to parse add request", e);
        }

        Iterator<Map.Entry<String, JsonNode>> fields = node.fields();
        while (fields.hasNext()) {
            Map.Entry<String, JsonNode> field = fields.next();
            JsonNode subNode = field.getValue();

            String ueIpAddrStr = subNode.path("ueIpAddr").asText(null);
            String appIpProtoStr = subNode.path("appIpProto").asText(null);
            String appIpAddrStr = subNode.path("appIpAddr").asText(null);
            String appL4PortLowStr = subNode.path("appL4PortLow").asText(null);
            String appL4PortHighStr = subNode.path("appL4PortHigh").asText(null);
            String priorityStr = subNode.path("priority").asText(null);
            String actionStr = subNode.path("action").asText(null);

            if (ueIpAddrStr != null &&
                    appIpProtoStr != null &&
                    appIpAddrStr != null &&
                    appL4PortLowStr != null &&
                    appL4PortHighStr != null &&
                    priorityStr != null &&
                    actionStr != null) {

                attackEntries.add(new AppFilteringEntry(ueIpAddrStr, appIpProtoStr,
                        appIpAddrStr, appL4PortLowStr, appL4PortHighStr, priorityStr, actionStr));
            }
        }

        return attackEntries;
    }
}