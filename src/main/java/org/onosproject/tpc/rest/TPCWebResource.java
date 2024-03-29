package org.onosproject.tpc.rest;

import com.fasterxml.jackson.databind.JsonNode;
import org.onlab.packet.Ip4Address;
import org.onosproject.rest.AbstractWebResource;
import org.onosproject.tpc.TPCService;
import org.onosproject.tpc.common.AppFilteringEntry;

import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.util.*;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.onlab.util.Tools.readTreeFromStream;

@Path("tpc")
public class TPCWebResource extends AbstractWebResource {
    private final Logger log = LoggerFactory.getLogger(getClass());

    @GET
    @Path("flush")
    public Response flushFlowRules() {
        get(TPCService.class).flushFlowRules();
        return Response.noContent().build();
    }

    /*
    --header 'Content-Type: application/json' \
    --data-raw '{
        "ipaddresses": ["172.250.237.121","172.250.237.154", "172.250.237.153"]}'
    */

    @GET
    @Path("rogueIps")
    public Response getRogueIps() {
        List<String> rogueIps = get(TPCService.class).getRogueIps();
        String resp = "{ \"ipaddresses\": [\"" + String.join(", ", rogueIps) + "\"] }";
        log.info("Sending {}!", resp);
        return Response.ok(resp, MediaType.APPLICATION_JSON).build();
    }

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Path("blockRogueIp")
    public Response blockIp(InputStream stream) {
        log.info("Received rogue Ip .json file");
        List<String> rogueIps = jsonToRogueIp(stream);
        get(TPCService.class).blockRogueIp(rogueIps);
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
	    log.info("Received rules .json file");
        List<AppFilteringEntry> appFilteringEntries = jsonToAppFilteringEntries(stream);
        get(TPCService.class).postApplicationFilteringRules(appFilteringEntries);
        return Response.noContent().build();
    }

    private List<String> jsonToRogueIp(InputStream stream) throws IllegalArgumentException {
        List<String> ips = new ArrayList<>();

        JsonNode node;
        try {
            node = readTreeFromStream(mapper(), stream);
        } catch (IOException e) {
            log.info("Exception");
            throw new IllegalArgumentException("Unable to parse add request", e);
        }

        Iterator<Map.Entry<String, JsonNode>> fields = node.fields();
        while (fields.hasNext()) {
            Map.Entry<String, JsonNode> field = fields.next();
            JsonNode subNode = field.getValue();

            String rogueIpStr = subNode.path("rogueIp").asText(null);
            if (rogueIpStr != null) {
                ips.add(rogueIpStr);
            }
        }
        return ips;
    }

    private List<AppFilteringEntry> jsonToAppFilteringEntries(InputStream stream) throws IllegalArgumentException {
        List<AppFilteringEntry> attackEntries = new ArrayList<>();

        JsonNode node;
        try {
            node = readTreeFromStream(mapper(), stream);
        } catch (IOException e) {
            log.info("Exception");
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
