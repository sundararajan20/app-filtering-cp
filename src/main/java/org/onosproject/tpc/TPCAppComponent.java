/*
 * Copyright 2022-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.onosproject.tpc;

import org.onlab.packet.Ethernet;
import org.onosproject.core.ApplicationId;
import org.onosproject.net.*;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flow.criteria.PiCriterion;
import org.onosproject.net.link.LinkService;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketService;
import org.onosproject.net.pi.model.PiActionId;
import org.onosproject.net.pi.model.PiActionParamId;
import org.onosproject.net.pi.model.PiMatchFieldId;
import org.onosproject.net.pi.runtime.PiAction;
import org.onosproject.net.pi.runtime.PiActionParam;
import org.onosproject.tpc.common.AppFilteringEntry;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Modified;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import static org.onosproject.tpc.AppConstants.HIGH_FLOW_RULE_PRIORITY;
import static org.onosproject.tpc.common.Utils.buildFlowRule;

/**
 * Skeletal ONOS application component.
 */
@Component(immediate = true, enabled = true)
public class TPCAppComponent implements TPCService {

    private final Logger log = LoggerFactory.getLogger(getClass());

    private ApplicationId appId;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private DeviceService deviceService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private FlowRuleService flowRuleService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private LinkService linkService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PacketService packetService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private MainComponent mainComponent;

    private static short ETH_TYPE_IPV4 = (short) 0x0800;
    private static short ETH_TYPE_TPC_REPORT = (short) 0x5678;
    private static short ETH_TYPE_TPC_REPORT_MASK = (short) 0xFFFF;

    private Set<String> rogue_ues = new HashSet<>();

    private Lock lock = new ReentrantLock();

    private final InternalPacketProcessor packetProcessor = new InternalPacketProcessor();

    @Activate
    protected void activate() {
        appId = mainComponent.getAppId();

        packetService.addProcessor(packetProcessor, PacketProcessor.advisor(0));

        // TODO: new devices might be discovered after
        installAclPuntRules();
        installReportThrottlingRules();

        log.info("Started");
    }

    @Deactivate
    protected void deactivate() {
        // Then deregister the report endpoint
        packetService.removeProcessor(packetProcessor);

        lock.lock();
        try {
            rogue_ues.clear();
        } finally {
            lock.unlock();
        }

        // Then cleanup
        mainComponent.cleanUp();

        log.info("Stopped");
    }

    @Modified
    public void modified(ComponentContext context) {
        log.info("Reconfigured");
    }

    @Override
    public void postApplicationFilteringRules(List<AppFilteringEntry> app_filtering_rules) {
        log.info("Received postApplicationFilteringRules");

        List<FlowRule> flowRules = new ArrayList<>();
        for (AppFilteringEntry rule : app_filtering_rules) {
            FlowRule flowRule = rule.constructRulesForUpf(DeviceId.deviceId("device:leaf1"), appId);
            flowRules.add(flowRule);
            log.info(rule.toString());
            log.info(flowRule.toString());
        }

        flowRuleService.applyFlowRules(flowRules.toArray(new FlowRule[flowRules.size()]));
    }

    @Override
    public void flushFlowRules() {
        log.info("Received flushFlowRules");
        flowRuleService.removeFlowRulesById(appId);
        lock.lock();
        try {
            rogue_ues.clear();
        } finally {
            lock.unlock();
        }
    }

    @Override
    public List<String> getRogueIps() {
        log.info("Received getRogueIps");
        lock.lock();
        List<String> ret;
        try {
            ret = new ArrayList<>(rogue_ues);
        } finally {
            lock.unlock();
        }
        return ret;
    }

    @Override
    public void blockRogueIp(List<String> ips) {
        log.info("Received blockRogueIp");
        lock.lock();
        try {
            rogue_ues.addAll(ips);
        } finally {
            lock.unlock();
        }
    }

    public void installAclPuntRules() {
        List<FlowRule> puntRules = new ArrayList<>();
        for (Device device : deviceService.getAvailableDevices()) {
            puntRules.add(failedPacketsAclRule(device.id()));
        }

        flowRuleService.applyFlowRules(puntRules.toArray(new FlowRule[puntRules.size()]));
    }

    public FlowRule failedPacketsAclRule(DeviceId deviceId) {
        String tableId = "FabricIngress.acl.acl";
        PiMatchFieldId HDR_ETH_TYPE = PiMatchFieldId.of("eth_type");
        PiActionId piActionId = PiActionId.of("FabricIngress.acl.punt_to_cpu");

        PiCriterion match = PiCriterion.builder()
                .matchTernary(HDR_ETH_TYPE, ETH_TYPE_TPC_REPORT, ETH_TYPE_TPC_REPORT_MASK)
                .build();

        PiAction action = PiAction.builder()
                .withId(piActionId)
                .build();

        return buildFlowRule(deviceId, appId, tableId, match, action, HIGH_FLOW_RULE_PRIORITY);
    }

    public void installReportThrottlingRules() {
        List<FlowRule> puntRules = new ArrayList<>();
        for (Device device : deviceService.getAvailableDevices()) {
            puntRules.add(reportThrottlingRule(device.id()));
        }

        flowRuleService.applyFlowRules(puntRules.toArray(new FlowRule[puntRules.size()]));
    }

    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

    public FlowRule reportThrottlingRule(DeviceId deviceId) {
        String tableId = "FabricIngress.checker_report_control.config";
        PiMatchFieldId HDR_ETH_TYPE_IS_VALID = PiMatchFieldId.of("eth_type_is_valid");
        PiActionId piActionId = PiActionId.of("FabricIngress.checker_report_control.set_config");

        PiCriterion match = PiCriterion.builder()
                .matchExact(HDR_ETH_TYPE_IS_VALID, 1)
                .build();

        byte[] mask = hexStringToByteArray("ffffc0000000");

        PiAction action = PiAction.builder()
                .withId(piActionId)
                .withParameter(new PiActionParam(PiActionParamId.of("timestamp_mask"), mask))
                .build();

        return buildFlowRule(deviceId, appId, tableId, match, action, HIGH_FLOW_RULE_PRIORITY);
    }

    private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();
    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }

    /**
     * Processes incoming packets.
     */
    private class InternalPacketProcessor implements PacketProcessor {
        @Override
        public void process(PacketContext context) {
            Ethernet eth = context.inPacket().parsed();
            if (eth.getEtherType() == ETH_TYPE_IPV4) {
                log.info("TPC Report received from device {}!", context.inPacket().receivedFrom());
                log.info("Report payload: {}", bytesToHex(eth.getPayload().serialize()));
                String rogue_address = new String();
                byte[] ipv4_payload = eth.getPayload().serialize();
                for (int i = 12; i < 16; i++) {
                    if (i > 12) {
                        rogue_address += ".";
                    }
                    rogue_address += String.valueOf(Byte.toUnsignedInt(ipv4_payload[i]));
                }
                log.info("Rogue UE is: {}", rogue_address);
                lock.lock();
                try {
                    rogue_ues.add(rogue_address);
                    log.info("UEs on blacklist are: {}", rogue_ues);
                } finally {
                    lock.unlock();
                }
                context.block();
            }
        }
    }
}
