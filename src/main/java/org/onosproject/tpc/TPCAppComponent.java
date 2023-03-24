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

import com.google.common.collect.Lists;
import org.onlab.packet.Ethernet;
import org.onlab.packet.Ip4Address;
import org.onosproject.cfg.ComponentConfigService;
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
import org.onosproject.net.pi.model.PiTableId;
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

import java.nio.ByteBuffer;
import java.util.*;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import static org.onosproject.tpc.AppConstants.HIGH_FLOW_RULE_PRIORITY;
import static org.onosproject.tpc.AppConstants.MEDIUM_FLOW_RULE_PRIORITY;
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

    public FlowRule reportThrottlingRule(DeviceId deviceId) {
        String tableId = "FabricIngress.checker_report_control.config";
        PiMatchFieldId HDR_ETH_TYPE_IS_VALID = PiMatchFieldId.of("eth_type_is_valid");
        PiActionId piActionId = PiActionId.of("nop");

        PiCriterion match = PiCriterion.builder()
                .matchExact(HDR_ETH_TYPE_IS_VALID, 1)
                .build();

        PiAction action = PiAction.builder()
                .withId(piActionId)
                .build();

        return buildFlowRule(deviceId, appId, tableId, match, action, HIGH_FLOW_RULE_PRIORITY);
    }

    /**
     * Processes incoming packets.
     */
    private class InternalPacketProcessor implements PacketProcessor {
        @Override
        public void process(PacketContext context) {
            Ethernet eth = context.inPacket().parsed();
            if (eth.getEtherType() == ETH_TYPE_TPC_REPORT) {
                log.info("TPC Report received from device {}!", context.inPacket().receivedFrom());
                byte[] ipv4_payload = eth.getPayload().serialize();
                int addr = 0;
                int offset = 3;
                for (int i = 12; i < 16; i++) {
                    addr += Byte.toUnsignedInt(ipv4_payload[i]) << offset;
                    offset -= 1;
                }
                Ip4Address ue_addr = Ip4Address.valueOf(addr);
                log.info("Rogue UE is: {}", ue_addr);
                lock.lock();
                try {
                    rogue_ues.add(ue_addr.toString());
                    log.info("UEs on blacklist are: {}", rogue_ues);
                } finally {
                    lock.unlock();
                }
                context.block();
            }
        }
    }
}
