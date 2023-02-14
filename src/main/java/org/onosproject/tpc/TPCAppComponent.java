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

import java.util.*;

import static org.onlab.util.Tools.get;
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

    private final InternalPacketProcessor packetProcessor = new InternalPacketProcessor();

    @Activate
    protected void activate() {
        appId = mainComponent.getAppId();

        packetService.addProcessor(packetProcessor, PacketProcessor.advisor(0));

        installAclPuntRules();
        setUpTelemetryStripping();

        log.info("Started");
    }

    @Deactivate
    protected void deactivate() {
        // First stop the checking
        cleanUpUpdateVersion();

        // Then deregister the report endpoint
        packetService.removeProcessor(packetProcessor);

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
        for (AppFilteringEntry rule: app_filtering_rules) {
            log.info(rule.toString());
        }
    }

    @Override
    public void flushFlowRules() {
        log.info("Received flushFlowRules");
        flowRuleService.removeFlowRulesById(appId);
    }

    @Override
    public void turnOnChecking() {
        log.info("Received turnOnChecking");
        setUpdateVersion();
    }

    @Override
    public void turnOffChecking() {
        log.info("Received turnOffChecking");
        cleanUpUpdateVersion();
    }

    public void setUpTelemetryStripping() {
        List<FlowRule> flowRules = new ArrayList<>();

        for (Device device: deviceService.getAvailableDevices()) {
            for (PortNumber portNumber: edgePortsOnDevice(device.id())) {
                PiMatchFieldId UPDATE_VERSION = PiMatchFieldId.of("checker_header.variables.update_version");
                PiMatchFieldId HDR_EG_PORT = PiMatchFieldId.of("eg_port");
                String tableIdCheckLastHop = "FabricEgress.checker_control.tb_check_last_hop";
                PiActionId piActionIdCheckLastHop = PiActionId.of("FabricEgress.checker_control.set_last_hop");

                PiCriterion match = PiCriterion.builder()
                        .matchExact(UPDATE_VERSION, 0x1)
                        .matchExact(HDR_EG_PORT, portNumber.toLong())
                        .build();

                PiAction action = PiAction.builder()
                        .withId(piActionIdCheckLastHop)
                        .build();

                flowRules.add(buildFlowRule(device.id(), appId, tableIdCheckLastHop, match, action, MEDIUM_FLOW_RULE_PRIORITY));
            }
        }

        flowRuleService.applyFlowRules(flowRules.toArray(new FlowRule[flowRules.size()]));
    }

    public List<PortNumber> edgePortsOnDevice(DeviceId deviceId) {
        List<Port> portsOnDevice = deviceService.getPorts(deviceId);
        List<PortNumber> portNumbersOnDevice = new ArrayList<>();
        for (Port port: portsOnDevice) {
            portNumbersOnDevice.add(port.number());
        }
        Set<Link> linksOnDevice = linkService.getDeviceEgressLinks(deviceId);

        for (Link link: linksOnDevice) {
            if (portNumbersOnDevice.contains(link.src().port())) {
                portNumbersOnDevice.remove(link.src().port());
            }
        }

        return portNumbersOnDevice;
    }

    public void installAclPuntRules() {
        List<FlowRule> puntRules = new ArrayList<>();
        for (Device device: deviceService.getAvailableDevices()) {
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

    public void setUpdateVersion() {
        List<FlowRule> rules = new ArrayList<>();
        for (Device device: deviceService.getAvailableDevices()) {
            rules.add(updateVersionRule(device.id()));
        }

        flowRuleService.applyFlowRules(rules.toArray(new FlowRule[rules.size()]));
    }

    public FlowRule updateVersionRule(DeviceId deviceId) {
        String tableId = "FabricIngress.init_control.tb_set_update_version";
        PiMatchFieldId piMatchFieldId = PiMatchFieldId.of("checker_header.variables.$valid$");
        PiActionId piActionId = PiActionId.of("FabricIngress.init_control.set_update_version");
        PiActionParamId piActionParamId = PiActionParamId.of("update_version");

        byte match_valid = 0x1;
        byte update_version = 0x1;

        PiCriterion match = PiCriterion.builder()
                .matchExact(piMatchFieldId, match_valid)
                .build();

        PiAction action = PiAction.builder()
                .withId(piActionId)
                .withParameter(new PiActionParam(piActionParamId, update_version))
                .build();

        return buildFlowRule(deviceId, appId, tableId, match, action, HIGH_FLOW_RULE_PRIORITY);
    }

    public void cleanUpUpdateVersion() {
        Collection<FlowRule> flowRulesToRemove = Lists.newArrayList();
        for (FlowRule flow : flowRuleService.getFlowEntriesById(appId)) {
            if (flow.table().equals(PiTableId.of("FabricIngress.init_control.tb_set_update_version"))) {
                flowRulesToRemove.add(flow);
            }
        }

        if (flowRulesToRemove.isEmpty()) {
            return;
        }

        flowRulesToRemove.forEach(flowRuleService::removeFlowRules);
    }

    /**
     * Processes incoming packets.
     */
    private class InternalPacketProcessor implements PacketProcessor {
        @Override
        public void process(PacketContext context) {
            Ethernet eth = context.inPacket().parsed();
            if (eth.getEtherType() == ETH_TYPE_TPC_REPORT) {
                log.info("Packet received from checker on device {}!", context.inPacket().receivedFrom());
                context.block();
            }
        }
    }

}