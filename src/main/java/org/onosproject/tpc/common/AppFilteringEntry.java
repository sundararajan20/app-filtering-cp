package org.onosproject.tpc.common;

import org.onlab.packet.Ip4Address;
import org.onosproject.core.ApplicationId;
import org.onosproject.net.DeviceId;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.criteria.PiCriterion;
import org.onosproject.net.pi.model.PiActionId;
import org.onosproject.net.pi.model.PiActionParamId;
import org.onosproject.net.pi.model.PiMatchFieldId;
import org.onosproject.net.pi.runtime.PiAction;
import org.onosproject.net.pi.runtime.PiActionParam;

import static org.onosproject.tpc.AppConstants.HIGH_FLOW_RULE_PRIORITY;
import static org.onosproject.tpc.AppConstants.MEDIUM_FLOW_RULE_PRIORITY;
import static org.onosproject.tpc.common.Utils.buildFlowRule;

public class AppFilteringEntry {
    public String ue_ip_addr;

    public Ip4Address app_ip_addr;
    public Integer app_l4_port_low, app_l4_port_high, priority;
    public byte app_ip_proto, app_ip_proto_mask, action;

    public AppFilteringEntry(String ue_ip_addr, String app_ip_proto, String app_ip_addr, String app_l4_port_low, String app_l4_port_high, String priority, String action) {
        this.ue_ip_addr = ue_ip_addr;
        this.app_ip_proto = Byte.valueOf(app_ip_proto);
        this.app_ip_proto_mask = (byte) 0xFF;
        this.app_ip_addr = Ip4Address.valueOf(app_ip_addr);
        this.app_l4_port_low = Integer.valueOf(app_l4_port_low);
        this.app_l4_port_high = Integer.valueOf(app_l4_port_high);
        this.priority = Integer.valueOf(priority);
        this.action = Byte.valueOf(action);
    }

    public FlowRule constructRulesForUpf(DeviceId upfDeviceId, ApplicationId appId) {
        String table = "FabricIngress.init_control.tb_lkp_cp_dict_var_filtering_actions";

        PiCriterion match = PiCriterion.builder()
                .matchExact(PiMatchFieldId.of("checker_header.variables.update_version"), 1)
                .matchExact(PiMatchFieldId.of("checker_header.variables.ue_ipv4_addr"), 1)
                .matchTernary(PiMatchFieldId.of("checker_header.variables.app_ip_proto"), this.app_ip_proto, this.app_ip_proto_mask)
                // .matchLpm(PiMatchFieldId.of("checker_header.variables.app_ipv4_addr"), this.app_ip_addr.toInt(), 32)
                .matchLpm(PiMatchFieldId.of("checker_header.variables.app_ipv4_addr"), 0, 0)
                .matchRange(PiMatchFieldId.of("checker_header.variables.app_l4_port"), this.app_l4_port_low, this.app_l4_port_high)
                .build();

        PiAction action = PiAction.builder()
                .withId(PiActionId.of("FabricIngress.init_control.lkp_cp_dict_var_filtering_actions"))
                .withParameter(new PiActionParam(PiActionParamId.of("lookup_filtering_actions"), this.action))
                .build();

        return buildFlowRule(upfDeviceId, appId, table, match, action, priority);
    }

    @Override
    public String toString() {
        return String.format("AppFilteringEntry{ " +
                "  ue_ip_addr=%s, " +
                "  app_ip_proto=%s, " +
                "  app_ip_proto_mask=%s, " +
                "  app_ip_addr=%s, " +
                "  app_l4_port_low=%s, " +
                "  app_l4_port_high=%s, " +
                "  priority=%s" +
                "  action=%s" +
                "}", ue_ip_addr, app_ip_proto, app_ip_proto_mask, app_ip_addr, app_l4_port_low, app_l4_port_high, priority, action);
    }
}
