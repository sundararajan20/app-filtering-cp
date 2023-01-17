package org.onosproject.tpc.common;

public class AppFilteringEntry {
    public String ue_subnet, app_ip_proto, app_ip_proto_mask, app_subnet;
    public Integer app_l4_port_low, app_l4_port_high, priority;

    @Override
    public String toString() {
        return String.format(
                "AppFilteringEntry: ue_subnet=%s, app_ip_proto=%s, app_ip_proto_mask=%s, app_subnet=%s, app_l4_port_low=%s, app_l4_port_high=%s, priority=%s",
                ue_subnet, app_ip_proto, app_ip_proto_mask, app_subnet, app_l4_port_low, app_l4_port_high, priority
        );
    }
}
