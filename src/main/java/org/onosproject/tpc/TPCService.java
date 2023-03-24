package org.onosproject.tpc;

import org.onlab.packet.Ip4Address;
import org.onosproject.tpc.common.AppFilteringEntry;

import java.util.List;
import java.util.Set;

public interface TPCService {
    void postApplicationFilteringRules(List<AppFilteringEntry> app_filtering_rules);

    void flushFlowRules();

    List<String> getRogueIps();

    void blockRogueIp(List<String> ip);
}
