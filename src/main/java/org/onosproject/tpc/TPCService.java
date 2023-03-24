package org.onosproject.tpc;

import org.onosproject.tpc.common.AppFilteringEntry;

import java.util.List;

public interface TPCService {
    void postApplicationFilteringRules(List<AppFilteringEntry> app_filtering_rules);

    void flushFlowRules();
}
