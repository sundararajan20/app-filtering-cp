package org.onosproject.tpc.common;

import com.google.common.collect.Lists;
import org.onosproject.core.ApplicationId;
import org.onosproject.net.DeviceId;
import org.onosproject.net.flow.DefaultFlowRule;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.criteria.PiCriterion;
import org.onosproject.net.pi.model.PiTableId;
import org.onosproject.net.pi.runtime.PiTableAction;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collection;

public class Utils {
    private static final Logger log = LoggerFactory.getLogger(Utils.class);

    public static FlowRule buildFlowRule(DeviceId switchId, ApplicationId appId,
                                         String tableId, PiCriterion piCriterion,
                                         PiTableAction piAction, int priority) {
        return DefaultFlowRule.builder()
                .forDevice(switchId)
                .forTable(PiTableId.of(tableId))
                .fromApp(appId)
                .withPriority(priority)
                .makePermanent()
                .withSelector(DefaultTrafficSelector.builder()
                        .matchPi(piCriterion).build())
                .withTreatment(DefaultTrafficTreatment.builder()
                        .piTableAction(piAction).build())
                .build();
    }

    public static void sleep(int millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            log.error("Interrupted!", e);
            Thread.currentThread().interrupt();
        }
    }
}
