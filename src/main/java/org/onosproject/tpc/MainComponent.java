package org.onosproject.tpc;

import com.google.common.collect.Lists;
import org.onosproject.cfg.ComponentConfigService;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.Device;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.meter.MeterService;
import org.onosproject.net.pi.model.PiTableId;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collection;

import static org.onosproject.tpc.AppConstants.*;
import static org.onosproject.tpc.common.Utils.sleep;

@Component(immediate = true, service = {MainComponent.class})
public class MainComponent {
    private final Logger log = LoggerFactory.getLogger(getClass());

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected ComponentConfigService cfgService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowRuleService flowRuleService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private MeterService meterService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private DeviceService deviceService;

    private ApplicationId appId;

    @Activate
    protected void activate() {
        appId = coreService.registerApplication(APP_NAME);
        log.info("Started");
    }

    @Deactivate
    protected void deactivate() {
        cleanUpUpdateVersionTable();
        cleanUp();

        log.info("Stopped");
    }

    /**
     * Triggers clean up of flows in the update version table, returns false if no
     * flows were found, true otherwise.
     */
    private void cleanUpUpdateVersionTable() {
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
     * Triggers clean up of flows from this app, returns false if no
     * flows were found, true otherwise.
     *
     * @return false if no flows were found, true otherwise
     */
    private boolean cleanUp() {
        Collection<FlowRule> flows = Lists.newArrayList(
                flowRuleService.getFlowEntriesById(appId).iterator());

        if (flows.isEmpty()) {
            return false;
        }

        flows.forEach(flowRuleService::removeFlowRules);

        for (Device device: deviceService.getAvailableDevices()) {
            meterService.purgeMeters(device.id(), appId);
        }

        return true;
    }

    private void waitPreviousCleanup() {
        int retry = DEFAULT_CLEAN_UP_RETRY_TIMES;
        while (retry != 0) {

            if (!cleanUp()) {
                return;
            }

            log.info("Waiting to remove flows from " +
                            "previous execution of {}...",
                    appId.name());

            sleep(CLEAN_UP_DELAY);

            --retry;
        }
    }
}
