onos_url := http://localhost:8181/onos
onos_curl := curl --fail -sSL --user onos:rocks --noproxy localhost
MVN_IMG := maven:3.6.3-openjdk-11

app-build:
	$(info *** Building the TPC ONOS app for application filtering...)
	@mkdir -p target
	@docker run --rm -v ${HOME}/.m2:/root/.m2 -v ${PWD}:/mvn-src -w /mvn-src ${MVN_IMG} mvn clean install
	@ls -1 target/*.oar

app-install:
	$(info *** Installing and activating the TPC app in ONOS...)
	${onos_curl} -X POST -HContent-Type:application/octet-stream \
	'${onos_url}/v1/applications?activate=true' \
		--data-binary @target/app-filtering-cp-1.0.0.oar
	@echo

app-uninstall:
	$(info *** Uninstalling the TPC app from ONOS (if present)...) \
		-${onos_curl} -X DELETE ${onos_url}/v1/applications/org.onosproject.app-filtering-cp
	@echo

set1:
	$(info *** Posting flowrules/set1.json...)
	${onos_curl} -X POST -H 'Content-Type:application/json' \
		${onos_url}/tpc/add_rules -d@./flowrules/set1.json
	@echo

turn-on-checking:
	$(info *** Flushing flows...)
	${onos_curl} ${onos_url}/tpc/turn_on_checking
	@echo

turn-off-checking:
	$(info *** Flushing flows...)
	${onos_curl} ${onos_url}/tpc/turn_off_checking
	@echo

flush-flows:
	$(info *** Flushing flows...)
	${onos_curl} ${onos_url}/tpc/flush
	@echo

app-reload: app-uninstall app-install
