package org.onosproject.tpc.rest;

import org.onlab.rest.AbstractWebApplication;

import java.util.Set;

public class TPCWebApplication extends AbstractWebApplication {
    @Override
    public Set<Class<?>> getClasses() {
        return getClasses(TPCWebResource.class);
    }
}