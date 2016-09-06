package com.apifest.oauth20.persistence.cassandra;

import com.datastax.driver.core.Cluster;
import com.datastax.driver.core.Host;
import com.datastax.driver.core.Metadata;
import com.datastax.driver.core.Session;
import com.datastax.driver.core.policies.ConstantReconnectionPolicy;
import com.datastax.driver.core.policies.ReconnectionPolicy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Created by Giovanni Baleani on 23/02/2016.
 */
public final class CassandraConnector {

    protected static Logger log = LoggerFactory.getLogger(CassandraConnector.class);

    private CassandraConnector() {}

    private static Cluster cluster;

    public static Cluster connect(String cassandraContactPoints) {
        if(cluster == null) {
            cluster = Cluster.builder()
                    .addContactPoint(cassandraContactPoints)
                    .withReconnectionPolicy(new ConstantReconnectionPolicy(1000))
                    .build();
            Metadata metadata = cluster.getMetadata();
            log.info("Connected to cluster: %s\n",
                    metadata.getClusterName());
            for (Host host : metadata.getAllHosts()) {
                log.info(String.format("Datacenter: %s; Host: %s; Rack: %s\n",
                        host.getDatacenter(), host.getAddress(), host.getRack()));
            }
        }
        return cluster;
    }

    public static void close() {
        if(cluster!=null && !cluster.isClosed()) {
            cluster.close();
        }
    }
}
