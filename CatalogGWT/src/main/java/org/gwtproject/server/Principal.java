package org.gwtproject.server;

/**
 * Created by erik on 11/13/17
 */
public class Principal {

    public long userId;

    public Principal clonePrincipal() {
        Principal p = new Principal();
        p.userId = userId;
        return p;
    }
}
