package org.gwtproject.server.security;

import com.google.inject.Injector;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.session.SessionListener;
import org.apache.shiro.session.mgt.SessionManager;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.apache.shiro.web.session.mgt.ServletContainerSessionManager;

import javax.inject.Inject;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

public class ShiroWebSecurityManager extends DefaultWebSecurityManager {

    private Injector injector;

    @Inject
    public ShiroWebSecurityManager(DbUsersRealm dbUsersRealm, Injector injector) {
        super(Arrays.asList(new Realm[]{dbUsersRealm}));
        this.injector = injector;

        SessionManager sessManager = new ServletContainerSessionManager();
        setSessionManager(sessManager);
    }

    private Collection<SessionListener> createSessionListeners() {
        List<SessionListener> list = new ArrayList<>();

        return list;
    }
}
