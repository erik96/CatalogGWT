package org.gwtproject.server.security;

import com.candorgrc.core.security.saml.Saml2Realm;
import com.candorgrc.core.security.shiro.FirstExceptionStrategy;
import com.candorgrc.core.security.shiro.realms.DbUsersRealm;
import com.candorgrc.core.security.shiro.realms.SwitchUserRealm;
import com.google.inject.Injector;
import org.apache.shiro.authc.pam.ModularRealmAuthenticator;
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
    public ShiroWebSecurityManager(DbUsersRealm dbUsersRealm, SwitchUserRealm swUserRealm, Saml2Realm saml2Realm, Injector injector) {
        super(Arrays.asList(new Realm[]{dbUsersRealm, swUserRealm, saml2Realm}));
        this.injector = injector;

        SessionManager sessManager = new ServletContainerSessionManager();
        setSessionManager(sessManager);
        ((ModularRealmAuthenticator) getAuthenticator()).setAuthenticationStrategy(new FirstExceptionStrategy());

        // TODO iov: find an alternative
//        ((AbstractNativeSessionManager) getSessionManager())
//                .setGlobalSessionTimeout(CoreConstants.DEFAULT_SERVER_SESSION_TIMEOUT_MINUTES * 60000);
//        ((AbstractNativeSessionManager) getSessionManager()).setSessionListeners(createSessionListeners());
    }

    private Collection<SessionListener> createSessionListeners() {
        List<SessionListener> list = new ArrayList<>();

        return list;
    }
}
