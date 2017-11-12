package org.gwtproject.server.security;

import com.google.inject.Injector;
import com.google.inject.persist.Transactional;
import org.apache.shiro.authc.*;
import org.apache.shiro.authc.credential.CredentialsMatcher;
import org.apache.shiro.authc.credential.HashedCredentialsMatcher;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.crypto.hash.Md5Hash;
import org.apache.shiro.crypto.hash.Sha256Hash;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.gwtproject.server.persistence.AdUser;

import javax.inject.Inject;
import javax.persistence.EntityManager;
import javax.persistence.TypedQuery;
import javax.persistence.criteria.CriteriaBuilder;
import javax.persistence.criteria.CriteriaQuery;
import javax.persistence.criteria.ParameterExpression;
import javax.persistence.criteria.Root;
import java.util.logging.Logger;

public class DbUsersRealm extends AuthorizingRealm {

    protected static final String DEFAULT_AUTHORIZATION_CACHE_SUFFIX = ".authorizationCache";

    protected static final int HASH_ITERATIONS = 1024;

    private static final Logger log = Logger.getLogger(DbUsersRealm.class.getCanonicalName());


    // This is related to this http://shiro-user.582556.n2.nabble.com/Issue-with-Shiro-authorization-getting-cleared-td7140992.html
    public static final String REALM_NAME = DbUsersRealm.class.getName() + DEFAULT_AUTHORIZATION_CACHE_SUFFIX;

    private Injector injector;

    @Inject
    public DbUsersRealm(Injector injector) {
        super();

        this.injector = injector;

        setName(REALM_NAME);

        setCredentialsMatcher(createCredentialMatcher());
    }

    public static final CredentialsMatcher createCredentialMatcher() {
        HashedCredentialsMatcher credentialMatcher = new HashedCredentialsMatcher();
        credentialMatcher.setHashAlgorithmName(Md5Hash.ALGORITHM_NAME);
//        credentialMatcher.setHashIterations(HASH_ITERATIONS);
        credentialMatcher.setStoredCredentialsHexEncoded(true);

        return credentialMatcher;
    }

    @Override
    @Transactional
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authToken) throws AuthenticationException {
        UsernamePasswordToken token = (UsernamePasswordToken) authToken;

        String userName = token.getUsername();

        EntityManager em = injector.getInstance(EntityManager.class);

        CriteriaBuilder cb = em.getCriteriaBuilder();

        CriteriaQuery<AdUser> q = cb.createQuery(AdUser.class);
        Root<AdUser> u = q.from(AdUser.class);

        ParameterExpression<String> usernameP = cb.parameter(String.class, "username");

        q.select(u)
                .where(cb.equal(u.get("username"), usernameP))
        ;

        TypedQuery<AdUser> query = em.createQuery(q);
        query.setParameter("username", userName);
        try {
            AdUser user = query.getSingleResult();

            Principal principal = new Principal();
            principal.userId = user.getId();

            return new SimpleAuthenticationInfo(principal, user.getPassword(), getName());
        } catch (Exception e) {
            throw new UnknownAccountException();
        }
    }


    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        return new SimpleAuthorizationInfo();
    }

    protected Injector getInjector() {
        return injector;
    }

    protected Logger getLogger() {
        return log;
    }

}
