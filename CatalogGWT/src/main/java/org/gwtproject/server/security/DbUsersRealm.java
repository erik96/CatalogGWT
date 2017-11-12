package org.gwtproject.server.security;

import com.candorgrc.core.common.query.QueryBuilder;
import com.candorgrc.core.login.CoreSessionManager;
import com.candorgrc.core.persistence.AdRolePermissions;
import com.candorgrc.core.persistence.AdUser;
import com.candorgrc.core.security.PermissionsConstants;
import com.candorgrc.core.security.Principal;
import com.google.inject.Injector;
import com.google.inject.persist.Transactional;
import org.apache.shiro.authc.*;
import org.apache.shiro.authc.credential.CredentialsMatcher;
import org.apache.shiro.authc.credential.HashedCredentialsMatcher;
import org.apache.shiro.authz.AuthorizationException;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.Permission;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.crypto.hash.Sha256Hash;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.SimpleByteSource;
import org.gwtproject.server.persistence.AdUser;

import javax.inject.Inject;
import javax.persistence.EntityManager;
import javax.persistence.NoResultException;
import javax.persistence.Query;
import javax.persistence.TypedQuery;
import javax.persistence.criteria.CriteriaBuilder;
import javax.persistence.criteria.CriteriaQuery;
import javax.persistence.criteria.ParameterExpression;
import javax.persistence.criteria.Root;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
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
        credentialMatcher.setHashAlgorithmName(Sha256Hash.ALGORITHM_NAME);
        credentialMatcher.setHashIterations(HASH_ITERATIONS);
        credentialMatcher.setStoredCredentialsHexEncoded(false);
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
        Root<AdUser> c = q.from(AdUser.class);
        ParameterExpression<String> p = cb.parameter(String.class);
        q.select(c).where(cb.equal(c.get("username"), p));

        TypedQuery<AdUser> query = em.createQuery(q);
        query.setParameter("p", userName);
        try {
            AdUser user = query.getSingleResult();
        } catch (Exception e) {
            e.printStackTrace();
        }


        QueryBuilder<AdUser> b = new QueryBuilder<>(em, AdUser.class);
        b.and("userName", userName);

        try {
            AdUser user = b.getSingleResult();

            if (user.getEnabledFlag() == 'N') {
                throw new LockedAccountException();
            }

            Principal principal = new Principal();
            principal.userId = user.getId();

            SimpleByteSource sbs = new SimpleByteSource(user.getPasswordSalt());

            return new SimpleAuthenticationInfo(principal, user.getEncryptedUserPassword(), sbs, getName());
        } catch (NoResultException e) {
            throw new UnknownAccountException();
        }
    }


    private CoreSessionManager getCoreSessionManager() {
        return injector.getInstance(CoreSessionManager.class);
    }

    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        return new SimpleAuthorizationInfo();
    }

    @Override
    public boolean isPermitted(PrincipalCollection principals, String permission) {
        // System.out.println(">>>>>>> DbUsersRealm.isPermitted(): " +
        // permission);
        permission = permission.trim();

        Set<Long> roleIds = new HashSet<Long>();
        // only handle main role now
        roleIds.add(getCoreSessionManager().getIdentityInformations().currentRoleOrgContext.roleId);

        // permission type 1: "comp:[componentShortName]:[permission]"
        if (permission.startsWith(PermissionsConstants.PERMISSION_TYPE_COMPONENT)) {
            return checkComponentPermission(roleIds,
                    permission.substring(PermissionsConstants.PERMISSION_TYPE_COMPONENT.length() + 1));
        }

        // permission type 2, operation specific permission: "op_spec:operation"
        if (permission.startsWith(PermissionsConstants.PERMISSION_TYPE_OPERATION_SPECIFIC)) {
            return checkOperationPermission(roleIds,
                    permission.substring(PermissionsConstants.PERMISSION_TYPE_OPERATION_SPECIFIC.length() + 1));
        }

        // if permission is not of a known type
        log.warning("Unknow permission type: \"" + permission + "\"");
        return false;
    }

    @Override
    public boolean[] isPermitted(PrincipalCollection subjectPrincipal, String... permissions) {
        boolean[] permitted = new boolean[permissions.length];

        for (int i = 0; i < permissions.length; i++) {
            String permission = permissions[i];
            permitted[i] = isPermitted(subjectPrincipal, permission);
        }

        return permitted;
    }

    @Override
    public boolean isPermitted(PrincipalCollection subjectPrincipal, Permission permission) {
        throw new RuntimeException("DbUsersRealm.isPermitted(Permission) - No implementation for Shiro Permission object");
    }

    @Override
    public boolean[] isPermitted(PrincipalCollection subjectPrincipal, List<Permission> permissions) {
        throw new RuntimeException(
                "DbUsersRealm.isPermitted(List<Permission>) - No implementation for Shiro List<Permission> object");
    }

    @Override
    public boolean isPermittedAll(PrincipalCollection subjectPrincipal, String... permissions) {
        for (String permission : permissions) {
            if (!isPermitted(subjectPrincipal, permission)) {
                return false;
            }
        }
        return true;
    }

    @Override
    public boolean isPermittedAll(PrincipalCollection subjectPrincipal, Collection<Permission> permissions) {
        throw new RuntimeException(
                "DbUsersRealm.isPermitted(Collection<Permission>) - No implementation for Shiro Collection<Permission> object");
    }

    @Override
    public void checkPermission(PrincipalCollection subjectPrincipal, String permission) throws AuthorizationException {
        if (!isPermitted(subjectPrincipal, permission)) {
            throw new AuthenticationException(permission);
        }
    }

    @Override
    public void checkPermission(PrincipalCollection subjectPrincipal, Permission permission) throws AuthorizationException {
        if (!isPermitted(subjectPrincipal, permission)) {
            throw new AuthenticationException();
        }

    }

    @Override
    public void checkPermissions(PrincipalCollection subjectPrincipal, String... permissions) throws AuthorizationException {
        if (!isPermittedAll(subjectPrincipal, permissions)) {
            throw new AuthenticationException(String.valueOf(permissions));
        }
    }

    @Override
    public void checkPermissions(PrincipalCollection subjectPrincipal, Collection<Permission> permissions)
            throws AuthorizationException {
        if (!isPermittedAll(subjectPrincipal, permissions)) {
            throw new AuthenticationException();
        }
    }

    @Override
    public boolean hasRole(PrincipalCollection subjectPrincipal, String roleIdentifier) {
        return false;
    }

    @Override
    public boolean[] hasRoles(PrincipalCollection subjectPrincipal, List<String> roleIdentifiers) {
        return null;
    }

    @Override
    public boolean hasAllRoles(PrincipalCollection subjectPrincipal, Collection<String> roleIdentifiers) {
        return false;
    }

    @Override
    public void checkRole(PrincipalCollection subjectPrincipal, String roleIdentifier) throws AuthorizationException {
    }

    @Override
    public void checkRoles(PrincipalCollection subjectPrincipal, Collection<String> roleIdentifiers)
            throws AuthorizationException {
    }

    @Override
    public void checkRoles(PrincipalCollection subjectPrincipal, String... roleIdentifiers) throws AuthorizationException {
    }

    private boolean checkComponentPermission(Set<Long> roleIds, String compPermission) {
        String componentName = compPermission.substring(0, compPermission.indexOf(PermissionsConstants.SEPARATOR));
        String permission = compPermission.substring(compPermission.indexOf(PermissionsConstants.SEPARATOR) + 1);

        StringBuilder sb = new StringBuilder();
        sb.append("SELECT rp FROM AdRolePermissions rp");
        sb.append(" WHERE rp.enabledFlag = 'Y'");
        sb.append(" AND rp.adComponent.componentShortName = :componentName");
        sb.append(" AND rp.adComponent.enabledFlag = 'Y'");

        if (roleIds.size() == 1) {
            sb.append(" AND rp.adRole.id = :roleId");
        } else {
            sb.append(" AND rp.adRole.id IN (:roleIds)");
        }

        EntityManager em = injector.getInstance(EntityManager.class);
        Query query = em.createQuery(sb.toString());

        if (roleIds.size() == 1) {
            query.setParameter("roleId", roleIds.iterator().next());
        } else {
            query.setParameter("roleIds", roleIds);
        }
        query.setParameter("componentName", componentName);

        @SuppressWarnings("unchecked")
        List<AdRolePermissions> list = query.getResultList();

        for (AdRolePermissions rp : list) {
            if (permission.equals(PermissionsConstants.PERMISSION_READ)) {
                return rp.getReadFlag() == 'Y';
            } else if (permission.equals(PermissionsConstants.PERMISSION_CREATE)) {
                return rp.getCreateFlag() == 'Y';
            } else if (permission.equals(PermissionsConstants.PERMISSION_UPDATE)) {
                return rp.getUpdateFlag() == 'Y';
            } else if (permission.equals(PermissionsConstants.PERMISSION_DELETE)) {
                return rp.getDeleteFlag() == 'Y';
            }
        }
        log.info("Permission No permission!");
        return false;
    }

    private boolean checkOperationPermission(Set<Long> roleIds, String permission) {
        EntityManager em = injector.getInstance(EntityManager.class);
        String sql = "SELECT COUNT (pr) FROM AdPermissionsRoles pr"
                + " WHERE pr.adPermission.permission = :permission AND enabledFlag = 'Y'";
        if (roleIds.size() == 1) {
            sql += " AND pr.adRole.id = :roleId";
        } else {
            sql += " AND pr.adRole.id IN (:roleIds)";
        }
        Query query = em.createQuery(sql);

        query.setParameter("permission", permission);
        if (roleIds.size() == 1) {
            query.setParameter("roleId", roleIds.iterator().next());
        } else {
            query.setParameter("roleIds", roleIds);
        }

        try {
            Long count = (Long) query.getSingleResult();
            if (count != null && count > 0) {
                return true;
            }
        } catch (NoResultException e) {
        }
        return false;
    }

    protected Injector getInjector() {
        return injector;
    }

    protected Logger getLogger() {
        return log;
    }

}
