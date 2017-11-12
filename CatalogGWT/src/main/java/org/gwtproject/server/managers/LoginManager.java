package org.gwtproject.server.managers;

import com.google.inject.Inject;
import com.google.inject.persist.Transactional;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.*;
import org.apache.shiro.subject.SimplePrincipalCollection;
import org.apache.shiro.subject.Subject;
import org.gwtproject.server.Principal;
import org.gwtproject.server.persistence.AdUser;
import org.gwtproject.server.security.DbUsersRealm;

import javax.persistence.EntityManager;
import javax.persistence.TypedQuery;
import javax.persistence.criteria.CriteriaBuilder;
import javax.persistence.criteria.CriteriaQuery;
import javax.persistence.criteria.ParameterExpression;
import javax.persistence.criteria.Root;

/**
 * Created by erik on 11/13/17
 */
public class LoginManager {

    private EntityManager em;

    @Inject
    public LoginManager(EntityManager em) {

        this.em = em;
    }


    @Transactional()
    public boolean doLogin(String username, String password) {

        // make sure username does not have spaces at beginning or end
        username = username.trim();

        boolean result;
        AdUser user;

        CriteriaBuilder cb = em.getCriteriaBuilder();

        CriteriaQuery<AdUser> q = cb.createQuery(AdUser.class);
        Root<AdUser> c = q.from(AdUser.class);
        ParameterExpression<String> p = cb.parameter(String.class);
        q.select(c).where(cb.equal(c.get("username"), p));

        TypedQuery<AdUser> query = em.createQuery(q);
        query.setParameter("p", username);
        try {
            user = query.getSingleResult();
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }

        Subject subject = SecurityUtils.getSubject();

        if (subject.isAuthenticated()) {
            return true;
        }

        try {
            UsernamePasswordToken token = new UsernamePasswordToken(username, password);
            subject.login(token);

            // load user account
            result = loadAccount(user);

            // Check

            em.flush();

            return result;
        } catch (IncorrectCredentialsException e) {
            //todo
        } catch (LockedAccountException e) {
            //todo
        } catch (UnknownAccountException e) {
            //todo
        } catch (AuthenticationException e) {
            subject.logout();
        }

        return true;
    }

    private boolean loadAccount(AdUser user) {
        Principal principal = (Principal) SecurityUtils.getSubject().getPrincipal();
        principal.userId = user.getId();
        Subject subject = SecurityUtils.getSubject();
        String principalSessionKey = "org.apache.shiro.subject.support.DefaultSubjectContext_PRINCIPALS_SESSION_KEY";
        SimplePrincipalCollection pc = new SimplePrincipalCollection(principal.clonePrincipal(), DbUsersRealm.REALM_NAME);
        subject.getSession().setAttribute(principalSessionKey, pc);

        return true;
    }
}