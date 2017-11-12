package org.gwtproject.server.integration;

import com.google.inject.Provider;
import com.google.inject.persist.Transactional;
import org.gwtproject.server.managers.LoginManager;
import org.gwtproject.server.persistence.AdUser;

import javax.inject.Inject;
import javax.inject.Singleton;
import javax.persistence.EntityManager;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

/**
 * Created by radu on 5/14/17.
 */
@SuppressWarnings("ALL")
@Singleton
public class TestJpaServlet extends HttpServlet {

    private Provider<EntityManager> emp;
    private Provider<LoginManager> lmp;

    @Inject
    public TestJpaServlet(Provider<EntityManager> emp, Provider<LoginManager> lmp) {
        this.emp = emp;
        this.lmp = lmp;
    }

    public void doGet(HttpServletRequest request,
                      HttpServletResponse response)
            throws ServletException, IOException {

//        long id = testCreateUser();
        boolean result = lmp.get().doLogin("user", "test");


        PrintWriter out = response.getWriter();
        out.println("<HTML>");
        out.println("<HEAD>");
        out.println("<TITLE>JPA Testing</TITLE>");
        out.println("</HEAD>");
        out.println("<BODY>");
        out.println(String.format("login = %s", result));
        out.println("</BODY>");
        out.println("</HTML>");
        out.flush();
    }

    @Transactional
    public long testCreateUser() {
        EntityManager em = emp.get();

        AdUser user = new AdUser();
        user.setFirstName("u1");
        user.setUsername("user");
        user.setPassword("pass");
        em.persist(user);
        em.flush();

        return user.getId();
    }
}