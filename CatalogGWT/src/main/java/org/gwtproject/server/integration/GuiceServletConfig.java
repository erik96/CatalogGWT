package org.gwtproject.server.integration;

import com.google.inject.Guice;
import com.google.inject.Injector;
import com.google.inject.persist.PersistFilter;
import com.google.inject.persist.jpa.JpaPersistModule;
import com.google.inject.servlet.GuiceServletContextListener;
import com.google.inject.servlet.ServletModule;

/**
 * Created by radu on 5/14/17.
 */
public class GuiceServletConfig extends GuiceServletContextListener {

    private Injector injector;

    @Override
    protected Injector getInjector() {
        injector = Guice.createInjector(new ServletModule() {
            @Override
            protected void configureServlets() {
                install(new JpaPersistModule("persistenceUnit"));

                filter("/*").through(PersistFilter.class);

                serve("/jpaTest").with(TestJpaServlet.class);
            }
        });

        return injector;
    }
}