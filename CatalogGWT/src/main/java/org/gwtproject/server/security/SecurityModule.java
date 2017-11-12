package org.gwtproject.server.security;

import com.google.inject.AbstractModule;
import com.google.inject.Scopes;
import org.apache.shiro.crypto.RandomNumberGenerator;
import org.apache.shiro.crypto.SecureRandomNumberGenerator;

public class SecurityModule extends AbstractModule {

	@Override
	protected void configure() {
		bind(ShiroWebSecurityManager.class).in(Scopes.SINGLETON);

		bind(RandomNumberGenerator.class).to(SecureRandomNumberGenerator.class).in(Scopes.SINGLETON);
	}

}
