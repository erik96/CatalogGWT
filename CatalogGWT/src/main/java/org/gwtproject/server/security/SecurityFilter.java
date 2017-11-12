package org.gwtproject.server.security;

import org.apache.shiro.web.servlet.AbstractShiroFilter;

import javax.inject.Inject;
import javax.inject.Singleton;

@Singleton
public class SecurityFilter extends AbstractShiroFilter {

	private ShiroWebSecurityManager securityManager;

	@Inject
	public SecurityFilter(ShiroWebSecurityManager securityManager) {
		this.securityManager = securityManager;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.apache.shiro.web.servlet.AbstractShiroFilter#init()
	 */
	@Override
	public void init() throws Exception {
		super.init();

		setSecurityManager(securityManager);
	}

}
