package org.jenkinsci.plugins.cas.spring.security;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.cas.ServiceProperties;
import org.springframework.security.cas.web.authentication.ServiceAuthenticationDetails;

/**
 * {@code AuthenticationDetailsSource} implementation returning a
 * {@code DynamicServiceAuthenticationDetails} supporting relative service URLs.
 *
 * @author Fabien Crespel <fabien@crespel.net>
 */
public class DynamicServiceAuthenticationDetailsSource implements AuthenticationDetailsSource<HttpServletRequest, ServiceAuthenticationDetails> {

	private ServiceProperties serviceProperties;
	
	public DynamicServiceAuthenticationDetailsSource(ServiceProperties serviceProperties) {
		this.serviceProperties = serviceProperties;
	}
	
	public ServiceAuthenticationDetails buildDetails(HttpServletRequest context) {
		return new DynamicServiceAuthenticationDetails(context, serviceProperties);
	}

}
