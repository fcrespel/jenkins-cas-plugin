package org.jenkinsci.plugins.cas.spring.security;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;

/**
 * Processes a CAS service ticket.
 * 
 * @author Fabien Crespel <fabien@crespel.net>
 */
public class CasAuthenticationFilter extends org.springframework.security.cas.web.CasAuthenticationFilter {

	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, Authentication authResult) throws IOException, ServletException {
		super.successfulAuthentication(request, response, authResult);
		// make sure we have a session to store this successful authentication, given that we no longer
		// let HttpSessionContextIntegrationFilter2 to create sessions.
		// HttpSessionContextIntegrationFilter stores the updated SecurityContext object into this session later
		// (either when a redirect is issued, via its HttpResponseWrapper, or when the execution returns to its
		// doFilter method.
		request.getSession();
	}

}
