package org.jenkinsci.plugins.cas.spring.security;

import org.acegisecurity.Authentication;
import org.acegisecurity.AuthenticationException;
import org.acegisecurity.AuthenticationManager;
import org.acegisecurity.AuthenticationServiceException;
import org.acegisecurity.BadCredentialsException;
import org.acegisecurity.DisabledException;
import org.acegisecurity.LockedException;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;

/**
 * Acegi AuthenticationManager wrapper for a Spring AuthenticationManager.
 * This class will translate arguments, responses and exceptions between Acegi and Spring.
 * 
 * @author Fabien Crespel
 */
public class AcegiAuthenticationManager implements AuthenticationManager {

	private final org.springframework.security.authentication.AuthenticationManager authenticationManager;

	public AcegiAuthenticationManager(org.springframework.security.authentication.AuthenticationManager authenticationManager) {
		this.authenticationManager = authenticationManager;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		try {
			return mapAuthResponse(authenticationManager.authenticate(mapAuthRequest(authentication)));
		} catch (org.springframework.security.core.AuthenticationException e) {
			throw mapAuthException(e);
		}
	}

	protected org.springframework.security.core.Authentication mapAuthRequest(Authentication authentication) {
		if (authentication instanceof UsernamePasswordAuthenticationToken) {
			UsernamePasswordAuthenticationToken token = (UsernamePasswordAuthenticationToken) authentication;
			return new org.springframework.security.authentication.UsernamePasswordAuthenticationToken(token.getPrincipal(), token.getCredentials());
		} else {
			throw new UnsupportedOperationException("Unexpected authentication type: " + authentication);
		}
	}

	protected Authentication mapAuthResponse(org.springframework.security.core.Authentication authentication) {
		if (authentication instanceof org.springframework.security.cas.authentication.CasAuthenticationToken) {
			return CasAuthentication.newInstance((org.springframework.security.cas.authentication.CasAuthenticationToken) authentication);
		} else {
			throw new UnsupportedOperationException("Unsupported authentication type: " + authentication);
		}
	}

	protected AuthenticationException mapAuthException(org.springframework.security.core.AuthenticationException e) {
		if (e instanceof org.springframework.security.authentication.DisabledException) {
			return new DisabledException(e.getMessage(), e);
		} else if (e instanceof org.springframework.security.authentication.LockedException) {
			return new LockedException(e.getMessage(), e);
		} else if (e instanceof org.springframework.security.authentication.BadCredentialsException) {
			return new BadCredentialsException(e.getMessage(), e);
		} else {
			return new AuthenticationServiceException(e.getMessage(), e);
		}
	}
}
