package org.jenkinsci.plugins.cas.spring.security;

import jakarta.servlet.http.HttpSession;

import org.apereo.cas.client.session.SessionMappingStorage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.session.SessionFixationProtectionStrategy;

/**
 * Session fixation protection strategy that invalidates the existing session
 * and integrates with the Single Sign-Out session mapping storage.
 * 
 * @author Fabien Crespel
 */
public class CasSessionFixationProtectionStrategy extends SessionFixationProtectionStrategy {

	private static final Logger LOG = LoggerFactory.getLogger(CasSessionFixationProtectionStrategy.class);

	protected SessionMappingStorage sessionStorage = null;

	public CasSessionFixationProtectionStrategy() {
	}

	public CasSessionFixationProtectionStrategy(SessionMappingStorage sessionStorage) {
		this.sessionStorage = sessionStorage;
	}

	@Override
	protected void onSessionChange(String originalSessionId, HttpSession newSession, Authentication auth) {
		if (sessionStorage != null) {
			LOG.debug("Session changed, removing existing session with ID '{}'", originalSessionId);
			sessionStorage.removeBySessionById(originalSessionId);
			if (auth.getCredentials() instanceof String) {
				LOG.debug("Session changed, adding new session with ID '{}'", newSession.getId());
				sessionStorage.addSessionById((String) auth.getCredentials(), newSession);
			}
		}
		super.onSessionChange(originalSessionId, newSession, auth);
	}

	public SessionMappingStorage getSessionStorage() {
		return sessionStorage;
	}

	public void setSessionStorage(SessionMappingStorage sessionStorage) {
		this.sessionStorage = sessionStorage;
	}

}
