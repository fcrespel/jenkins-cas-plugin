package org.jenkinsci.plugins.cas.spring.security;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.jasig.cas.client.session.SingleSignOutHandler;
import org.springframework.util.Assert;
import org.springframework.web.filter.GenericFilterBean;

/**
 * CAS Single Sign-Out filter with support for a URL path matching.
 * 
 * @author Fabien Crespel
 */
public class CasSingleSignOutFilter extends GenericFilterBean {

	private boolean enabled = true;
	private String filterProcessesUrl = "/j_spring_cas_security_check";
	private SingleSignOutHandler singleSignOutHandler;

	@Override
	public void afterPropertiesSet() throws ServletException {
		Assert.hasLength(filterProcessesUrl, "filterProcessesUrl must be specified");
		Assert.notNull(singleSignOutHandler, "singleSignOutHandler cannot be null");
		singleSignOutHandler.init();
	}

	public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) res;

		if (!enabled || !requiresProcessing(request, response)) {
			chain.doFilter(request, response);
			return;
		}

		if (singleSignOutHandler.process(request, response)) {
			chain.doFilter(req, res);
		}
	}

	protected boolean requiresProcessing(HttpServletRequest request, HttpServletResponse response) {
		String uri = request.getRequestURI();
		int pathParamIndex = uri.indexOf(';');

		if (pathParamIndex > 0) {
			// strip everything after the first semi-colon
			uri = uri.substring(0, pathParamIndex);
		}

		if ("".equals(request.getContextPath())) {
			return uri.endsWith(filterProcessesUrl);
		}

		return uri.endsWith(request.getContextPath() + filterProcessesUrl);
	}

	/**
	 * @return the enabled
	 */
	public boolean isEnabled() {
		return enabled;
	}

	/**
	 * @param enabled the enabled to set
	 */
	public void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}

	/**
	 * @return the filterProcessesUrl
	 */
	public String getFilterProcessesUrl() {
		return filterProcessesUrl;
	}

	/**
	 * @param filterProcessesUrl the filterProcessesUrl to set
	 */
	public void setFilterProcessesUrl(String filterProcessesUrl) {
		this.filterProcessesUrl = filterProcessesUrl;
	}

	/**
	 * @return the singleSignOutHandler
	 */
	public SingleSignOutHandler getSingleSignOutHandler() {
		return singleSignOutHandler;
	}

	/**
	 * @param singleSignOutHandler the singleSignOutHandler to set
	 */
	public void setSingleSignOutHandler(SingleSignOutHandler singleSignOutHandler) {
		this.singleSignOutHandler = singleSignOutHandler;
	}

}
