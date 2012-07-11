package org.jenkinsci.plugins.cas.spring.security;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.jasig.cas.client.session.SingleSignOutFilter;
import org.springframework.util.Assert;
import org.springframework.web.filter.GenericFilterBean;

/**
 * CAS Single Sign-Out filter with support for a URL path matching.
 * 
 * @author Fabien Crespel <fabien@crespel.net>
 */
public class CasSingleSignOutFilter extends GenericFilterBean {

	private boolean enabled = true;
	private String filterProcessesUrl = "/j_spring_cas_security_check";
	private SingleSignOutFilter singleSignOutFilter;

	@Override
	public void afterPropertiesSet() throws ServletException {
		Assert.hasLength(filterProcessesUrl, "filterProcessesUrl must be specified");
		Assert.notNull(singleSignOutFilter, "singleSignOutFilter cannot be null");
		singleSignOutFilter.init();
	}

	public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) res;

        if (!enabled || !requiresProcessing(request, response)) {
            chain.doFilter(request, response);
            return;
        }
        
        singleSignOutFilter.doFilter(req, res, chain);
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
	 * @return the singleSignOutFilter
	 */
	public SingleSignOutFilter getSingleSignOutFilter() {
		return singleSignOutFilter;
	}

	/**
	 * @param singleSignOutFilter the singleSignOutFilter to set
	 */
	public void setSingleSignOutFilter(SingleSignOutFilter singleSignOutFilter) {
		this.singleSignOutFilter = singleSignOutFilter;
	}

}
