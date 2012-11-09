package org.jenkinsci.plugins.cas;

import groovy.lang.Binding;
import hudson.Extension;
import hudson.Util;
import hudson.model.Descriptor;
import hudson.security.ChainedServletFilter;
import hudson.security.SecurityRealm;
import hudson.util.FormValidation;
import hudson.util.spring.BeanBuilder;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;

import javax.servlet.Filter;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpSession;

import jenkins.model.Jenkins;

import org.acegisecurity.Authentication;
import org.acegisecurity.AuthenticationException;
import org.acegisecurity.AuthenticationManager;
import org.acegisecurity.BadCredentialsException;
import org.acegisecurity.providers.anonymous.AnonymousAuthenticationToken;
import org.apache.commons.lang.StringUtils;
import org.jasig.cas.client.session.SessionMappingStorage;
import org.jasig.cas.client.util.CommonUtils;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.StaplerResponse;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.web.context.WebApplicationContext;

/**
 * Jasig CAS Single Sign-On security realm.
 * 
 * @see http://www.jasig.org/cas
 * @author Fabien Crespel <fabien@crespel.net>
 * @author J. David Beutel <jbeutel@hawaii.edu>
 */
public class CasSecurityRealm extends SecurityRealm {

	public static final String DEFAULT_COMMENCE_LOGIN_URL = "securityRealm/commenceLogin";
	public static final String DEFAULT_FINISH_LOGIN_URL = "securityRealm/finishLogin";
	public static final String DEFAULT_FAILED_LOGIN_URL = "securityRealm/failedLogin";

	public final String casServerUrl;
	public final CasProtocol casProtocol;
	public final Boolean forceRenewal;
	public final Boolean enableSingleSignOut;

	private transient WebApplicationContext applicationContext;

	@DataBoundConstructor
	public CasSecurityRealm(String casServerUrl, CasProtocol casProtocol, Boolean forceRenewal, Boolean enableSingleSignOut) {
		this.casServerUrl = StringUtils.stripEnd(casServerUrl, "/") + "/";
		this.casProtocol = casProtocol;
		this.forceRenewal = forceRenewal;
		this.enableSingleSignOut = enableSingleSignOut;
	}


	//~ Public getters =================================================================================================

	public String getJenkinsUrl() {
		return Jenkins.getInstance().getRootUrl();
	}
	
	public String getFinishLoginUrl() {
		return DEFAULT_FINISH_LOGIN_URL;
	}
	
	public String getFailedLoginUrl() {
		return DEFAULT_FAILED_LOGIN_URL;
	}


	//~ Protected methods ==============================================================================================

	/**
	 * Create the Spring application context that will hold CAS filters.
	 */
	protected WebApplicationContext getApplicationContext() {
		if (this.applicationContext == null) {
			Binding binding = new Binding();
	        binding.setVariable("securityRealm", this);
	        binding.setVariable("casProtocol", this.casProtocol);

	        BeanBuilder builder = new BeanBuilder(getClass().getClassLoader());
	        builder.parse(getClass().getClassLoader().getResourceAsStream(getClass().getName().replace('.', '/') + ".groovy"), binding);

	        this.applicationContext = builder.createApplicationContext();
		}
		return this.applicationContext;
	}


	//~ SecurityRealm implementation ===================================================================================

	/**
     * Login begins with our {@link #doCommenceLogin(String)} method.
     */
    @Override
    public String getLoginUrl() {
        return DEFAULT_COMMENCE_LOGIN_URL;
    }

    /**
     * Logout redirects to CAS before coming back to Jenkins.
     */
	@Override
	protected String getPostLogOutUrl(StaplerRequest req, Authentication auth) {
		StringBuilder logoutUrlBuilder = new StringBuilder(casServerUrl);
		logoutUrlBuilder.append("logout?service=");
		try {
			logoutUrlBuilder.append(URLEncoder.encode(getJenkinsUrl(), "UTF-8"));
		} catch (UnsupportedEncodingException e) {
			throw new RuntimeException(e);
		}
		return logoutUrlBuilder.toString();
	}

    /**
     * Build a no-op authentication manager as everything is handled by a
     * separate CAS filter chain.
     */
    @Override
    public SecurityComponents createSecurityComponents() {
        return new SecurityComponents(
            new AuthenticationManager() {
                public Authentication authenticate(Authentication authentication) throws AuthenticationException {
                    if (authentication instanceof AnonymousAuthenticationToken)
                        return authentication;
                    throw new BadCredentialsException("Unexpected authentication type: " + authentication);
                }
            }
        );
    }

    /**
     * Build the filter that will validate the service ticket returned by CAS.
     * This filter, defined in the CasSecurityRealm.groovy application context,
     * will wrap the original filter chain from Jenkins to preserve support for
     * API token authentication (among other features).
     */
	@Override
	public Filter createFilter(FilterConfig filterConfig) {
		Filter defaultFilter = super.createFilter(filterConfig);
		Filter casFilter = (Filter) getApplicationContext().getBean("casFilter");
		return new ChainedServletFilter(casFilter, defaultFilter);
	}


	//~ Stapler controller actions =====================================================================================
	
	/**
	 * Handles the logout processing.
	 */
	@Override
	public void doLogout(StaplerRequest req, StaplerResponse rsp) throws IOException, ServletException {
		// Clear Spring Security context
		SecurityContextHolder.clearContext();
		
		// Remove session from CAS single sign-out storage
		HttpSession session = req.getSession(false);
        if (session != null) {
    		SessionMappingStorage sessionMappingStorage = (SessionMappingStorage) getApplicationContext().getBean("casSessionMappingStorage");
    		sessionMappingStorage.removeBySessionById(session.getId());
        }
        
		super.doLogout(req, rsp);
	}

	/**
     * The login process starts from here, using the CasAuthenticationEntryPoint
     * defined in the CasSecurityRealm.groovy application context.
     */
	public void doCommenceLogin(StaplerRequest req, StaplerResponse rsp) throws IOException, ServletException {
		AuthenticationEntryPoint entryPoint = (AuthenticationEntryPoint) getApplicationContext().getBean("casAuthenticationEntryPoint");
		entryPoint.commence(req, rsp, null);
	}
	
	/**
	 * The login process finishes here, although by the time this action is called
	 * everything has already been taken care of by filters.
	 */
	public void doFinishLogin(StaplerRequest req, StaplerResponse rsp) {
		// Nothing to do
	}


	//~ SecurityRealm descriptor =======================================================================================

	@Extension
	public static final class DescriptorImpl extends Descriptor<SecurityRealm> {
		@Override
		public String getDisplayName() {
			return "CAS (Central Authentication Service)";
		}

		public FormValidation doCheckCasServerUrl(@QueryParameter String value) throws IOException, ServletException {
            value = Util.fixEmptyAndTrim(value);
            if (value == null)
                return FormValidation.error(Messages.CasSecurityRealm_casServerUrl_missingUrl());

            try {
                URL url = new URL(StringUtils.stripEnd(value, "/") + "/login");
                String response = CommonUtils.getResponseFromServer(url);
                if (!response.contains("username")) {
                    return FormValidation.warning(Messages.CasSecurityRealm_casServerUrl_invalidResponse());
                }
            } catch (MalformedURLException e) {
                return FormValidation.error(Messages.CasSecurityRealm_casServerUrl_malformedUrl() + ": " + e.getMessage());
            } catch (RuntimeException e) {
                return FormValidation.error(Messages.CasSecurityRealm_casServerUrl_cannotGetResponse() + ": "
                        + (e.getCause() == null ? e : e.getCause()));
            }

            return FormValidation.ok();
        }
	}

}
