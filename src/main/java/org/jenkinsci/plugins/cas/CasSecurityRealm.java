package org.jenkinsci.plugins.cas;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;

import javax.servlet.Filter;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.apache.commons.lang.StringUtils;
import org.jasig.cas.client.session.SessionMappingStorage;
import org.jasig.cas.client.util.CommonUtils;
import org.jenkinsci.plugins.cas.spring.CasConfigurationContext;
import org.jenkinsci.plugins.cas.spring.security.CasRestAuthenticator;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.StaplerResponse;
import org.kohsuke.stapler.interceptor.RequirePOST;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.cas.ServiceProperties;
import org.springframework.security.cas.authentication.CasAuthenticationToken;
import org.springframework.security.cas.web.CasAuthenticationEntryPoint;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.util.UrlUtils;

import hudson.Extension;
import hudson.Util;
import hudson.model.Descriptor;
import hudson.security.ChainedServletFilter;
import hudson.security.SecurityRealm;
import hudson.util.FormValidation;
import jenkins.model.Jenkins;
import jenkins.security.SecurityListener;

/**
 * CAS Single Sign-On security realm.
 * 
 * @see <a href="https://apereo.github.io/cas/">Apereo CAS project</a>
 * @author Fabien Crespel
 * @author J. David Beutel
 */
public class CasSecurityRealm extends SecurityRealm {

	public static final String DEFAULT_COMMENCE_LOGIN_URL = "securityRealm/commenceLogin";
	public static final String DEFAULT_FINISH_LOGIN_URL = "securityRealm/finishLogin";
	public static final String DEFAULT_FAILED_LOGIN_URL = "securityRealm/failedLogin";

	private static final Logger LOG = LoggerFactory.getLogger(CasSecurityRealm.class);

	public final String casServerUrl;
	public final CasProtocol casProtocol;
	public final Boolean forceRenewal;
	public final Boolean enableSingleSignOut;
	public final Boolean enableRestApi;

	private transient ApplicationContext applicationContext;

	@Deprecated
	public CasSecurityRealm(String casServerUrl, CasProtocol casProtocol, Boolean forceRenewal, Boolean enableSingleSignOut) {
		this(casServerUrl, casProtocol, forceRenewal, enableSingleSignOut, false);
	}

	@DataBoundConstructor
	public CasSecurityRealm(String casServerUrl, CasProtocol casProtocol, Boolean forceRenewal, Boolean enableSingleSignOut, Boolean enableRestApi) {
		this.casServerUrl = StringUtils.stripEnd(casServerUrl, "/") + "/";
		this.casProtocol = casProtocol;
		this.forceRenewal = forceRenewal;
		this.enableSingleSignOut = enableSingleSignOut;
		this.enableRestApi = enableRestApi;
	}

	// ~ Public getters =================================================================================================

	/**
	 * Get the root Jenkins URL configured in global settings.
	 * @return Jenkins URL
	 */
	public static String getJenkinsUrl() {
		return Jenkins.get().getRootUrl();
	}

	/**
	 * Get the root Jenkins URL configured in global settings, or construct it
	 * from the current HTTP request.
	 * @param req current HTTP request
	 * @return Jenkins URL
	 */
	public static String getJenkinsUrl(HttpServletRequest req) {
		String jenkinsUrl = getJenkinsUrl();
		if (jenkinsUrl == null && req != null) {
			jenkinsUrl = UrlUtils.buildFullRequestUrl(req.getScheme(), req.getServerName(), req.getServerPort(), req.getContextPath(), null) + "/";
		}
		return jenkinsUrl;
	}

	/**
	 * Get the callback URL after CAS authentication.
	 * @return finish login URL
	 */
	public static String getFinishLoginUrl() {
		return DEFAULT_FINISH_LOGIN_URL;
	}

	/**
	 * Get the URL to redirect to in case of authentication failure.
	 * @return failed login URL
	 */
	public static String getFailedLoginUrl() {
		return DEFAULT_FAILED_LOGIN_URL;
	}

	/**
	 * Get the full service URL for use with CAS.
	 * @param req current HTTP request
	 * @param serviceProperties service properties
	 * @return full service URL
	 */
	public static String getServiceUrl(HttpServletRequest req, ServiceProperties serviceProperties) {
		String serviceUrl = serviceProperties.getService();
		if (serviceUrl != null && !serviceUrl.startsWith("http")) {
			serviceUrl = getJenkinsUrl(req) + serviceUrl;
		}
		return serviceUrl;
	}

	// ~ Protected methods ==============================================================================================

	/**
	 * Create the Spring application context that will hold CAS filters.
	 * @return Spring application context
	 */
	protected ApplicationContext getApplicationContext() {
		if (this.applicationContext == null) {
			LOG.debug("Creating CAS ApplicationContext");
			CasSecurityRealm casSecurityRealm = this;
			AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext();
			context.registerBean(CasSecurityRealm.class, () -> casSecurityRealm);
			context.registerBean(CasProtocol.class, () -> casSecurityRealm.casProtocol);
			context.register(CasConfigurationContext.class);
			context.refresh();
			this.applicationContext = context;
		}
		return this.applicationContext;
	}

	// ~ SecurityRealm implementation ===================================================================================

	/**
	 * Login begins with our {@link #doCommenceLogin(StaplerRequest, StaplerResponse)} method.
	 * @return Jenkins commenceLogin URL
	 */
	@Override
	public String getLoginUrl() {
		return DEFAULT_COMMENCE_LOGIN_URL;
	}

	/**
	 * Logout redirects to CAS before coming back to Jenkins.
	 * @return CAS logout URL
	 */
	@Override
	protected String getPostLogOutUrl2(StaplerRequest req, Authentication auth) {
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
	 * Build a authentication manager which uses the CAS REST API for username and password based authentication against
	 * the REST API. Browser authentication is handled by the CAS filter chain.
	 * @return SecurityComponents holder for the authentication manager
	 */
	@Override
	public SecurityComponents createSecurityComponents() {
		return new SecurityComponents(new AuthenticationManager() {
			@Override
			public Authentication authenticate(Authentication authentication) throws AuthenticationException {
				if (authentication instanceof AnonymousAuthenticationToken) {
					return authentication;
				} else if ((authentication instanceof UsernamePasswordAuthenticationToken) && Boolean.TRUE.equals(enableRestApi)) {
					return getApplicationContext().getBean(CasRestAuthenticator.class).authenticate(authentication);
				} else {
					throw new BadCredentialsException("Unexpected authentication type: " + authentication);
				}
			}
		});
	}

	/**
	 * Build the filter that will validate the service ticket returned by CAS.
	 * This filter will also wrap the original filter chain from Jenkins to
	 * preserve support for API token authentication (among other features).
	 * @return CAS filter
	 */
	@Override
	public Filter createFilter(FilterConfig filterConfig) {
		LOG.debug("Creating CAS authentication filter");
		Filter defaultFilter = super.createFilter(filterConfig);
		Filter casFilter = getApplicationContext().getBean("casFilter", ChainedServletFilter.class);
		return new ChainedServletFilter(casFilter, defaultFilter);
	}

	// ~ Stapler controller actions =====================================================================================

	/**
	 * Handles the logout processing.
	 * @param req request
	 * @param rsp response
	 * @throws IOException
	 * @throws ServletException
	 */
	@Override
	public void doLogout(StaplerRequest req, StaplerResponse rsp) throws IOException, ServletException {
		// Remove session from CAS single sign-out storage
		HttpSession session = req.getSession(false);
		if (session != null) {
			getApplicationContext().getBean(SessionMappingStorage.class).removeBySessionById(session.getId());
		}
		super.doLogout(req, rsp);
	}

	/**
	 * The login process starts from here, using the CasAuthenticationEntryPoint.
	 * @param req request
	 * @param rsp response
	 * @throws IOException
	 * @throws ServletException
	 */
	public void doCommenceLogin(StaplerRequest req, StaplerResponse rsp) throws IOException, ServletException {
		LOG.debug("Redirecting to CAS for authentication");
		getApplicationContext().getBean(CasAuthenticationEntryPoint.class).commence(req, rsp, null);
	}

	/**
	 * The login process finishes here, by firing the authenticated event.
	 * @param req request
	 * @param rsp response
	 */
	public void doFinishLogin(StaplerRequest req, StaplerResponse rsp) {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		LOG.debug("Finishing CAS login with authentication={}", authentication);
		req.getSession(); // Force session creation
		if (authentication instanceof CasAuthenticationToken) {
			SecurityListener.fireAuthenticated2(((CasAuthenticationToken) authentication).getUserDetails());
		}
	}

	// ~ SecurityRealm descriptor =======================================================================================

	@Extension
	public static final class DescriptorImpl extends Descriptor<SecurityRealm> {
		@Override
		public String getDisplayName() {
			return "CAS (Central Authentication Service)";
		}

		@RequirePOST
		public FormValidation doCheckCasServerUrl(@QueryParameter String value) throws IOException, ServletException {
			Jenkins.get().checkPermission(Jenkins.ADMINISTER);

			value = Util.fixEmptyAndTrim(value);
			if (value == null)
				return FormValidation.error(Messages.CasSecurityRealm_casServerUrl_missingUrl());

			try {
				URL url = new URL(StringUtils.stripEnd(value, "/") + "/login");
				String response = CommonUtils.getResponseFromServer(url, "UTF-8");
				if (!response.contains("username")) {
					return FormValidation.warning(Messages.CasSecurityRealm_casServerUrl_invalidResponse());
				}
			} catch (MalformedURLException e) {
				return FormValidation.error(Messages.CasSecurityRealm_casServerUrl_malformedUrl() + ": " + e.getMessage());
			} catch (RuntimeException e) {
				return FormValidation.error(Messages.CasSecurityRealm_casServerUrl_cannotGetResponse() + ": " + (e.getCause() == null ? e : e.getCause()));
			}

			return FormValidation.ok();
		}
	}

}
