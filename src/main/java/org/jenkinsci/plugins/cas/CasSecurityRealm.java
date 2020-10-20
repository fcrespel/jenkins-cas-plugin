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

import org.acegisecurity.Authentication;
import org.acegisecurity.AuthenticationException;
import org.acegisecurity.AuthenticationManager;
import org.acegisecurity.BadCredentialsException;
import org.acegisecurity.context.SecurityContextHolder;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import org.acegisecurity.providers.anonymous.AnonymousAuthenticationToken;
import org.apache.commons.lang.StringUtils;
import org.jasig.cas.client.util.CommonUtils;
import org.jenkinsci.plugins.cas.spring.security.AcegiAuthenticationManager;
import org.jenkinsci.plugins.cas.spring.security.CasAuthentication;
import org.jenkinsci.plugins.cas.spring.security.CasRestAuthenticator;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.StaplerResponse;
import org.kohsuke.stapler.interceptor.RequirePOST;
import org.springframework.security.cas.ServiceProperties;
import org.springframework.security.cas.authentication.CasAuthenticationToken;
import org.springframework.security.web.util.UrlUtils;

import hudson.Extension;
import hudson.Util;
import hudson.model.Descriptor;
import hudson.security.ChainedServletFilter;
import hudson.security.SecurityRealm;
import hudson.util.FormValidation;
import jenkins.model.Jenkins;
import jenkins.security.SecurityListener;
import org.jasig.cas.client.session.HashMapBackedSessionMappingStorage;
import org.jasig.cas.client.session.SingleSignOutHandler;
import org.jasig.cas.client.validation.AbstractUrlBasedTicketValidator;
import org.jasig.cas.client.validation.TicketValidator;
import org.jenkinsci.plugins.cas.spring.CasEventListener;
import org.jenkinsci.plugins.cas.spring.security.CasAuthenticationEntryPoint;
import org.jenkinsci.plugins.cas.spring.security.CasSingleSignOutFilter;
import org.jenkinsci.plugins.cas.spring.security.CasUserDetailsService;
import org.jenkinsci.plugins.cas.spring.security.DynamicServiceAuthenticationDetailsSource;
import org.jenkinsci.plugins.cas.spring.security.SessionUrlAuthenticationSuccessHandler;
import org.springframework.security.authentication.DefaultAuthenticationEventPublisher;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.cas.authentication.CasAuthenticationProvider;
import org.springframework.security.cas.web.CasAuthenticationFilter;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;

/**
 * CAS Single Sign-On security realm.
 * 
 * @see <a href="https://www.apereo.org/projects/cas">Apereo CAS project</a>
 * @author Fabien Crespel
 * @author J. David Beutel
 */
public class CasSecurityRealm extends SecurityRealm {

	public static final String DEFAULT_COMMENCE_LOGIN_URL = "securityRealm/commenceLogin";
	public static final String DEFAULT_FINISH_LOGIN_URL = "securityRealm/finishLogin";
	public static final String DEFAULT_FAILED_LOGIN_URL = "securityRealm/failedLogin";

	public final String casServerUrl;
	public final CasProtocol casProtocol;
	public final Boolean forceRenewal;
	public final Boolean enableSingleSignOut;
	public final Boolean enableRestApi;

	private transient CasAuthenticationEntryPoint casAuthenticationEntryPoint;
    private transient HashMapBackedSessionMappingStorage casSessionMappingStorage;
    private transient ChainedServletFilter casFilter;
    private transient CasRestAuthenticator casRestAuthenticator;

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
		return Jenkins.getInstance().getRootUrl();
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
	 */
	protected void init() {
		if (casAuthenticationEntryPoint == null) {
            CasEventListener casEventListener;
            { // TODO How can this be used? With the DefaultAuthenticationEventPublisher below?
                casEventListener = new CasEventListener();
                casEventListener.setFullNameAttribute(casProtocol.getFullNameAttribute());
                casEventListener.setEmailAttribute(casProtocol.getEmailAttribute());
            }
            ServiceProperties casServiceProperties;
            {
                casServiceProperties = casProtocol.createServiceProperties();
                casServiceProperties.setSendRenew(forceRenewal);
                casServiceProperties.setService(getFinishLoginUrl());
            }
            TicketValidator casTicketValidator;
            {
                casTicketValidator = casProtocol.createTicketValidator(casServerUrl);
                ((AbstractUrlBasedTicketValidator) casTicketValidator).setRenew(forceRenewal);
            }
            CasUserDetailsService casAuthenticationUserDetailsService;
            {
                casAuthenticationUserDetailsService = new CasUserDetailsService();
                casAuthenticationUserDetailsService.setAttributes(casProtocol.getAuthoritiesAttributes());
                casAuthenticationUserDetailsService.setConvertToUpperCase(false);
                casAuthenticationUserDetailsService.setDefaultAuthorities(new String[] {AUTHENTICATED_AUTHORITY.getAuthority()});
            }
            CasAuthenticationProvider casAuthenticationProvider;
            {
                casAuthenticationProvider = new CasAuthenticationProvider();
                casAuthenticationProvider.setTicketValidator(casTicketValidator);
                casAuthenticationProvider.setAuthenticationUserDetailsService(casAuthenticationUserDetailsService);
                casAuthenticationProvider.setKey("cas_auth_provider");
            }
            ProviderManager casAuthenticationManager;
            {
                casAuthenticationManager = new ProviderManager(casAuthenticationProvider);
                casAuthenticationManager.setAuthenticationEventPublisher(new DefaultAuthenticationEventPublisher());
            }
            {
                casAuthenticationEntryPoint = new CasAuthenticationEntryPoint();
                casAuthenticationEntryPoint.setLoginUrl(casServerUrl + "login");
                casAuthenticationEntryPoint.setServiceProperties(casServiceProperties);
                casAuthenticationEntryPoint.setTargetUrlParameter("from");
                casAuthenticationEntryPoint.setTargetUrlSessionAttribute(SessionUrlAuthenticationSuccessHandler.DEFAULT_TARGET_URL_SESSION_ATTRIBUTE);
            }
            DynamicServiceAuthenticationDetailsSource casAuthenticationDetailsSource;
            {
                casAuthenticationDetailsSource = new DynamicServiceAuthenticationDetailsSource(casServiceProperties);
            }
            {
                casSessionMappingStorage = new HashMapBackedSessionMappingStorage();
            }
            SecurityContextPersistenceFilter securityContextPersistenceFilter;
            {
                HttpSessionSecurityContextRepository httpSessionSecurityContextRepository = new HttpSessionSecurityContextRepository();
                httpSessionSecurityContextRepository.setAllowSessionCreation(false);
                // TODO restricted: securityContextPersistenceFilter = new HttpSessionContextIntegrationFilter2(httpSessionSecurityContextRepository);
                securityContextPersistenceFilter = new SecurityContextPersistenceFilter(httpSessionSecurityContextRepository);
            }
            CasSingleSignOutFilter casSingleSignOutFilter;
            {
                casSingleSignOutFilter = new CasSingleSignOutFilter();
                casSingleSignOutFilter.setEnabled(enableSingleSignOut);
                casSingleSignOutFilter.setFilterProcessesUrl("/" + getFinishLoginUrl());
                SingleSignOutHandler singleSignOutHandler;
                {
                    singleSignOutHandler = new SingleSignOutHandler();
                    singleSignOutHandler.setArtifactParameterName(casProtocol.getArtifactParameter());
                    // TODO nonexistent: singleSignOutHandler.setCasServerUrlPrefix(casServerUrl);
                    singleSignOutHandler.setSessionMappingStorage(casSessionMappingStorage);
                }
                casSingleSignOutFilter.setSingleSignOutHandler(singleSignOutHandler);
            }
            CasAuthenticationFilter casAuthenticationFilter;
            {
                casAuthenticationFilter = new CasAuthenticationFilter();
                casAuthenticationFilter.setFilterProcessesUrl("/" + getFinishLoginUrl());
                casAuthenticationFilter.setAuthenticationManager(casAuthenticationManager);
                casAuthenticationFilter.setAuthenticationDetailsSource(casAuthenticationDetailsSource);
                casAuthenticationFilter.setServiceProperties(casServiceProperties);
                casAuthenticationFilter.setAuthenticationFailureHandler(new SimpleUrlAuthenticationFailureHandler("/" + getFailedLoginUrl()));
                casAuthenticationFilter.setAuthenticationSuccessHandler(new SessionUrlAuthenticationSuccessHandler("/"));
                casAuthenticationFilter.setContinueChainBeforeSuccessfulAuthentication(true);
            }
            {
                casFilter = new ChainedServletFilter(securityContextPersistenceFilter, casSingleSignOutFilter, casAuthenticationFilter);
            }
            {
                casRestAuthenticator = new CasRestAuthenticator();
                casRestAuthenticator.setCasServerUrl(casServerUrl);
                casRestAuthenticator.setAuthenticationManager(casAuthenticationManager);
                casRestAuthenticator.setAuthenticationDetailsSource(casAuthenticationDetailsSource);
            }
		}
	}

	/**
	 * Get or create the CAS REST client for API authentication.
	 * @return CAS REST authenticator
	 */
	protected CasRestAuthenticator getCasRestAuthenticator() {
        init();
		return casRestAuthenticator;
	}

	/**
	 * Check if the CAS REST API is enabled.
	 * @return true if enabled
	 */
	protected boolean isRestApiEnabled() {
		return Boolean.TRUE.equals(enableRestApi);
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
				} else if ((authentication instanceof UsernamePasswordAuthenticationToken) && isRestApiEnabled()) {
					return new AcegiAuthenticationManager(getCasRestAuthenticator()).authenticate(authentication);
				} else {
					throw new BadCredentialsException("Unexpected authentication type: " + authentication);
				}
			}
		});
	}

	/**
	 * Build the filter that will validate the service ticket returned by CAS.
	 * This filter, defined in the CasSecurityRealm.groovy application context,
	 * will wrap the original filter chain from Jenkins to preserve support for
	 * API token authentication (among other features).
	 * @return CAS filter
	 */
	@Override
	public Filter createFilter(FilterConfig filterConfig) {
		Filter defaultFilter = super.createFilter(filterConfig);
        init();
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
		// Clear Spring Security context
		org.springframework.security.core.context.SecurityContextHolder.clearContext();

		// Remove session from CAS single sign-out storage
		HttpSession session = req.getSession(false);
		if (session != null) {
            init();
			casSessionMappingStorage.removeBySessionById(session.getId());
		}

		super.doLogout(req, rsp);
	}

	/**
	 * The login process starts from here, using the CasAuthenticationEntryPoint
	 * defined in the CasSecurityRealm.groovy application context.
	 * @param req request
	 * @param rsp response
	 * @throws IOException
	 * @throws ServletException
	 */
	public void doCommenceLogin(StaplerRequest req, StaplerResponse rsp) throws IOException, ServletException {
        init();
		casAuthenticationEntryPoint.commence(req, rsp, null);
	}

	/**
	 * The login process finishes here, by mapping the Spring Security
	 * authentication back to Acegi and by firing the authenticated event.
	 * @param req request
	 * @param rsp response
	 */
	public void doFinishLogin(StaplerRequest req, StaplerResponse rsp) {
		org.springframework.security.core.Authentication authentication = org.springframework.security.core.context.SecurityContextHolder.getContext().getAuthentication();
		if (authentication instanceof CasAuthenticationToken) {
			org.springframework.security.core.context.SecurityContextHolder.clearContext();
			CasAuthenticationToken casToken = (CasAuthenticationToken) authentication;
			CasAuthentication casAuth = CasAuthentication.newInstance(casToken);
			SecurityContextHolder.getContext().setAuthentication(casAuth);
			SecurityListener.fireAuthenticated(casAuth.getUserDetails());
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
			Jenkins.getInstance().checkPermission(Jenkins.ADMINISTER);

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
