package org.jenkinsci.plugins.cas.spring.security;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.util.StringUtils;

/**
 * <tt>AuthenticationSuccessHandler</tt> that behaves like <tt>SimpleUrlAuthenticationSuccessHandler</tt>,
 * but also looks for a configurable session attribute holding the target URL to redirect to.
 * 
 * @author Fabien Crespel
 */
public class SessionUrlAuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

	public static final String DEFAULT_TARGET_URL_SESSION_ATTRIBUTE = "spring-security-redirect";

	private String targetUrlSessionAttribute = DEFAULT_TARGET_URL_SESSION_ATTRIBUTE;

	/**
	 * Constructor which sets the <tt>defaultTargetUrl</tt> property of the base class.
	 * @param defaultTargetUrl the URL to which the user should be redirected on successful authentication.
	 */
	public SessionUrlAuthenticationSuccessHandler(String defaultTargetUrl) {
		super(defaultTargetUrl);
	}

	/**
	 * Builds the target URL according to the logic defined in the main class Javadoc.
	 */
	protected String determineTargetUrl(HttpServletRequest request, HttpServletResponse response) {
		String targetUrl = null;
		HttpSession session = request.getSession(false);
		if (session != null && targetUrlSessionAttribute != null) {
			targetUrl = (String) session.getAttribute(targetUrlSessionAttribute);
			session.removeAttribute(targetUrlSessionAttribute);
		}

		if (isAlwaysUseDefaultTargetUrl() || StringUtils.hasText(request.getParameter(getTargetUrlParameter())) || !StringUtils.hasText(targetUrl)) {
			return super.determineTargetUrl(request, response);
		}

		logger.debug("Found targetUrlSessionAttribute in request: " + targetUrl);

		// URL returned from determineTargetUrl() is resolved against the context path,
		// whereas the "from" URL is resolved against the top of the website, so adjust this.
		if (targetUrl.startsWith(request.getContextPath()))
			return targetUrl.substring(request.getContextPath().length());

		return targetUrl;
	}

	/**
	 * @return the targetUrlSessionAttribute
	 */
	public String getTargetUrlSessionAttribute() {
		return targetUrlSessionAttribute;
	}

	/**
	 * @param targetUrlSessionAttribute the targetUrlSessionAttribute to set
	 */
	public void setTargetUrlSessionAttribute(String targetUrlSessionAttribute) {
		this.targetUrlSessionAttribute = targetUrlSessionAttribute;
	}

}
