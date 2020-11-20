package org.jenkinsci.plugins.cas.spring.security;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.jasig.cas.client.util.CommonUtils;
import org.jenkinsci.plugins.cas.CasSecurityRealm;
import org.springframework.security.cas.web.CasAuthenticationEntryPoint;

/**
 * CAS authentication entry point that will save a target URL request parameter
 * into a session attribute before redirecting. Additionally, the service URL
 * will be made absolute by adding the Jenkins root URL if necessary.
 * 
 * @author Fabien Crespel
 */
public class SessionUrlCasAuthenticationEntryPoint extends CasAuthenticationEntryPoint {

	private String targetUrlParameter;
	private String targetUrlSessionAttribute;

	@Override
	protected void preCommence(HttpServletRequest request, HttpServletResponse response) {
		if (targetUrlParameter != null && targetUrlSessionAttribute != null) {
			String targetUrl = request.getParameter(targetUrlParameter);
			if (targetUrl != null) {
				HttpSession session = request.getSession(true);
				session.setAttribute(targetUrlSessionAttribute, targetUrl);
			}
		}
	}

	@Override
	protected String createServiceUrl(HttpServletRequest request, HttpServletResponse response) {
		String serviceUrl = CasSecurityRealm.getServiceUrl(request, getServiceProperties());
		return CommonUtils.constructServiceUrl(null, response, serviceUrl, null, getServiceProperties().getServiceParameter(), getServiceProperties().getArtifactParameter(), getEncodeServiceUrlWithSessionId());
	}

	/**
	 * @return the targetUrlParameter
	 */
	public String getTargetUrlParameter() {
		return targetUrlParameter;
	}

	/**
	 * @param targetUrlParameter the targetUrlParameter to set
	 */
	public void setTargetUrlParameter(String targetUrlParameter) {
		this.targetUrlParameter = targetUrlParameter;
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
