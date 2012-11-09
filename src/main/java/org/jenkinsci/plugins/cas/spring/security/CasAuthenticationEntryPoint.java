package org.jenkinsci.plugins.cas.spring.security;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

/**
 * CAS authentication entry point that will save a target URL request parameter
 * into a session attribute before redirecting.
 * 
 * @author Fabien Crespel <fabien@crespel.net>
 */
public class CasAuthenticationEntryPoint extends org.springframework.security.cas.web.CasAuthenticationEntryPoint {

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
