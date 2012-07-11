package org.jenkinsci.plugins.cas.spring;

import org.jasig.cas.client.validation.TicketValidator;
import org.jenkinsci.plugins.cas.CasProtocol;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.cas.ServiceProperties;
import org.springframework.util.Assert;

/**
 * CAS-related bean factory relying on a CasProtocol backing implementation.
 * 
 * @author Fabien Crespel <fabien@crespel.net>
 */
public class CasBeanFactory implements InitializingBean {

	private String casServerUrl;
	private CasProtocol casProtocol;

	/*
	 * (non-Javadoc)
	 * @see org.springframework.beans.factory.InitializingBean#afterPropertiesSet()
	 */
	public void afterPropertiesSet() throws Exception {
		Assert.notNull(casServerUrl, "casServerUrl cannot be null");
		Assert.notNull(casProtocol, "casProtocol cannot be null");
	}

	/**
	 * Create a ServiceProperties object describing the CAS service.
	 * @return ServiceProperties
	 */
	public ServiceProperties createServiceProperties() {
		return casProtocol.createServiceProperties();
	}

	/**
	 * Create a TicketValidator used to validate a CAS response.
	 * @return TicketValidator
	 */
	public TicketValidator createTicketValidator() {
		return casProtocol.createTicketValidator(casServerUrl);
	}

	/**
	 * @return the casServerUrl
	 */
	public String getCasServerUrl() {
		return casServerUrl;
	}

	/**
	 * @param casServerUrl the casServerUrl to set
	 */
	public void setCasServerUrl(String casServerUrl) {
		this.casServerUrl = casServerUrl;
	}

	/**
	 * @return the casProtocol
	 */
	public CasProtocol getCasProtocol() {
		return casProtocol;
	}

	/**
	 * @param casProtocol the casProtocol to set
	 */
	public void setCasProtocol(CasProtocol casProtocol) {
		this.casProtocol = casProtocol;
	}
}
