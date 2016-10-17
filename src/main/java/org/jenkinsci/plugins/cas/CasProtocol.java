package org.jenkinsci.plugins.cas;

import hudson.DescriptorExtensionList;
import hudson.ExtensionPoint;
import hudson.model.AbstractDescribableImpl;
import hudson.model.Descriptor;
import jenkins.model.Jenkins;

import org.apache.commons.lang.StringUtils;
import org.jasig.cas.client.validation.TicketValidator;
import org.springframework.security.cas.ServiceProperties;

/**
 * CAS protocol extension point. The protocol determines how to validate
 * a server response, and may define specific configuration options.
 * 
 * @author Fabien Crespel
 */
public abstract class CasProtocol extends AbstractDescribableImpl<CasProtocol> implements ExtensionPoint {

	protected transient String artifactParameter = null;
	protected transient String[] authoritiesAttributes = null;
	protected String authoritiesAttribute = null;
	protected String fullNameAttribute = null;
	protected String emailAttribute = null;

	/**
	 * @return the artifactParameter
	 */
	public String getArtifactParameter() {
		if (artifactParameter == null) {
			artifactParameter = createServiceProperties().getArtifactParameter();
		}
		return artifactParameter;
	}

	/**
	 * @return the authoritiesAttribute
	 */
	public String getAuthoritiesAttribute() {
		return authoritiesAttribute;
	}

	/**
	 * @return the authoritiesAttributes
	 */
	public String[] getAuthoritiesAttributes() {
		if (authoritiesAttributes == null) {
			authoritiesAttributes = StringUtils.split(getAuthoritiesAttribute(), ",");
		}
		return authoritiesAttributes;
	}

	/**
	 * @return the fullNameAttribute
	 */
	public String getFullNameAttribute() {
		return fullNameAttribute;
	}

	/**
	 * @return the emailAttribute
	 */
	public String getEmailAttribute() {
		return emailAttribute;
	}

	/**
	 * Create a ServiceProperties object describing the CAS service.
	 * @return ServiceProperties
	 */
	public ServiceProperties createServiceProperties() {
		return new ServiceProperties();
	}

	/**
	 * Create a TicketValidator used to validate a CAS response.
	 * @param casServerUrl CAS server URL prefix
	 * @return TicketValidator
	 */
	public abstract TicketValidator createTicketValidator(String casServerUrl);

	/**
	 * Returns all the registered {@link CasProtocol} descriptors.
	 * @return all {@link CasProtocol} descriptors
	 */
	public static DescriptorExtensionList<CasProtocol, Descriptor<CasProtocol>> all() {
		return Jenkins.getInstance().<CasProtocol, Descriptor<CasProtocol>> getDescriptorList(CasProtocol.class);
	}

}
