package org.jenkinsci.plugins.cas;

import java.util.Arrays;
import java.util.List;

import org.apache.commons.lang.StringUtils;
import org.jasig.cas.client.validation.TicketValidator;
import org.springframework.security.cas.ServiceProperties;

import hudson.DescriptorExtensionList;
import hudson.ExtensionPoint;
import hudson.Util;
import hudson.model.AbstractDescribableImpl;
import hudson.model.Descriptor;
import jenkins.model.Jenkins;

/**
 * CAS protocol extension point. The protocol determines how to validate
 * a server response, and may define specific configuration options.
 * 
 * @author Fabien Crespel
 */
public abstract class CasProtocol extends AbstractDescribableImpl<CasProtocol> implements ExtensionPoint {

	public final String authoritiesAttribute;
	public final String fullNameAttribute;
	public final String emailAttribute;

	protected transient String artifactParameter = null;
	protected transient List<String> authoritiesAttributes = null;

	protected CasProtocol() {
		this(null, null, null);
	}

	protected CasProtocol(String authoritiesAttribute) {
		this(authoritiesAttribute, null, null);
	}

	protected CasProtocol(String authoritiesAttribute, String fullNameAttribute, String emailAttribute) {
		this.authoritiesAttribute = Util.fixEmptyAndTrim(authoritiesAttribute);
		this.fullNameAttribute = Util.fixEmptyAndTrim(fullNameAttribute);
		this.emailAttribute = Util.fixEmptyAndTrim(emailAttribute);
	}

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
	public List<String> getAuthoritiesAttributes() {
		if (authoritiesAttributes == null) {
			authoritiesAttributes = Arrays.asList(StringUtils.split(getAuthoritiesAttribute(), ","));
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
		return Jenkins.get().<CasProtocol, Descriptor<CasProtocol>> getDescriptorList(CasProtocol.class);
	}

}
