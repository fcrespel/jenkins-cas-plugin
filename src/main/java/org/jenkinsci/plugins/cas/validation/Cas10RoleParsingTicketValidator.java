package org.jenkinsci.plugins.cas.validation;

import java.io.BufferedReader;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.jasig.cas.client.authentication.AttributePrincipal;
import org.jasig.cas.client.authentication.AttributePrincipalImpl;
import org.jasig.cas.client.validation.AbstractCasProtocolUrlBasedTicketValidator;
import org.jasig.cas.client.validation.Assertion;
import org.jasig.cas.client.validation.AssertionImpl;
import org.jasig.cas.client.validation.TicketValidationException;
import org.jenkinsci.plugins.scriptsecurity.sandbox.groovy.SecureGroovyScript;

import groovy.lang.Binding;
import jenkins.model.Jenkins;

/**
 * Implementation of a Ticket Validator that can validate tickets conforming to the CAS 1.0 specification.
 * This implementation also allows parsing roles from a custom extension with a Groovy script.
 *
 * @author Scott Battaglia
 * @author Fabien Crespel
 */
public class Cas10RoleParsingTicketValidator extends AbstractCasProtocolUrlBasedTicketValidator {

	public static final String DEFAULT_ROLE_ATTRIBUTE = "roles";

	private SecureGroovyScript rolesValidationScript;
	private String rolesAttribute = DEFAULT_ROLE_ATTRIBUTE;

	public Cas10RoleParsingTicketValidator(final String casServerUrlPrefix) {
		super(casServerUrlPrefix);
	}

	/*
	 * (non-Javadoc)
	 * @see org.jasig.cas.client.validation.AbstractUrlBasedTicketValidator#getUrlSuffix()
	 */
	protected String getUrlSuffix() {
		return "validate";
	}

	/*
	 * (non-Javadoc)
	 * @see org.jasig.cas.client.validation.AbstractUrlBasedTicketValidator#parseResponseFromServer(java.lang.String)
	 */
	protected Assertion parseResponseFromServer(final String response) throws TicketValidationException {
		if (!response.startsWith("yes")) {
			throw new TicketValidationException("CAS Server could not validate ticket.");
		}

		try {
			final BufferedReader reader = new BufferedReader(new StringReader(response));
			reader.readLine();
			final String name = reader.readLine();

			List<String> roles = parseRolesFromValidationResponse(rolesValidationScript, response);
			if (roles != null) {
				Map<String, Object> attributes = new HashMap<String, Object>(1);
				attributes.put(rolesAttribute, roles);
				AttributePrincipal principal = new AttributePrincipalImpl(name, attributes);
				return new AssertionImpl(principal);
			} else {
				return new AssertionImpl(name);
			}

		} catch (final Exception e) {
			throw new TicketValidationException("Unable to parse response.", e);
		}
	}

	/**
	 * Parse roles from a custom CAS 1.0 validation response.
	 * @param script Groovy roles validation script
	 * @param response validation response from the CAS server
	 * @return list of roles
	 */
	@SuppressWarnings("rawtypes")
	public static List<String> parseRolesFromValidationResponse(SecureGroovyScript script, String response) throws Exception {
		if (script == null)
			return null;

		// Run the script to parse the response
		Binding binding = new Binding();
		binding.setVariable("response", response);
		Collection coll = (Collection) script.evaluate(Jenkins.getInstance().getPluginManager().uberClassLoader, binding);
		if (coll == null || coll.isEmpty())
			return null;

		// Map the collection to a safe string list
		List<String> roles = new ArrayList<String>(coll.size());
		for (Object obj : coll) {
			if (obj != null) {
				roles.add(obj.toString());
			}
		}

		return roles;
	}

	/**
	 * @return the rolesValidationScript
	 */
	public SecureGroovyScript getRolesValidationScript() {
		return rolesValidationScript;
	}

	/**
	 * @param rolesValidationScript the rolesValidationScript to set
	 */
	public void setRolesValidationScript(SecureGroovyScript rolesValidationScript) {
		this.rolesValidationScript = rolesValidationScript;
	}

	/**
	 * @return the rolesAttribute
	 */
	public String getRolesAttribute() {
		return rolesAttribute;
	}

	/**
	 * @param rolesAttribute the rolesAttribute to set
	 */
	public void setRolesAttribute(String rolesAttribute) {
		this.rolesAttribute = rolesAttribute;
	}
}
