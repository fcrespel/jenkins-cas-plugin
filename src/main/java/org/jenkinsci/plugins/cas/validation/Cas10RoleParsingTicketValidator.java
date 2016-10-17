package org.jenkinsci.plugins.cas.validation;

import groovy.lang.GroovyShell;
import groovy.lang.Script;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.lang.StringUtils;
import org.jasig.cas.client.authentication.AttributePrincipal;
import org.jasig.cas.client.authentication.AttributePrincipalImpl;
import org.jasig.cas.client.validation.AbstractCasProtocolUrlBasedTicketValidator;
import org.jasig.cas.client.validation.Assertion;
import org.jasig.cas.client.validation.AssertionImpl;
import org.jasig.cas.client.validation.TicketValidationException;

/**
 * Implementation of a Ticket Validator that can validate tickets conforming to the CAS 1.0 specification.
 * This implementation also allows parsing roles from a custom extension with a Groovy script.
 *
 * @author Scott Battaglia
 * @author Fabien Crespel
 */
public class Cas10RoleParsingTicketValidator extends AbstractCasProtocolUrlBasedTicketValidator {

	public static final String DEFAULT_ROLE_ATTRIBUTE = "roles";

	private String rolesValidationScript;
	private String rolesAttribute = DEFAULT_ROLE_ATTRIBUTE;
	private Script parsedScript;

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

			List<String> roles = parseRolesFromValidationResponse(getParsedScript(), response);
			if (roles != null) {
				Map<String, Object> attributes = new HashMap<String, Object>(1);
				attributes.put(rolesAttribute, roles);
				AttributePrincipal principal = new AttributePrincipalImpl(name, attributes);
				return new AssertionImpl(principal);
			} else {
				return new AssertionImpl(name);
			}

		} catch (final IOException e) {
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
	public static List<String> parseRolesFromValidationResponse(Script script, String response) {
		if (script == null)
			return null;

		// Run the script to parse the response
		script.getBinding().setVariable("response", response);
		Collection coll = (Collection) script.run();
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
	 * Get the parsed Groovy roles validation script.
	 * @return parsed Groovy script
	 */
	protected synchronized Script getParsedScript() {
		if (parsedScript == null && StringUtils.isNotEmpty(rolesValidationScript)) {
			parsedScript = new GroovyShell().parse(rolesValidationScript);
		}
		return parsedScript;
	}

	/**
	 * @return the rolesValidationScript
	 */
	public String getRolesValidationScript() {
		return rolesValidationScript;
	}

	/**
	 * @param rolesValidationScript the rolesValidationScript to set
	 */
	public void setRolesValidationScript(String rolesValidationScript) {
		this.rolesValidationScript = rolesValidationScript;
		this.parsedScript = null;
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
