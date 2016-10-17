package org.jenkinsci.plugins.cas.protocols;

import groovy.lang.GroovyShell;
import groovy.lang.Script;
import hudson.Extension;
import hudson.Util;
import hudson.model.Descriptor;
import hudson.util.FormValidation;

import java.util.Collection;

import org.codehaus.groovy.control.CompilationFailedException;
import org.jasig.cas.client.validation.TicketValidator;
import org.jenkinsci.plugins.cas.CasProtocol;
import org.jenkinsci.plugins.cas.Messages;
import org.jenkinsci.plugins.cas.validation.Cas10RoleParsingTicketValidator;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;

/**
 * CAS 1.0 protocol support.
 * 
 * @author Fabien Crespel
 * @author J. David Beutel
 */
public class Cas10Protocol extends CasProtocol {

	public final String rolesValidationScript;
	public final String testValidationResponse;

	@DataBoundConstructor
	public Cas10Protocol(String rolesValidationScript, String testValidationResponse) {
		this.rolesValidationScript = Util.fixEmptyAndTrim(rolesValidationScript);
		this.testValidationResponse = Util.fixEmpty(testValidationResponse);
	}

	@Override
	public String getAuthoritiesAttribute() {
		return Cas10RoleParsingTicketValidator.DEFAULT_ROLE_ATTRIBUTE;
	}

	@Override
	public TicketValidator createTicketValidator(String casServerUrl) {
		Cas10RoleParsingTicketValidator ticketValidator = new Cas10RoleParsingTicketValidator(casServerUrl);
		ticketValidator.setRolesValidationScript(rolesValidationScript);
		return ticketValidator;
	}

	@Extension
	public static final class DescriptorImpl extends Descriptor<CasProtocol> {
		@Override
		public String getDisplayName() {
			return "CAS 1.0";
		}

		@SuppressWarnings("rawtypes")
		public FormValidation doTestScript(
				@QueryParameter("rolesValidationScript") final String rolesValidationScript,
				@QueryParameter("testValidationResponse") final String testValidationResponse) {
			try {
				Script script = new GroovyShell().parse(rolesValidationScript);
				Collection roles = Cas10RoleParsingTicketValidator.parseRolesFromValidationResponse(script, testValidationResponse);
				if (roles == null) {
					return FormValidation.error(Messages.Cas10Protocol_rolesValidationScript_noResult());
				}
				return FormValidation.ok(Messages.Cas10Protocol_rolesValidationScript_result() + ": " + roles);
			} catch (CompilationFailedException e) {
				return FormValidation.error(Messages.Cas10Protocol_rolesValidationScript_compilationError() + ": " + e);
			} catch (ClassCastException e) {
				return FormValidation.error(Messages.Cas10Protocol_rolesValidationScript_returnTypeError() + ": " + e);
			}
		}
	}

}
