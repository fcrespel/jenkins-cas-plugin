package org.jenkinsci.plugins.cas.protocols;

import hudson.Extension;
import hudson.Util;
import hudson.model.Descriptor;

import org.jasig.cas.client.validation.Saml11TicketValidator;
import org.jasig.cas.client.validation.TicketValidator;
import org.jenkinsci.plugins.cas.CasProtocol;
import org.kohsuke.stapler.DataBoundConstructor;
import org.springframework.security.cas.SamlServiceProperties;
import org.springframework.security.cas.ServiceProperties;

/**
 * SAML 1.1 protocol support.
 * 
 * @author Fabien Crespel <fabien@crespel.net>
 */
public class Saml11Protocol extends CasProtocol {

	public final int tolerance;

	@DataBoundConstructor
	public Saml11Protocol(String authoritiesAttribute, String fullNameAttribute, String emailAttribute, int tolerance) {
		this.authoritiesAttribute = Util.fixEmptyAndTrim(authoritiesAttribute);
		this.fullNameAttribute = Util.fixEmptyAndTrim(fullNameAttribute);
		this.emailAttribute = Util.fixEmptyAndTrim(emailAttribute);
		this.tolerance = tolerance;
	}

	@Override
	public ServiceProperties createServiceProperties() {
		return new SamlServiceProperties();
	}

	@Override
	public TicketValidator createTicketValidator(String casServerUrl) {
		Saml11TicketValidator ticketValidator = new Saml11TicketValidator(casServerUrl);
		ticketValidator.setTolerance(tolerance);
		return ticketValidator;
	}

	@Extension
	public static final class DescriptorImpl extends Descriptor<CasProtocol> {
		@Override
		public String getDisplayName() {
			return "SAML 1.1";
		}
	}

}
