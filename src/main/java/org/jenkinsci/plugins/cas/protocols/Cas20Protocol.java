package org.jenkinsci.plugins.cas.protocols;

import hudson.Extension;
import hudson.Util;
import hudson.model.Descriptor;

import org.jasig.cas.client.validation.Cas20ServiceTicketValidator;
import org.jasig.cas.client.validation.TicketValidator;
import org.jenkinsci.plugins.cas.CasProtocol;
import org.kohsuke.stapler.DataBoundConstructor;

/**
 * CAS 2.0 protocol support.
 * 
 * @author Fabien Crespel <fabien@crespel.net>
 */
public class Cas20Protocol extends CasProtocol {

	@DataBoundConstructor
	public Cas20Protocol(String authoritiesAttribute, String fullNameAttribute, String emailAttribute) {
		this.authoritiesAttribute = Util.fixEmptyAndTrim(authoritiesAttribute);
		this.fullNameAttribute = Util.fixEmptyAndTrim(fullNameAttribute);
		this.emailAttribute = Util.fixEmptyAndTrim(emailAttribute);
	}

	@Override
	public TicketValidator createTicketValidator(String casServerUrl) {
		return new Cas20ServiceTicketValidator(casServerUrl);
	}

	@Extension
	public static final class DescriptorImpl extends Descriptor<CasProtocol> {
		@Override
		public String getDisplayName() {
			return "CAS 2.0";
		}
	}

}
