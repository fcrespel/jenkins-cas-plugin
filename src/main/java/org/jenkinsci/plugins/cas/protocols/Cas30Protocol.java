package org.jenkinsci.plugins.cas.protocols;

import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang.StringUtils;
import org.jasig.cas.client.validation.Cas30ProxyTicketValidator;
import org.jasig.cas.client.validation.Cas30ServiceTicketValidator;
import org.jasig.cas.client.validation.ProxyList;
import org.jasig.cas.client.validation.TicketValidator;
import org.jenkinsci.plugins.cas.CasProtocol;
import org.kohsuke.stapler.DataBoundConstructor;

import hudson.Extension;
import hudson.Util;
import hudson.model.Descriptor;

/**
 * CAS 3.0 protocol support.
 * 
 * @author Fabien Crespel
 */
public class Cas30Protocol extends CasProtocol {

	public final Boolean proxyEnabled;
	public final Boolean proxyAllowAny;
	public final String proxyAllowList;

	@DataBoundConstructor
	public Cas30Protocol(String authoritiesAttribute, String fullNameAttribute, String emailAttribute, Boolean proxyEnabled, Boolean proxyAllowAny, String proxyAllowList) {
		this.authoritiesAttribute = Util.fixEmptyAndTrim(authoritiesAttribute);
		this.fullNameAttribute = Util.fixEmptyAndTrim(fullNameAttribute);
		this.emailAttribute = Util.fixEmptyAndTrim(emailAttribute);
		this.proxyEnabled = proxyEnabled;
		this.proxyAllowAny = proxyAllowAny;
		this.proxyAllowList = proxyAllowList;
	}

	@Override
	public TicketValidator createTicketValidator(String casServerUrl) {
		if (this.proxyEnabled != null && this.proxyEnabled) {
			Cas30ProxyTicketValidator ptv = new Cas30ProxyTicketValidator(casServerUrl);
			ptv.setAcceptAnyProxy(this.proxyAllowAny);
			String[] proxyChain = StringUtils.split(this.proxyAllowList, '\n');
			if (proxyChain != null && proxyChain.length > 0) {
				List<String[]> proxyList = new ArrayList<String[]>(1);
				proxyList.add(proxyChain);
				ptv.setAllowedProxyChains(new ProxyList(proxyList));
			}
			return ptv;
		} else {
			return new Cas30ServiceTicketValidator(casServerUrl);
		}
	}

	@Extension
	public static final class DescriptorImpl extends Descriptor<CasProtocol> {
		@Override
		public String getDisplayName() {
			return "CAS 3.0";
		}
	}

}
