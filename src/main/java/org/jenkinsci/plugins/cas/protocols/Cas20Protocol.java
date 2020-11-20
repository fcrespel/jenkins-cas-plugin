package org.jenkinsci.plugins.cas.protocols;

import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang.StringUtils;
import org.jasig.cas.client.validation.Cas20ProxyTicketValidator;
import org.jasig.cas.client.validation.Cas20ServiceTicketValidator;
import org.jasig.cas.client.validation.ProxyList;
import org.jasig.cas.client.validation.TicketValidator;
import org.jenkinsci.plugins.cas.CasProtocol;
import org.kohsuke.stapler.DataBoundConstructor;

import hudson.Extension;
import hudson.model.Descriptor;

/**
 * CAS 2.0 protocol support.
 * 
 * @author Fabien Crespel
 */
public class Cas20Protocol extends CasProtocol {

	public final Boolean proxyEnabled;
	public final Boolean proxyAllowAny;
	public final String proxyAllowList;

	@Deprecated
	public Cas20Protocol(String authoritiesAttribute, String fullNameAttribute, String emailAttribute) {
		this(authoritiesAttribute, fullNameAttribute, emailAttribute, false, true, null);
	}

	@DataBoundConstructor
	public Cas20Protocol(String authoritiesAttribute, String fullNameAttribute, String emailAttribute, Boolean proxyEnabled, Boolean proxyAllowAny, String proxyAllowList) {
		super(authoritiesAttribute, fullNameAttribute, emailAttribute);
		this.proxyEnabled = proxyEnabled;
		this.proxyAllowAny = proxyAllowAny;
		this.proxyAllowList = proxyAllowList;
	}

	@Override
	public TicketValidator createTicketValidator(String casServerUrl) {
		if (this.proxyEnabled != null && this.proxyEnabled) {
			Cas20ProxyTicketValidator ptv = new Cas20ProxyTicketValidator(casServerUrl);
			ptv.setAcceptAnyProxy(this.proxyAllowAny);
			String[] proxyChain = StringUtils.split(this.proxyAllowList, '\n');
			if (proxyChain != null && proxyChain.length > 0) {
				List<String[]> proxyList = new ArrayList<String[]>(1);
				proxyList.add(proxyChain);
				ptv.setAllowedProxyChains(new ProxyList(proxyList));
			}
			return ptv;
		} else {
			return new Cas20ServiceTicketValidator(casServerUrl);
		}
	}

	@Extension
	public static final class DescriptorImpl extends Descriptor<CasProtocol> {
		@Override
		public String getDisplayName() {
			return "CAS 2.0";
		}
	}

}
