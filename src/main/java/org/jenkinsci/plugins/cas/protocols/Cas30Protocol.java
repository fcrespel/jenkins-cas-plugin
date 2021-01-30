package org.jenkinsci.plugins.cas.protocols;

import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang.StringUtils;
import org.jasig.cas.client.validation.Cas30ProxyTicketValidator;
import org.jasig.cas.client.validation.Cas30ServiceTicketValidator;
import org.jasig.cas.client.validation.ProxyList;
import org.jasig.cas.client.validation.TicketValidator;
import org.jasig.cas.client.validation.json.Cas30JsonProxyTicketValidator;
import org.jasig.cas.client.validation.json.Cas30JsonServiceTicketValidator;
import org.jenkinsci.plugins.cas.CasProtocol;
import org.kohsuke.stapler.DataBoundConstructor;

import hudson.Extension;
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
	public final Boolean jsonEnabled;

	@Deprecated
	public Cas30Protocol(String authoritiesAttribute, String fullNameAttribute, String emailAttribute, Boolean proxyEnabled, Boolean proxyAllowAny, String proxyAllowList) {
		this(authoritiesAttribute, fullNameAttribute, emailAttribute, proxyEnabled, proxyAllowAny, proxyAllowList, false);
	}

	@Deprecated
	public Cas30Protocol(String authoritiesAttribute, String fullNameAttribute, String emailAttribute, Boolean proxyEnabled, Boolean proxyAllowAny, String proxyAllowList, Boolean jsonEnabled) {
		this(authoritiesAttribute, fullNameAttribute, emailAttribute, null, proxyEnabled, proxyAllowAny, proxyAllowList, jsonEnabled);
	}

	@DataBoundConstructor
	public Cas30Protocol(String authoritiesAttribute, String fullNameAttribute, String emailAttribute, String customValidationParams, Boolean proxyEnabled, Boolean proxyAllowAny, String proxyAllowList, Boolean jsonEnabled) {
		super(authoritiesAttribute, fullNameAttribute, emailAttribute, customValidationParams);
		this.proxyEnabled = proxyEnabled;
		this.proxyAllowAny = proxyAllowAny;
		this.proxyAllowList = proxyAllowList;
		this.jsonEnabled = jsonEnabled;
	}

	@Override
	public TicketValidator createTicketValidator(String casServerUrl) {
		if (this.proxyEnabled != null && this.proxyEnabled) {
			Cas30ProxyTicketValidator ptv;
			if (Boolean.TRUE.equals(this.jsonEnabled)) {
				ptv = new Cas30JsonProxyTicketValidator(casServerUrl);
			} else {
				ptv = new Cas30ProxyTicketValidator(casServerUrl);
			}
			ptv.setCustomParameters(getCustomValidationParamsMap());
			ptv.setAcceptAnyProxy(this.proxyAllowAny);
			String[] proxyChain = StringUtils.split(this.proxyAllowList, '\n');
			if (proxyChain != null && proxyChain.length > 0) {
				List<String[]> proxyList = new ArrayList<String[]>(1);
				proxyList.add(proxyChain);
				ptv.setAllowedProxyChains(new ProxyList(proxyList));
			}
			return ptv;
		} else {
			Cas30ServiceTicketValidator stv;
			if (Boolean.TRUE.equals(this.jsonEnabled)) {
				stv = new Cas30JsonServiceTicketValidator(casServerUrl);
			} else {
				stv = new Cas30ServiceTicketValidator(casServerUrl);
			}
			stv.setCustomParameters(getCustomValidationParamsMap());
			return stv;
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
