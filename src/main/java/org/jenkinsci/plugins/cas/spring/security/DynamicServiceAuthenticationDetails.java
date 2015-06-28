package org.jenkinsci.plugins.cas.spring.security;

import javax.servlet.http.HttpServletRequest;

import org.jenkinsci.plugins.cas.CasSecurityRealm;
import org.springframework.security.cas.ServiceProperties;
import org.springframework.security.cas.web.authentication.ServiceAuthenticationDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetails;

/**
 * {@code ServiceAuthenticationDetails} implementation that will convert a relative
 * service URL to an absolute one by adding the Jenkins root URL if necessary.
 *
 * @author Fabien Crespel <fabien@crespel.net>
 */
public class DynamicServiceAuthenticationDetails extends WebAuthenticationDetails implements ServiceAuthenticationDetails {

	private String serviceUrl;

	public DynamicServiceAuthenticationDetails(HttpServletRequest request, ServiceProperties serviceProperties) {
		super(request);
		this.serviceUrl = CasSecurityRealm.getServiceUrl(request, serviceProperties);
	}

	public String getServiceUrl() {
		return serviceUrl;
	}

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = super.hashCode();
        result = prime * result + serviceUrl.hashCode();
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!super.equals(obj) || !(obj instanceof DynamicServiceAuthenticationDetails)) {
            return false;
        }
        ServiceAuthenticationDetails that = (ServiceAuthenticationDetails) obj;
        return serviceUrl.equals(that.getServiceUrl());
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(super.toString()).append("; ");
        sb.append("ServiceUrl: ").append(serviceUrl);
        return sb.toString();
    }

}
