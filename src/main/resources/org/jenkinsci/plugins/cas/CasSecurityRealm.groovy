import hudson.security.ChainedServletFilter
import hudson.security.HttpSessionContextIntegrationFilter2
import hudson.security.SecurityRealm

import org.jasig.cas.client.session.HashMapBackedSessionMappingStorage;
import org.jasig.cas.client.session.SingleSignOutFilter
import org.jenkinsci.plugins.cas.spring.CasBeanFactory
import org.jenkinsci.plugins.cas.spring.CasEventListener
import org.jenkinsci.plugins.cas.spring.security.CasAuthenticationFilter
import org.jenkinsci.plugins.cas.spring.security.CasSingleSignOutFilter
import org.jenkinsci.plugins.cas.spring.security.CasUserDetailsService
import org.springframework.security.authentication.ProviderManager
import org.springframework.security.cas.authentication.CasAuthenticationProvider
import org.springframework.security.cas.web.CasAuthenticationEntryPoint
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler


casEventListener(CasEventListener) {
	fullNameAttribute = casProtocol.fullNameAttribute
	emailAttribute = casProtocol.emailAttribute
}

casBeanFactory(CasBeanFactory) {
	casServerUrl = securityRealm.casServerUrl
	casProtocol = casProtocol
}

casServiceProperties(casBeanFactory: "createServiceProperties") {
	sendRenew = securityRealm.forceRenewal
	service = securityRealm.jenkinsUrl + securityRealm.finishLoginUrl
}

casTicketValidator(casBeanFactory: "createTicketValidator")

casAuthenticationUserDetailsService(CasUserDetailsService) {
	attributes = casProtocol.authoritiesAttributes
	convertToUpperCase = false
	defaultAuthorities = [ SecurityRealm.AUTHENTICATED_AUTHORITY.getAuthority() ]
}

casAuthenticationManager(ProviderManager) {
	providers = [
		bean(CasAuthenticationProvider) {
			serviceProperties = casServiceProperties
			ticketValidator = casTicketValidator
			authenticationUserDetailsService = casAuthenticationUserDetailsService
			key = "cas_auth_provider"
		}
	]
}

casAuthenticationEntryPoint(CasAuthenticationEntryPoint) {
	loginUrl = securityRealm.casServerUrl + "login"
	serviceProperties = casServiceProperties
}

casSessionMappingStorage(HashMapBackedSessionMappingStorage)

casFilter(ChainedServletFilter) {
	filters = [
		bean(HttpSessionContextIntegrationFilter2) {
			allowSessionCreation = false;
		},
		bean(CasSingleSignOutFilter) {
			enabled = securityRealm.enableSingleSignOut
			filterProcessesUrl = "/" + securityRealm.finishLoginUrl
			singleSignOutFilter = bean(SingleSignOutFilter) {
				artifactParameterName = casProtocol.artifactParameter
				sessionMappingStorage = casSessionMappingStorage
			}
		},
		bean(CasAuthenticationFilter) {
			filterProcessesUrl = "/" + securityRealm.finishLoginUrl
			authenticationManager = casAuthenticationManager
			serviceProperties = casServiceProperties
			authenticationSuccessHandler = bean(SimpleUrlAuthenticationSuccessHandler, "/")
			authenticationFailureHandler = bean(SimpleUrlAuthenticationFailureHandler, "/loginError")
		}
	]
}
