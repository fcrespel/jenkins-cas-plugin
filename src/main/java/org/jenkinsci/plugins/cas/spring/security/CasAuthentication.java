package org.jenkinsci.plugins.cas.spring.security;

import java.io.Serializable;

import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.GrantedAuthorityImpl;
import org.acegisecurity.providers.AbstractAuthenticationToken;
import org.acegisecurity.userdetails.User;
import org.acegisecurity.userdetails.UserDetails;
import org.jasig.cas.client.validation.Assertion;
import org.springframework.security.cas.authentication.CasAuthenticationProvider;
import org.springframework.security.cas.authentication.CasAuthenticationToken;

/**
 * Represents a successful CAS <code>Authentication</code>.
 *
 * @author Ben Alex
 * @author Scott Battaglia
 * @author Fabien Crespel
 */
public class CasAuthentication extends AbstractAuthenticationToken implements Serializable {
	//~ Instance fields ================================================================================================

	private static final long serialVersionUID = 1L;
	private final Object credentials;
	private final Object principal;
	private final UserDetails userDetails;
	private final int keyHash;
	private final Assertion assertion;

	//~ Constructors ===================================================================================================

	/**
	 * Constructor.
	 *
	 * @param key to identify if this object made by a given {@link
	 *        CasAuthenticationProvider}
	 * @param principal typically the UserDetails object (cannot  be <code>null</code>)
	 * @param credentials the service/proxy ticket ID from CAS (cannot be
	 *        <code>null</code>)
	 * @param authorities the authorities granted to the user (from the {@link
	 *        org.springframework.security.core.userdetails.UserDetailsService}) (cannot be <code>null</code>)
	 * @param userDetails the user details (from the {@link
	 *        org.springframework.security.core.userdetails.UserDetailsService}) (cannot be <code>null</code>)
	 * @param assertion the assertion returned from the CAS servers.  It contains the principal and how to obtain a
	 *        proxy ticket for the user.
	 *
	 * @throws IllegalArgumentException if a <code>null</code> was passed
	 */
	public CasAuthentication(final String key, final Object principal, final Object credentials,
			final GrantedAuthority[] authorities, final UserDetails userDetails, final Assertion assertion) {
		this(key.hashCode(), principal, credentials, authorities, userDetails, assertion);
	}

	/**
	 * Constructor.
	 *
	 * @param keyHash to identify if this object made by a given {@link
	 *        CasAuthenticationProvider}
	 * @param principal typically the UserDetails object (cannot  be <code>null</code>)
	 * @param credentials the service/proxy ticket ID from CAS (cannot be
	 *        <code>null</code>)
	 * @param authorities the authorities granted to the user (from the {@link
	 *        org.springframework.security.core.userdetails.UserDetailsService}) (cannot be <code>null</code>)
	 * @param userDetails the user details (from the {@link
	 *        org.springframework.security.core.userdetails.UserDetailsService}) (cannot be <code>null</code>)
	 * @param assertion the assertion returned from the CAS servers.  It contains the principal and how to obtain a
	 *        proxy ticket for the user.
	 *
	 * @throws IllegalArgumentException if a <code>null</code> was passed
	 */
	public CasAuthentication(final int keyHash, final Object principal, final Object credentials,
		final GrantedAuthority[] authorities, final UserDetails userDetails, final Assertion assertion) {
		super(authorities);

		if ((principal == null) || "".equals(principal) || (credentials == null)
			|| "".equals(credentials) || (authorities == null) || (userDetails == null) || (assertion == null)) {
			throw new IllegalArgumentException("Cannot pass null or empty values to constructor");
		}

		this.keyHash = keyHash;
		this.principal = principal;
		this.credentials = credentials;
		this.userDetails = userDetails;
		this.assertion = assertion;
		setAuthenticated(true);
	}

	//~ Factories ======================================================================================================

	public static CasAuthentication newInstance(CasAuthenticationToken casToken) {
		// Map granted authorities
		GrantedAuthority[] authorities = new GrantedAuthority[casToken.getAuthorities().size()];
		int i = 0;
		for (org.springframework.security.core.GrantedAuthority authority : casToken.getAuthorities()) {
			authorities[i++] = new GrantedAuthorityImpl(authority.getAuthority());
		}

		// Map user
		org.springframework.security.core.userdetails.User sourceUser = (org.springframework.security.core.userdetails.User) casToken.getUserDetails();
		User user = new User(sourceUser.getUsername(), CasUserDetailsService.NON_EXISTENT_PASSWORD_VALUE, sourceUser.isEnabled(), sourceUser.isAccountNonExpired(), sourceUser.isCredentialsNonExpired(), sourceUser.isAccountNonLocked(), authorities);

		// Build a CasAuthentication object
		return new CasAuthentication(casToken.getKeyHash(), user, casToken.getCredentials(), authorities, user, casToken.getAssertion());
	}

	//~ Methods ========================================================================================================

	public boolean equals(final Object obj) {
		if (!super.equals(obj)) {
			return false;
		}

		if (obj instanceof CasAuthentication) {
			CasAuthentication test = (CasAuthentication) obj;

			if (!this.assertion.equals(test.getAssertion())) {
				return false;
			}

			if (this.getKeyHash() != test.getKeyHash()) {
				return false;
			}

			return true;
		}

		return false;
	}

	public Object getCredentials() {
		return this.credentials;
	}

	public int getKeyHash() {
		return this.keyHash;
	}

	public Object getPrincipal() {
		return this.principal;
	}

	public Assertion getAssertion() {
		return this.assertion;
	}

	public UserDetails getUserDetails() {
		return userDetails;
	}

	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append(super.toString());
		sb.append(" Assertion: ").append(this.assertion);
		sb.append(" Credentials (Service/Proxy Ticket): ").append(this.credentials);

		return (sb.toString());
	}
}
