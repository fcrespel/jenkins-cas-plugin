package org.jenkinsci.plugins.cas.spring.security;

import org.jasig.cas.client.validation.Assertion;
import org.springframework.security.cas.userdetails.AbstractCasAssertionUserDetailsService;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.GrantedAuthorityImpl;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.List;

/**
 * Populates the {@link org.springframework.security.core.GrantedAuthority}s for a user by reading a list of attributes that were returned as
 * part of the CAS response. Each attribute is read and each value of the attribute is turned into a GrantedAuthority. If the attribute has no
 * value then its not added.
 *
 * @author Scott Battaglia
 * @author Fabien Crespel <fabien@crespel.net>
 */
public final class CasUserDetailsService extends AbstractCasAssertionUserDetailsService {

	private static final String NON_EXISTENT_PASSWORD_VALUE = "NO_PASSWORD";

	private String[] attributes;
	private boolean convertToUpperCase = true;
	private String[] defaultAuthorities;

	@Override
	@SuppressWarnings("rawtypes")
	protected UserDetails loadUserDetails(final Assertion assertion) {
		final List<GrantedAuthority> grantedAuthorities = new ArrayList<GrantedAuthority>();

		if (this.attributes != null) {
			for (final String attribute : this.attributes) {
				final Object value = assertion.getPrincipal().getAttributes().get(attribute);

				if (value == null) {
					continue;
				}

				if (value instanceof List) {
					final List list = (List) value;

					for (final Object o : list) {
						grantedAuthorities.add(new GrantedAuthorityImpl(this.convertToUpperCase ? o.toString().toUpperCase() : o.toString()));
					}

				} else {
					grantedAuthorities.add(new GrantedAuthorityImpl(this.convertToUpperCase ? value.toString().toUpperCase() : value.toString()));
				}
			}
		}

		if (this.defaultAuthorities != null) {
			for (final String authority : this.defaultAuthorities) {
				grantedAuthorities.add(new GrantedAuthorityImpl(authority));
			}
		}

		return new User(assertion.getPrincipal().getName(), NON_EXISTENT_PASSWORD_VALUE, true, true, true, true, grantedAuthorities);
	}

	/**
	 * Get the attribute names used to extract granted authorities.
	 * @return the attributes
	 */
	public String[] getAttributes() {
		return attributes;
	}

	/**
	 * Set the attribute names used to extract granted authorities.
	 * @param attributes the attributes to set
	 */
	public void setAttributes(String[] attributes) {
		this.attributes = attributes;
	}

	/**
	 * Converts the returned attribute values to uppercase values.
	 * @return true if it should convert, false otherwise.
	 */
	public boolean isConvertToUpperCase() {
		return convertToUpperCase;
	}

	/**
	 * Converts the returned attribute values to uppercase values.
	 * @param convertToUpperCase true if it should convert, false otherwise.
	 */
	public void setConvertToUpperCase(final boolean convertToUpperCase) {
		this.convertToUpperCase = convertToUpperCase;
	}

	/**
	 * Get default authorities to add to the user in any case.
	 * @return default authorities
	 */
	public String[] getDefaultAuthorities() {
		return defaultAuthorities;
	}

	/**
	 * Set default authorities to add to the user in any case.
	 * @param defaultAuthorities default authorities
	 */
	public void setDefaultAuthorities(String[] defaultAuthorities) {
		this.defaultAuthorities = defaultAuthorities;
	}
}
