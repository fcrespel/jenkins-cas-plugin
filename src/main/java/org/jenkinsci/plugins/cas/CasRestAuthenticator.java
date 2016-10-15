package org.jenkinsci.plugins.cas;

import hudson.tasks.Mailer;
import java.io.BufferedWriter;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import javax.servlet.http.HttpServletResponse;
import org.acegisecurity.AuthenticationServiceException;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.GrantedAuthorityImpl;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import org.acegisecurity.userdetails.User;
import org.jasig.cas.client.validation.Assertion;
import org.jasig.cas.client.validation.TicketValidationException;
import static org.jenkinsci.plugins.cas.spring.CasEventListener.CAS_NO_PASSWORD;
import org.jenkinsci.plugins.cas.spring.security.CasAuthentication;
import org.jenkinsci.plugins.cas.spring.security.CasUserDetailsService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.cas.authentication.CasAssertionAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;

/**
 * Authenticator to handle the CAS REST protocol. The authenticator is mainly to handle username and password based
 * API requests.
 * 
 * @see <a href="http://apereo.github.io/cas/4.0.x/protocol/REST-Protocol.html">CAS REST-Protocol</a>
 * @author Sebastian Sdorra <sebastian.sdorra@triology.de>
 */
public final class CasRestAuthenticator {

	private static final String CAS_V1_TICKETS = "v1/tickets";

	private static final String ENCODING = "UTF-8";

	private static final Logger LOG = LoggerFactory.getLogger(CasRestAuthenticator.class);

	private final CasProtocol protocol;
	private final String casServerUrl;
	private final String serviceURL;

	public CasRestAuthenticator(CasProtocol protocol, String casServerUrl, String serviceURL) {
		this.protocol = protocol;
		this.casServerUrl = casServerUrl;
		this.serviceURL = serviceURL;
	}

	public CasAuthentication authenticate(UsernamePasswordAuthenticationToken token) {
		return authenticate(token.getPrincipal().toString(), token.getCredentials().toString());
	}

	public CasAuthentication authenticate(String username, String password) {
		String grantingTicket = fetchGrantingTicket(username, password);
		if (grantingTicket != null) {
			String serviceTicket = fetchServiceTicket(grantingTicket);
			if (serviceTicket != null) {
				Assertion assertion = validateServiceTicket(serviceTicket);
				return createCasAuthentication(serviceTicket, assertion);
			} else {
				throw new AuthenticationServiceException("could not fetch service ticket from cas");
			}
		} else {
			throw new AuthenticationServiceException("could not fetch granting ticket from cas");
		}
	}

	private Assertion validateServiceTicket(String serviceTicket) {
		try {
			return protocol.createTicketValidator(casServerUrl).validate(serviceTicket, serviceURL);
		} catch (TicketValidationException ex) {
			throw new AuthenticationServiceException("could not validate service ticket", ex);
		}
	}

	private String fetchServiceTicket(String grantingTicket) {
		String serviceTicket = null;
		HttpURLConnection connection = null;
		try {
			connection = (HttpURLConnection) openConnection(createServiceTicketUrl(grantingTicket));
			String post = createServiceTicketPostContent();
			writeContent(connection, post);
			serviceTicket = extractServiceTicket(connection);
		} catch (IOException ex) {
			LOG.error("failed to optain a service ticket from cas", ex);
		} finally {
			if (connection != null) {
				connection.disconnect();
			}
		}

		return serviceTicket;
	}

	private String extractServiceTicket(HttpURLConnection connection) throws IOException {
		String serviceTicket = null;
		int rc = connection.getResponseCode();
		if (rc == HttpServletResponse.SC_OK) {
			serviceTicket = readContent(connection);
			if (serviceTicket != null) {
				serviceTicket = serviceTicket.trim();
			}
		} else {
			LOG.warn("cas returned status code {}, durring service ticket extraction", rc);
		}
		return serviceTicket;
	}

	private String readContent(HttpURLConnection connection) throws IOException {
		String content = null;
		InputStream inputStream = null;
		try {
			inputStream = connection.getInputStream();
			ByteArrayOutputStream result = new ByteArrayOutputStream();
			byte[] buffer = new byte[1024];
			int length;
			while ((length = inputStream.read(buffer)) != -1) {
				result.write(buffer, 0, length);
			}
			content = result.toString(ENCODING);
		} finally {
			if (inputStream != null) {
				inputStream.close();
			}
		}
		return content;
	}

	private String createServiceTicketUrl(String grantingTicket) {
		return new StringBuilder(casServerUrl).append(CAS_V1_TICKETS).append('/').append(grantingTicket).toString();
	}

	private String createGrantingTicketUrl() {
		return casServerUrl + CAS_V1_TICKETS;
	}

	private String fetchGrantingTicket(String username, String password) {
		String grantingTicket = null;
		HttpURLConnection connection = null;
		try {
			connection = (HttpURLConnection) openConnection(createGrantingTicketUrl());
			String post = createGrantingTicketPostContent(username, password);
			writeContent(connection, post);
			grantingTicket = extractGrantingTicket(connection);
		} catch (IOException ex) {
			LOG.error("failed to optain a ticket granting ticket from cas", ex);
		} finally {
			if (connection != null) {
				connection.disconnect();
			}
		}
		return grantingTicket;
	}

	private String extractGrantingTicket(HttpURLConnection connection) throws IOException {
		String grantingTicket = null;
		int rc = connection.getResponseCode();
		if (rc == HttpServletResponse.SC_CREATED) {
			String location = connection.getHeaderField("location");
			if (location != null && location.length() > 0) {
				int index = location.lastIndexOf('/');
				if (index > 0) {
					grantingTicket = location.substring(location.lastIndexOf('/') + 1);
				} else {
					LOG.warn("cas returned invalid location header");
				}
			} else {
				LOG.warn("cas does not return a location header");
			}
		} else {
			LOG.warn("cas returned status code {}, durring granting ticket extraction", rc);
		}
		return grantingTicket;
	}

	private void writeContent(HttpURLConnection connection, String content) throws IOException {
		BufferedWriter writer = null;
		try {
			writer = new BufferedWriter(new OutputStreamWriter(connection.getOutputStream()));
			writer.write(content);
			writer.flush();
		} finally {
			if (writer != null) {
				writer.close();
			}
		}
	}

	private String createServiceTicketPostContent() throws UnsupportedEncodingException {
		return "service=".concat(encode(serviceURL));
	}

	private String createGrantingTicketPostContent(String username, String password) throws UnsupportedEncodingException {
		StringBuilder buffer = new StringBuilder();
		buffer.append("username=").append(encode(username));
		buffer.append("&password=").append(encode(password));
		return buffer.toString();
	}

	private String encode(String value) throws UnsupportedEncodingException {
		return URLEncoder.encode(value, ENCODING);
	}

	private URLConnection openConnection(final String url) throws IOException {
		HttpURLConnection connection = (HttpURLConnection) new URL(url).openConnection();
		connection.setRequestMethod("POST");
		connection.setDoInput(true);
		connection.setDoOutput(true);
		connection.setRequestProperty("Content-Type", "text/xml");
		return connection;
	}

	private GrantedAuthority[] createAuthorities(Assertion assertion) {
		Map<String, Object> attributes = assertion.getPrincipal().getAttributes();

		List<String> authorityNames = new ArrayList<String>();

		String[] authorityAttributeNames = protocol.getAuthoritiesAttributes();
		for (String name : authorityAttributeNames) {
			addAuthorities(authorityNames, attributes.get(name));
		}

		int i = 0;
		GrantedAuthority[] authorities = new GrantedAuthority[authorityNames.size()];
		for (String authorityName : authorityNames) {
			authorities[i++] = new GrantedAuthorityImpl(authorityName);
		}
		return authorities;
	}

	private void addAuthorities(List<String> authorities, Object attribute) {
		if (attribute != null) {
			if (attribute instanceof Iterable) {
				for (Object value : (Iterable) attribute) {
					authorities.add(value.toString());
				}
			} else {
				authorities.add(attribute.toString());
			}
		}
	}

	private User convert(org.springframework.security.core.userdetails.User sourceUser, GrantedAuthority[] authorities) {
		// Map user
		return new User(sourceUser.getUsername(), CAS_NO_PASSWORD, sourceUser.isEnabled(), sourceUser.isAccountNonExpired(), sourceUser.isCredentialsNonExpired(), sourceUser.isAccountNonLocked(), authorities);
	}

	private CasAuthentication createCasAuthentication(String serviceTicket, Assertion assertion) {
		CasUserDetailsService cuds = new CasUserDetailsService();
		UserDetails details = cuds.loadUserDetails(new CasAssertionAuthenticationToken(assertion, serviceTicket));

		GrantedAuthority[] authorities = createAuthorities(assertion);

		User user = null;
		if (details instanceof User) {
			user = (User) details;
		} else if (details instanceof org.springframework.security.core.userdetails.User) {
			user = convert((org.springframework.security.core.userdetails.User) details, authorities);
		} else {
			throw new IllegalStateException("detailed service returned non user " + details.getClass().getName());
		}

		// ???
		int hash = serviceTicket.hashCode();
		CasAuthentication authentication = new CasAuthentication(hash, user, serviceTicket, authorities, user, assertion);
		syncUserAttributes(assertion);
		return authentication;
	}

	/**
	 * Sync user attributes with a cas assertions.
	 * 
	 * @param assertion cas assertion
	 * 
	 * @throws IOException
	 */
	private void syncUserAttributes(Assertion assertion) {
		// Retrieve or create the Jenkins user
		hudson.model.User user = hudson.model.User.get(assertion.getPrincipal().getName());

		// Sync the full name
		String fullName = getAttributeValue(assertion, protocol.getFullNameAttribute());
		if (fullName != null) {
			user.setFullName(fullName);
		}

		// Sync the email address
		String email = getAttributeValue(assertion, protocol.getEmailAttribute());
		if (email != null) {
			addMailProperty(user, email);
		}

		// Save the user to disk
		try {
			user.save();
		} catch (IOException ex) {
			LOG.error("failed to sync cas attributes with user", ex);
		}
	}

	private void addMailProperty(hudson.model.User user, String email) {
		try {
			user.addProperty(new Mailer.UserProperty(email));
		} catch (IOException ex) {
			LOG.warn("could not add mail property to user", ex);
		}
	}

	/**
	 * Retrieve an attribute's value from a CAS assertion.
	 * 
	 * @param assertion CAS assertion
	 * @param attributeName attribute name
	 * 
	 * @return attribute value or null if not found
	 */
	private String getAttributeValue(Assertion assertion, String attributeName) {
		Map<String, Object> attributes = assertion.getPrincipal().getAttributes();
		Object attribute = attributes.get(attributeName);
		if (attribute != null) {
			if (attribute instanceof Collection) {
				return ((Collection<String>) attribute).iterator().next();
			} else {
				return attribute.toString();
			}
		}
		return null;
	}
}
