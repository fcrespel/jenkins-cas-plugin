package org.jenkinsci.plugins.cas.spring.security;

import java.io.BufferedWriter;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.cas.web.CasAuthenticationFilter;
import org.springframework.security.cas.web.authentication.ServiceAuthenticationDetails;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.util.Assert;

/**
 * Authenticator to handle the CAS REST protocol. The authenticator is mainly to handle username and password based
 * API requests.
 * 
 * @see <a href="https://apereo.github.io/cas/6.2.x/protocol/REST-Protocol.html">CAS REST-Protocol</a>
 * @author Sebastian Sdorra
 * @author Fabien Crespel
 */
public final class CasRestAuthenticator implements InitializingBean, AuthenticationManager {

	private static final String CAS_V1_TICKETS = "v1/tickets";
	private static final String ENCODING = "UTF-8";
	private static final Logger LOG = LoggerFactory.getLogger(CasRestAuthenticator.class);

	private String casServerUrl;
	private AuthenticationManager authenticationManager;
	private AuthenticationDetailsSource<HttpServletRequest, ServiceAuthenticationDetails> authenticationDetailsSource;

	@Override
	public void afterPropertiesSet() throws Exception {
		Assert.notNull(casServerUrl, "casServerUrl cannot be null");
		Assert.notNull(authenticationManager, "authenticationManager cannot be null");
		Assert.notNull(authenticationDetailsSource, "authenticationDetailsSource cannot be null");
	}

	public String getCasServerUrl() {
		return casServerUrl;
	}

	public void setCasServerUrl(String casServerUrl) {
		this.casServerUrl = casServerUrl;
	}

	public AuthenticationManager getAuthenticationManager() {
		return authenticationManager;
	}

	public void setAuthenticationManager(AuthenticationManager authenticationManager) {
		this.authenticationManager = authenticationManager;
	}

	public AuthenticationDetailsSource<HttpServletRequest, ServiceAuthenticationDetails> getAuthenticationDetailsSource() {
		return authenticationDetailsSource;
	}

	public void setAuthenticationDetailsSource(AuthenticationDetailsSource<HttpServletRequest, ServiceAuthenticationDetails> authenticationDetailsSource) {
		this.authenticationDetailsSource = authenticationDetailsSource;
	}

	// ~ AuthenticationManager implementation ===========================================================================

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		if (authentication instanceof UsernamePasswordAuthenticationToken) {
			return authenticate((UsernamePasswordAuthenticationToken) authentication);
		} else {
			throw new BadCredentialsException("Unexpected authentication type: " + authentication);
		}
	}

	public Authentication authenticate(UsernamePasswordAuthenticationToken token) {
		return authenticate(token.getPrincipal().toString(), token.getCredentials().toString());
	}

	public Authentication authenticate(String username, String password) throws AuthenticationException {
		String grantingTicket = fetchGrantingTicket(username, password);
		if (grantingTicket != null) {
			try {
				String serviceTicket = fetchServiceTicket(grantingTicket);
				if (serviceTicket != null) {
					return validateServiceTicket(serviceTicket);
				} else {
					throw new AuthenticationServiceException("Could not fetch service ticket from CAS");
				}
			} finally {
				destroyGrantingTicket(grantingTicket);
			}
		} else {
			throw new AuthenticationServiceException("Could not fetch granting ticket from CAS");
		}
	}

	// ~ Granting Ticket ================================================================================================

	private String createGrantingTicketUrl() {
		return new StringBuilder(casServerUrl).append(CAS_V1_TICKETS).toString();
	}

	private String createGrantingTicketPostContent(String username, String password) throws UnsupportedEncodingException {
		StringBuilder buffer = new StringBuilder();
		buffer.append("username=").append(encode(username));
		buffer.append("&password=").append(encode(password));
		return buffer.toString();
	}

	private String fetchGrantingTicket(String username, String password) {
		String grantingTicket = null;
		HttpURLConnection connection = null;
		try {
			connection = openConnection(createGrantingTicketUrl());
			String post = createGrantingTicketPostContent(username, password);
			writeContent(connection, post);
			grantingTicket = extractGrantingTicket(connection);
		} catch (IOException ex) {
			LOG.error("Failed to obtain a ticket granting ticket from CAS", ex);
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
					LOG.warn("CAS returned invalid location header");
				}
			} else {
				LOG.warn("CAS did not return a location header");
			}
		} else {
			LOG.warn("CAS returned status code {}, during granting ticket extraction", rc);
		}
		return grantingTicket;
	}

	private void destroyGrantingTicket(String grantingTicket) {
		HttpURLConnection connection = null;
		try {
			connection = openConnection(createServiceTicketUrl(grantingTicket), "DELETE");
			int rc = connection.getResponseCode();
			if (rc != HttpServletResponse.SC_OK) {
				LOG.warn("CAS returned status code {}, during granting ticket destruction", rc);
			}
		} catch (IOException ex) {
			LOG.error("Failed to destroy granting ticket from CAS", ex);
		} finally {
			if (connection != null) {
				connection.disconnect();
			}
		}
	}

	// ~ Service Ticket =================================================================================================

	private String createServiceTicketUrl(String grantingTicket) {
		return new StringBuilder(casServerUrl).append(CAS_V1_TICKETS).append('/').append(grantingTicket).toString();
	}

	private String createServiceTicketPostContent() throws UnsupportedEncodingException {
		return "service=".concat(encode(authenticationDetailsSource.buildDetails(null).getServiceUrl()));
	}

	private String fetchServiceTicket(String grantingTicket) {
		String serviceTicket = null;
		HttpURLConnection connection = null;
		try {
			connection = openConnection(createServiceTicketUrl(grantingTicket));
			String post = createServiceTicketPostContent();
			writeContent(connection, post);
			serviceTicket = extractServiceTicket(connection);
		} catch (IOException ex) {
			LOG.error("Failed to obtain a service ticket from CAS", ex);
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
			LOG.warn("CAS returned status code {}, during service ticket extraction", rc);
		}
		return serviceTicket;
	}

	private Authentication validateServiceTicket(String serviceTicket) {
		UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(CasAuthenticationFilter.CAS_STATEFUL_IDENTIFIER, serviceTicket);
		authRequest.setDetails(authenticationDetailsSource.buildDetails(null));
		return authenticationManager.authenticate(authRequest);
	}

	// ~ Connection utilities ===========================================================================================

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

	private void writeContent(HttpURLConnection connection, String content) throws IOException {
		BufferedWriter writer = null;
		try {
			writer = new BufferedWriter(new OutputStreamWriter(connection.getOutputStream(), ENCODING));
			writer.write(content);
			writer.flush();
		} finally {
			if (writer != null) {
				writer.close();
			}
		}
	}

	private String encode(String value) throws UnsupportedEncodingException {
		return URLEncoder.encode(value, ENCODING);
	}

	private HttpURLConnection openConnection(String url) throws IOException {
		return openConnection(url, "POST");
	}

	private HttpURLConnection openConnection(String url, String method) throws IOException {
		HttpURLConnection connection = (HttpURLConnection) new URL(url).openConnection();
		connection.setRequestMethod(method);
		connection.setDoInput(true);
		connection.setDoOutput(true);
		return connection;
	}

}
