package br.ufpb.authentication.twitter.restApi;

import java.awt.Desktop;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.security.GeneralSecurityException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.Calendar;
import java.util.Properties;
import java.util.StringTokenizer;
import java.util.UUID;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;

import org.apache.commons.codec.binary.Base64;
import org.apache.http.HttpException;
import org.apache.http.HttpHost;
import org.apache.http.HttpRequestInterceptor;
import org.apache.http.HttpResponse;
import org.apache.http.HttpVersion;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.DefaultHttpClientConnection;
import org.apache.http.message.BasicHttpEntityEnclosingRequest;
import org.apache.http.params.HttpParams;
import org.apache.http.params.HttpProtocolParams;
import org.apache.http.params.SyncBasicHttpParams;
import org.apache.http.protocol.BasicHttpContext;
import org.apache.http.protocol.ExecutionContext;
import org.apache.http.protocol.HttpContext;
import org.apache.http.protocol.HttpProcessor;
import org.apache.http.protocol.HttpRequestExecutor;
import org.apache.http.protocol.ImmutableHttpProcessor;
import org.apache.http.protocol.RequestConnControl;
import org.apache.http.protocol.RequestContent;
import org.apache.http.protocol.RequestExpectContinue;
import org.apache.http.protocol.RequestTargetHost;
import org.apache.http.protocol.RequestUserAgent;
import org.apache.http.util.EntityUtils;
import org.codehaus.jettison.json.JSONException;
import org.codehaus.jettison.json.JSONObject;

/**
 * Class to perform authentication of an app with Twitter. using the
 * REST API v1.1.
 * 
 * @author Diego Sousa, diego[at]diegosousa[dot]com
 * @version 0.0.1
 * @since Mar 2, 2013
 * 
 * Based on the example of cyrus7580 and modified to my need:
 * https://github.com/cyrus7580/twitter_api_examples/blob/master/src/SampleTwitterRequests.java
 * 
 * Mandatory reading for understanding this code:
 * https://dev.twitter.com/docs/auth/implementing-sign-twitter
 */

public class AuthTwitterRest {

	private static AuthTwitterRest authTwitterRest;
	
	private String twitter_host = "api.twitter.com";

	private HttpParams params;
	private HttpProcessor httpproc;
	private HttpRequestExecutor httpexecutor;
	private HttpContext context;
	private DefaultHttpClientConnection connection;

	private File file;
	private Properties prop;
	private InputStream is = null;
	private OutputStream os = null;
	private String fileProperties = "twitterRest.properties";

	private AuthTwitterRest() {
		createFileProperties();
		connect();
	}
	
	//Singleton
	public static synchronized AuthTwitterRest getInstance(){
		if(authTwitterRest==null){
			authTwitterRest = new AuthTwitterRest();
		}
		return authTwitterRest;
	}
	
	/**
	 * Method used to create the file.properties and save the
	 * consumer Key and consumer Secret.
	 */

	private void createFileProperties() {
		BufferedReader br = new BufferedReader(new InputStreamReader(System.in));

		try {
			file = new File(fileProperties);

			if (!file.exists()) {
				file.createNewFile();
			}

			prop = new Properties();
			is = new FileInputStream(file);
			prop.load(is);

			if (prop.getProperty("oauth.consumerKey") == null
					&& prop.getProperty("oauth.consumerSecret") == null) {

				System.out
						.println("To handle a Twitter account, you must register your application in:\n"
								+ "https://dev.twitter.com/apps\n"
								+ "After the register obtain the 'consumer Key' and 'consumer Secret' in\n"
								+ "the tab 'Details' on profile of your application on Twitter.\n");

				System.out
						.println("Enter the consumer key of its Twitter application:");
				prop.setProperty("oauth.consumerKey", br.readLine());

				System.out
						.println("Enter the consumers secret Twitter application:");
				prop.setProperty("oauth.consumerSecret", br.readLine());

				os = new FileOutputStream(file);
				prop.store(os, fileProperties);

				if (os != null) {
					os.close();
				}
			}
		} catch (IOException ioe) {
			ioe.printStackTrace();
			System.exit(-1);
		} finally {
			if (is != null) {
				try {
					is.close();
				} catch (IOException io) {
					io.printStackTrace();
				}
			}
		}
	}

	/**
	 * Method that manages all flow of authentication with twitter, implements
	 * the second step in the flow oauth Twitter redirecting the user to the
	 * authorization page to get the PIN and finally write file.properties the
	 * access tokens.
	 */

	private void connect() {

		if (prop.getProperty("oauth.accessToken") == null
				&& prop.getProperty("oauth.accessTokenSecret") == null) {

			BufferedReader br = new BufferedReader(new InputStreamReader(
					System.in));
			JSONObject jsonTokens = startTwitterAuthentication();			
			
			try {
				Desktop.getDesktop().browse(
						new URI(
								"https://api.twitter.com/oauth/authorize?oauth_token="
										+ jsonTokens.getString("oauth_token")));
				System.out
						.print("\nEnter the PIN authorization acquired in the application\n"
								+ "by the browser and press enter:\n");

				String pin = br.readLine();

				JSONObject jsonAccessToken = getTwitterAccessTokenFromAuthorizationCode(
						pin, jsonTokens.getString("oauth_token"));

				prop.setProperty("oauth.accessToken",
						jsonAccessToken.getString("access_token"));
				prop.setProperty("oauth.accessTokenSecret",
						jsonAccessToken.getString("access_token_secret"));
				os = new FileOutputStream(file);
				prop.store(os, fileProperties);
			} catch (IOException e) {
				e.printStackTrace();
			} catch (URISyntaxException e) {
				e.printStackTrace();
			} catch (JSONException e) {
				e.printStackTrace();
			}

			if (os != null) {
				try {
					os.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
		}
	}

	/**
	 * The first step in the twitter oauth flow is to get a request token with a
	 * call to api.twitter.com/oauth/request_token.
	 * 
	 * @return JSONObject with oauth_token, oauth_token_secret and
	 *         oauth_token_confirmed
	 * 
	 */

	private JSONObject startTwitterAuthentication() {
		JSONObject jsonresponse = new JSONObject();

		String resource_url = "https://api.twitter.com/oauth/request_token";
		String resource_url_path = "/oauth/request_token";

		String oauth_token = "";
		String oauth_token_secret = "";
		String oauth_callback_confirmed = "";
		String oauth_signature = "";
		String oauth_signature_method = "HMAC-SHA1";
		String oauth_nonce = UUID.randomUUID().toString().replaceAll("-", "");
		String oauth_timestamp = (new Long(Calendar.getInstance()
				.getTimeInMillis() / 1000)).toString();

		// Assemble the proper parameter string, which must be in alphabetical
		// order.
		String parameter = "oauth_consumer_key=" + getConsumerKey()
				+ "&oauth_nonce=" + oauth_nonce + "&oauth_signature_method="
				+ oauth_signature_method + "&oauth_timestamp="
				+ oauth_timestamp + "&oauth_version=1.0";

		try {
			oauth_signature = computeSignature("POST&" + encode(resource_url)
					+ "&" + encode(parameter), getConsumerSecret() + "&");
		} catch (GeneralSecurityException e) {
			e.printStackTrace();
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}

		// Each request to the twitter API 1.1 requires an
		// "Authorization: parameters"
		// header. The following String is what "parameters" should look like
		String authorization_header = "OAuth oauth_consumer_key=\""
				+ getConsumerKey()
				+ "\",oauth_signature_method=\"HMAC-SHA1\",oauth_timestamp=\""
				+ oauth_timestamp + "\",oauth_nonce=\"" + oauth_nonce
				+ "\",oauth_version=\"1.0\",oauth_signature=\""
				+ encode(oauth_signature) + "\"";

		try {
			try {

				confTransferData(jsonresponse);

				BasicHttpEntityEnclosingRequest request = new BasicHttpEntityEnclosingRequest(
						"POST", resource_url_path);
				request.setEntity(new StringEntity("",
						"application/x-www-form-urlencoded", "UTF-8"));
				request.setParams(params);
				request.addHeader("Authorization", authorization_header);
				httpexecutor.preProcess(request, httpproc, context);
				HttpResponse response = httpexecutor.execute(request, connection,
						context);
				response.setParams(params);
				httpexecutor.postProcess(response, httpproc, context);

				if (response.getStatusLine().toString().indexOf("200") == -1) {
					jsonresponse.put("response_status", "error");
					jsonresponse
							.put("message",
									"Twitter request_token request failed. Response was !200.");
				} else {
					String responseBody = EntityUtils.toString(response
							.getEntity());
					
					if (responseBody.indexOf("oauth_callback_confirmed=") == -1) {
						jsonresponse.put("response_status", "error");
						jsonresponse
								.put("message",
										"Twitter request_token request failed. response was 200"
												+ " but did not contain oauth_callback_confirmed");
					} else {
						String occ_val = responseBody.substring(responseBody
								.indexOf("oauth_callback_confirmed=") + 25);
						if (!occ_val.equals("true")) {
							jsonresponse.put("response_status", "error");
							jsonresponse
									.put("message",
											"Twitter request_token response was 200 and contained "
													+ "oauth_callback_confirmed but it was not \"true\".");
						}
						// using the tokenizer takes away the need for the
						// values to be in any particular order.
						StringTokenizer st = new StringTokenizer(responseBody,
								"&");
						String currenttoken = "";
						while (st.hasMoreTokens()) {
							currenttoken = st.nextToken();
							if (currenttoken.startsWith("oauth_token="))
								oauth_token = currenttoken
										.substring(currenttoken.indexOf("=") + 1);
							else if (currenttoken
									.startsWith("oauth_token_secret="))
								oauth_token_secret = currenttoken
										.substring(currenttoken.indexOf("=") + 1);
							else if (currenttoken
									.startsWith("oauth_callback_confirmed="))
								oauth_callback_confirmed = currenttoken
										.substring(currenttoken.indexOf("=") + 1);
							else {
								System.out
										.println("Warning... twitter returned a key"
												+ " we weren't looking for.");
							}
						}

						if (oauth_token.equals("")
								|| oauth_token_secret.equals("")) {
							jsonresponse.put("response_status", "error");
							jsonresponse.put("message",
									"oauth tokens in response were invalid");
						} else {

							jsonresponse.put("response_status", "success");
							jsonresponse.put("oauth_token", oauth_token);
							jsonresponse.put("oauth_token_secret",
									oauth_token_secret);
							jsonresponse.put("oauth_callback_confirmed",
									oauth_callback_confirmed);
						}
					}
				}
				connection.close();
			} catch (HttpException he) {
				System.out.println(he.getMessage());
				jsonresponse.put("response_status", "error");
				jsonresponse.put("message",
						"startTwitterAuthentication HttpException message="
								+ he.getMessage());
			} finally {
				connection.close();
			}
		} catch (JSONException jsone) {
			jsone.printStackTrace();
		} catch (IOException ioe) {
			ioe.printStackTrace();
		}
		return jsonresponse;
	}

	/**
	 * The three step in the twitter oauth flow is to get a access token and
	 * access token secret with a call to api.twitter.com/oauth/access_token.
	 * 
	 * @param pin
	 *            verifier. Obtained in the authorization page.
	 * @param oauth_token
	 *            of request_token
	 * @return JSONObject with oauth_access_token and oauth_access_token_secret.
	 * 
	 */

	private JSONObject getTwitterAccessTokenFromAuthorizationCode(String pin,
			String oauth_token) {
		JSONObject jsonresponse = new JSONObject();

		String resource_url = "https://api.twitter.com/oauth/access_token";
		String resource_url_path = "/oauth/access_token";

		String oauth_signature = "";
		String oauth_signature_method = "HMAC-SHA1";
		String oauth_nonce = UUID.randomUUID().toString().replaceAll("-", "");
		String oauth_timestamp = (new Long(Calendar.getInstance()
				.getTimeInMillis() / 1000)).toString();

		String access_token = "";
		String access_token_secret = "";
		String user_id = "";
		String screen_name = "";

		// the parameter string must be in alphabetical order
		String parameter_string = "oauth_consumer_key=" + getConsumerKey()
				+ "&oauth_nonce=" + oauth_nonce + "&oauth_signature_method="
				+ oauth_signature_method + "&oauth_timestamp="
				+ oauth_timestamp + "&oauth_token=" + encode(oauth_token)
				+ "&oauth_version=1.0";

		try {
			oauth_signature = computeSignature(
					"POST&" + encode(resource_url) + "&"
							+ encode(parameter_string), getConsumerSecret()
							+ "&");
		} catch (GeneralSecurityException e) {
			e.printStackTrace();
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}

		String authorization_header = "OAuth oauth_consumer_key=\""
				+ getConsumerKey()
				+ "\",oauth_signature_method=\"HMAC-SHA1\",oauth_timestamp=\""
				+ oauth_timestamp + "\",oauth_nonce=\"" + oauth_nonce
				+ "\",oauth_version=\"1.0\",oauth_signature=\""
				+ encode(oauth_signature) + "\",oauth_token=\""
				+ encode(oauth_token) + "\"";

		try {
			try {
				confTransferData(jsonresponse);

				BasicHttpEntityEnclosingRequest request = new BasicHttpEntityEnclosingRequest(
						"POST", resource_url_path);
				// include the oauth_verifier value with
				// the request
				request.setEntity(new StringEntity("oauth_verifier="
						+ encode(pin), "application/x-www-form-urlencoded",
						"UTF-8"));
				request.setParams(params);
				request.addHeader("Authorization", authorization_header);
				httpexecutor.preProcess(request, httpproc, context);
				HttpResponse response = httpexecutor.execute(request, connection,
						context);
				response.setParams(params);
				httpexecutor.postProcess(response, httpproc, context);
				String responseBody = EntityUtils
						.toString(response.getEntity());

				if (response.getStatusLine().toString().indexOf("200") == -1) {
					jsonresponse.put("response_status", "error");
					jsonresponse.put("message",
							"getTwitterAccessTokenFromAuthorizationCode "
									+ "request failed. Response was !200.");
				} else {
					StringTokenizer st = new StringTokenizer(responseBody, "&");
					String currenttoken = "";
					while (st.hasMoreTokens()) {
						currenttoken = st.nextToken();
						if (currenttoken.startsWith("oauth_token="))
							access_token = currenttoken.substring(currenttoken
									.indexOf("=") + 1);
						else if (currenttoken.startsWith("oauth_token_secret="))
							access_token_secret = currenttoken
									.substring(currenttoken.indexOf("=") + 1);
						else if (currenttoken.startsWith("user_id="))
							user_id = currenttoken.substring(currenttoken
									.indexOf("=") + 1);
						else if (currenttoken.startsWith("screen_name="))
							screen_name = currenttoken.substring(currenttoken
									.indexOf("=") + 1);
					}
				}

				if (access_token.equals("") || access_token_secret.equals("")) {
					jsonresponse.put("response_status", "error");
					jsonresponse.put("message",
							"code into access token failed. oauth tokens"
									+ "in response were invalid");
				} else {
					jsonresponse.put("response_status", "success");
					jsonresponse.put("access_token", access_token);
					jsonresponse
							.put("access_token_secret", access_token_secret);
					jsonresponse.put("user_id", user_id);
					jsonresponse.put("screen_name", screen_name);
				}
				connection.close();
			} catch (HttpException he) {
				System.out.println(he.getMessage());
				jsonresponse.put("response_status", "error");
				jsonresponse.put("message",
						"getTwitterAccessTokenFromAuthorizationCode HttpException message="
								+ he.getMessage());
			} finally {
				connection.close();
			}
		} catch (JSONException jsone) {
			jsone.printStackTrace();
		} catch (IOException ioe) {
			ioe.printStackTrace();
		}
		return jsonresponse;
	}

	/**
	 * Configures the objects necessary to send in requests. <br>
	 * 
	 * @param JSONObject
	 * @return void
	 * 
	 */

	private void confTransferData(JSONObject jsonresponse) {

		/**
		 * In theory, could use HTTPClient, but HTTPClient defaults to the wrong
		 * RFC encoding, which has to be tweaked. Then Apache HTTPCore can make
		 * the connection and process the request.
		 */
		params = new SyncBasicHttpParams();
		HttpProtocolParams.setVersion(params, HttpVersion.HTTP_1_1);
		HttpProtocolParams.setContentCharset(params, "UTF-8");
		HttpProtocolParams.setUserAgent(params, "HttpCore/1.1");
		HttpProtocolParams.setUseExpectContinue(params, false);

		httpproc = new ImmutableHttpProcessor(new HttpRequestInterceptor[] {
				new RequestContent(), new RequestTargetHost(),
				new RequestConnControl(), new RequestUserAgent(),
				new RequestExpectContinue() });

		httpexecutor = new HttpRequestExecutor();
		context = new BasicHttpContext(null);
		// use 80 if you want regular HTTP (not HTTPS)
		HttpHost host = new HttpHost(twitter_host, 443);
		connection = new DefaultHttpClientConnection();

		context.setAttribute(ExecutionContext.HTTP_CONNECTION, connection);
		context.setAttribute(ExecutionContext.HTTP_TARGET_HOST, host);
		try {
			try {
				// initialize the HTTPS connection
				SSLContext sslcontext;
				sslcontext = SSLContext.getInstance("TLS");
				sslcontext.init(null, null, null);

				SSLSocketFactory ssf = sslcontext.getSocketFactory();
				Socket socket;

				socket = ssf.createSocket();
				socket.connect(
						new InetSocketAddress(host.getHostName(), host
								.getPort()), 0);
				connection.bind(socket, params);
			} catch (NoSuchAlgorithmException nsae) {
				System.out.println(nsae.getMessage());
				jsonresponse.put("response_status", "error");
				jsonresponse.put("message",
						"startTwitterAuthentication NoSuchAlgorithmException message="
								+ nsae.getMessage());
			} catch (KeyManagementException kme) {
				System.out.println(kme.getMessage());
				jsonresponse.put("response_status", "error");
				jsonresponse.put("message",
						"startTwitterAuthentication KeyManagementException message="
								+ kme.getMessage());
			}
		} catch (JSONException jsone) {
			jsone.printStackTrace();
		} catch (IOException ioe) {
			ioe.printStackTrace();
		}
	}

	/**
	 * Method to convert a string to the specification RFC 3986 that Twitter
	 * requires in some parameters. Java's native URLEncoder.encode function
	 * will not work. It is the wrong RFC specification (which does "+" where
	 * "%20" should be)... the encode() function included in this class
	 * compensates to conform to RFC 3986 (which twitter requires)
	 * 
	 * @param String
	 *            to be converted to RFC 3986 specification.
	 * @return String converted in the specification RFC 3986.
	 * @exception UnsupportedEncodingException
	 */

	public String encode(String value) {
		String encoded = null;
		try {
			encoded = URLEncoder.encode(value, "UTF-8");
		} catch (UnsupportedEncodingException uee) {
			uee.printStackTrace();
		}
		StringBuilder buf = new StringBuilder(encoded.length());
		char focus;
		for (int i = 0; i < encoded.length(); i++) {
			focus = encoded.charAt(i);
			if (focus == '*') {
				buf.append("%2A");
			} else if (focus == '+') {
				buf.append("%20");
			} else if (focus == '%' && (i + 1) < encoded.length()
					&& encoded.charAt(i + 1) == '7'
					&& encoded.charAt(i + 2) == 'E') {
				buf.append('~');
				i += 2;
			} else {
				buf.append(focus);
			}
		}
		return buf.toString();
	}

	/**
	 * Method to encrypt the parameter oauth_signature.
	 * 
	 * @param baseString
	 * @param keyString
	 * @return oauth_signature encrypt.
	 * @throws GeneralSecurityException
	 * @throws UnsupportedEncodingException
	 */
	private static String computeSignature(String baseString, String keyString)
			throws GeneralSecurityException, UnsupportedEncodingException {
		SecretKey secretKey = null;

		byte[] keyBytes = keyString.getBytes();
		secretKey = new SecretKeySpec(keyBytes, "HmacSHA1");

		Mac mac = Mac.getInstance("HmacSHA1");
		mac.init(secretKey);

		byte[] text = baseString.getBytes();

		return new String(Base64.encodeBase64(mac.doFinal(text))).trim();
	}

	public String getConsumerKey() {
		return prop.getProperty("oauth.consumerKey");
	}

	public String getConsumerSecret() {
		return prop.getProperty("oauth.consumerSecret");
	}

	public String getAccessToken() {
		return prop.getProperty("oauth.accessToken");
	}

	public String getAccessTokenSecret() {
		return prop.getProperty("oauth.accessTokenSecret");
	}
}
