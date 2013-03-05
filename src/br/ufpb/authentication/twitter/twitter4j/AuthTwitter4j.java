package br.ufpb.authentication.twitter.twitter4j;

import java.awt.Desktop;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Properties;

import twitter4j.Twitter;
import twitter4j.TwitterException;
import twitter4j.TwitterFactory;
import twitter4j.auth.AccessToken;
import twitter4j.auth.RequestToken;

/**
 * Class to perform authentication of an app with Twitter. using the twitter4j
 * lib.
 * 
 * @author Diego Sousa, diego[at]diegosousa[dot]com
 * @version 0.0.1
 * @since Mar 2, 2013
 * 
 */

public class AuthTwitter4j {

	private static AuthTwitter4j authTwitter4j;

	private File file;
	private String nameFileProperties = "twitter4j.properties";
	private Properties prop;
	private InputStream is = null;
	private OutputStream os = null;
	private Twitter twitter;

	private AuthTwitter4j() {
		createFileProperties();
		connect();
	}

	/**
	 * With this instance it is possible to manipulate all the features of twitter.
	 * 
	 * @return Instance Twitter
	 */
	
	public Twitter getTwitter() {
		return twitter;
	}

	// Singleton
	public static synchronized AuthTwitter4j getInstance() {
		if (authTwitter4j == null) {
			authTwitter4j = new AuthTwitter4j();
		}
		return authTwitter4j;
	}

	/**
	 * Method used to create the file.properties and save the
	 * consumer Key and consumer Secret.
	 */
	
	private void createFileProperties() {
		BufferedReader br = new BufferedReader(new InputStreamReader(System.in));

		try {
			file = new File(nameFileProperties);

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
				prop.store(os, nameFileProperties);

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
				} catch (IOException ignore) {
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
		try {
			twitter = new TwitterFactory().getInstance();
			// Se Token ainda não persistido no arquivo twitter4j.properties
			if (prop.getProperty("oauth.accessToken") == null
					&& prop.getProperty("oauth.accessTokenSecret") == null) {

				RequestToken requestToken = twitter.getOAuthRequestToken();

				AccessToken accessToken = null;
				BufferedReader br = new BufferedReader(new InputStreamReader(
						System.in));

				while (accessToken == null) {
					System.out.println(requestToken.getToken());
					Desktop.getDesktop().browse(
							new URI(requestToken.getAuthorizationURL()));

					System.out
					.print("\nEnter the PIN authorization acquired in the application\n"
							+ "by the browser and press enter:\n");

					String pin = br.readLine();
					try {
						if (pin.length() > 0) {
							accessToken = twitter.getOAuthAccessToken(
									requestToken, pin);

						} else {
							accessToken = twitter
									.getOAuthAccessToken(requestToken);
						}
					} catch (TwitterException te) {
						if (401 == te.getStatusCode()) {
							System.out
									.println("Unable to get the access token.");
						} else {
							te.printStackTrace();
						}
					}
				}

				prop.setProperty("oauth.accessToken", accessToken.getToken());
				prop.setProperty("oauth.accessTokenSecret",
						accessToken.getTokenSecret());
				os = new FileOutputStream(file);
				prop.store(os, nameFileProperties);

				if (os != null) {
					os.close();
				}
			}
			// Se accessToken e accessTokenSecret expiradas será redirecionada
			// para autorização novamente.
			try {
				twitter.verifyCredentials();
			} catch (TwitterException te) {
				if (te.getStatusCode() == 401) {
					System.out
							.println("Invalid token. Probably your token has expired, authorizing again.");
					prop.remove("oauth.accessToken");
					prop.remove("oauth.accessTokenSecret");
					os = new FileOutputStream(file);
					prop.store(os, nameFileProperties);
					if (os != null) {
						os.close();
					}
					connect();
				} else {
					te.printStackTrace();
				}
			}
		} catch (TwitterException te) {
			te.printStackTrace();
			System.out.println("Failed to get accessToken: " + te.getMessage());
			System.exit(-1);
		} catch (IOException ioe) {
			ioe.printStackTrace();
			System.out.println("Failed to read the system input.");
			System.exit(-1);
		} catch (URISyntaxException e) {
			throw new AssertionError(e);
		}
	}
}
