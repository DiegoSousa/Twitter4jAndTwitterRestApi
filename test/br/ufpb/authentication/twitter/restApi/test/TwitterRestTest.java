package br.ufpb.authentication.twitter.restApi.test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import oauth.signpost.OAuthConsumer;
import oauth.signpost.commonshttp.CommonsHttpOAuthConsumer;
import oauth.signpost.signature.SignatureMethod;

import org.apache.commons.io.IOUtils;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.DefaultHttpClient;
import org.codehaus.jettison.json.JSONObject;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import br.ufpb.authentication.twitter.restApi.AuthTwitterRest;

/**
 * Class testing of Twitter REST API v 1.1
 * 
 * @author Diego Sousa, diego[at]diegosousa[dot]com
 * @version 0.0.1
 * @since Mar 2, 2013
 * 
 */
public class TwitterRestTest {

	private static OAuthConsumer consumer;
	private static HttpClient client;
	private static AuthTwitterRest authTwitterRest;

	@BeforeClass
	public static void setUpBeforeClass() throws Exception {
		System.out.println("Starting the test Twitter Rest API v1.1...");
		authTwitterRest = AuthTwitterRest.getInstance();
		consumer = new CommonsHttpOAuthConsumer(
				authTwitterRest.getConsumerKey(),
				authTwitterRest.getConsumerSecret(), SignatureMethod.HMAC_SHA1);

		consumer.setTokenWithSecret(authTwitterRest.getAccessToken(),
				authTwitterRest.getAccessTokenSecret());
		client = new DefaultHttpClient();
	}

	@AfterClass
	public static void tearDownAfterClass() throws Exception {
		System.out.println("Finished the test facade class!");
	}

	@Test
	public void testStatus() throws Exception {

		for (int c = 11; c <= 20; c++) {

			String status = "Testando Update Status com Twitter REST API v 1.1 e app AuthTwitter - Update - "
					+ c + " Developer by: @diego_sousa_ ";
			
			HttpPost request = new HttpPost(
					"https://api.twitter.com/1.1/statuses/update.json?status="
							+ authTwitterRest.encode(status));
			consumer.sign(request);// OAuth
			HttpResponse response = client.execute(request);
			
			assertTrue(response.getStatusLine().getStatusCode() == 200);
			
			String json = IOUtils.toString(response.getEntity().getContent());
			JSONObject jsonObject = new JSONObject(json);			
			assertEquals(status, jsonObject.getString("text"));
		}
	}
}
