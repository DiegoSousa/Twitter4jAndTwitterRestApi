package br.ufpb.authentication.twitter.twitter4j.test;

import static org.junit.Assert.assertEquals;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import twitter4j.Status;
import twitter4j.Twitter;
import br.ufpb.authentication.twitter.twitter4j.AuthTwitter4j;

/**
 * Class testing of Twitter4j lib
 * 
 * @author Diego Sousa, diego[at]diegosousa[dot]com
 * @version 0.0.1
 * @since Mar 2, 2013
 * 
 */
public class Twitter4jTest {

	private static Twitter twitter;

	@BeforeClass
	public static void setUpBeforeClass() throws Exception {
		System.out.println("Starting the test Twitter Rest API v1.1...");
		twitter = AuthTwitter4j.getInstance().getTwitter();
	}

	@AfterClass
	public static void tearDownAfterClass() throws Exception {
		System.out.println("Finished the test facade class!");
	}

	@Test
	public void testStatus() throws Exception {

		for (int c = 21; c <= 22; c++) {

			String statusActual = "@"
					+ twitter.getScreenName()
					+ " Testando Update Status com Twitter4j e app AuthTwitter - Update - "
					+ c + " Developer by: @diego_sousa_";
			Status status = twitter.updateStatus(statusActual);
			assertEquals(statusActual, status.getText());

		}
	}
}
