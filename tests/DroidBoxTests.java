package droidbox.tests;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import android.app.Activity;
import android.os.Bundle;

public class DroidBoxTests extends Activity {
	
    /** 
     * Called when the activity is first created. 
     */
    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        // Run tests
        this.testCryptHash();
        this.testNetworkHTTP();
        
        setContentView(R.layout.main);
    }
    
    /**
     * Usage of hashing in the crypto API
     */
    public void testCryptHash() {
    	String testStr = "Hash me";
    	@SuppressWarnings("unused")
		byte messageDigest[];
    	MessageDigest digest = null;
        try {
            // MD5
            digest = java.security.MessageDigest.getInstance("MD5");
            digest.update(testStr.getBytes());
            messageDigest = digest.digest();
            
            // SHA1
            digest = java.security.MessageDigest.getInstance("SHA1");
            digest.update(testStr.getBytes());
            messageDigest = digest.digest();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }
    
    /**
     * Usage of HTTP connections
     */
    public void testNetworkHTTP() {
    	// HttpURLConnection read & write
    	URL url =  null;
    	HttpURLConnection urlConnection = null;
    	try {
    		url = new URL("http://droidbox.googlecode.com/");
        	urlConnection = (HttpURLConnection) url.openConnection();
    		BufferedReader rd = new BufferedReader(
                                new InputStreamReader(urlConnection.getInputStream()));
    		@SuppressWarnings("unused")
			String line = "";
            while ((line = rd.readLine()) != null) ;
        } catch (IOException e) {
			e.printStackTrace();
		} finally {
    	    urlConnection.disconnect();
    	}
    }
}