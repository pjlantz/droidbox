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
import android.telephony.TelephonyManager;
import android.util.Log;

public class DroidBoxTests extends Activity {
	
	private String imei, hashedImei;
	
    /** 
     * Called when the activity is first created. 
     */
    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);   
        setContentView(R.layout.main);
        // Setup test variables
        this.setupTest();
        // Run tests
        this.testCryptHash();
        this.testNetworkHTTP();
    }
    
    public void setupTest() {
    	// IMEI
        TelephonyManager manager = (TelephonyManager)getSystemService(TELEPHONY_SERVICE);
        imei = manager.getDeviceId();
    }
    
    /**
     * Usage of hashing in the crypto API
     */
    public void testCryptHash() {
    	Log.v("Test", "[*] testCryptHash()");
    	String testStr = "Hash me";
    	byte messageDigest[];
    	MessageDigest digest = null;
        try {
            // MD5
            digest = java.security.MessageDigest.getInstance("MD5");
            digest.update(testStr.getBytes());
            messageDigest = digest.digest();
            digest.digest(testStr.getBytes());
            
            // SHA1
            digest = java.security.MessageDigest.getInstance("SHA1");
            digest.update(testStr.getBytes());
            messageDigest = digest.digest();
            
            // Hash tainted data
            digest = null;
            digest = java.security.MessageDigest.getInstance("SHA1");
            digest.update(imei.getBytes());
            messageDigest = digest.digest();
            
            // Create Hex String
            StringBuffer hexString = new StringBuffer();
            for (int i = 0; i < messageDigest.length; i++) {
                String h = Integer.toHexString(0xFF & messageDigest[i]);
                while (h.length() < 2)
                    h = "0" + h;
                hexString.append(h);
            }
            hashedImei = hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }
    
    /**
     * Usage of HTTP connections
     */
    public void testNetworkHTTP() {
    	Log.v("Test", "[*] testNetworkHTTP()");
    	// HttpURLConnection read & write
        URL url =  null;
        HttpURLConnection urlConnection = null;
    	try {
            url = new URL("http://code.google.com/p/droidbox/");
            urlConnection = (HttpURLConnection) url.openConnection();
            BufferedReader rd = new BufferedReader(
                                new InputStreamReader(urlConnection.getInputStream()));
            @SuppressWarnings("unused")
            String line = "";
            while ((line = rd.readLine()) != null);
            
            // HttpURLConnection sending tainted data
            url = new URL("http://pjlantz.com/imei.php?imei=" + hashedImei);
            urlConnection = (HttpURLConnection) url.openConnection();
            rd = new BufferedReader(new InputStreamReader(urlConnection.getInputStream()));
            while ((line = rd.readLine()) != null);
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
    	    urlConnection.disconnect();
    	}
    }
}