package droidbox.tests;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;

import android.app.Service;
import android.content.Intent;
import android.os.IBinder;
import android.util.Log;

public class SendDataService extends Service {

	
    @Override
    public void onCreate() {
    	super.onCreate();
    	Log.v("Test", "[*] SendDataService()");
    	// HttpURLConnection read & write
        URL url =  null;
        HttpURLConnection urlConnection = null;
        
        try {
			url = new URL("http://pjlantz.com/data.php?data=Hello");
	        urlConnection = (HttpURLConnection) url.openConnection();
	        BufferedReader rd = new BufferedReader(new InputStreamReader(urlConnection.getInputStream()));
	        String line = "";
	        while ((line = rd.readLine()) != null);
	        rd.close();
	        urlConnection.disconnect();
		} catch (MalformedURLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

    }

	@Override
	public IBinder onBind(Intent arg0) {
		// TODO Auto-generated method stub
		return null;
	}

}
