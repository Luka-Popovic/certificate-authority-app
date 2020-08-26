package implementation;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;


public class KS {

	private static KeyStore ks;
	private static String filename = "keystore.p12";
	private static char[] password = "1234".toCharArray();

	private KS() {

		try {

			ks = KeyStore.getInstance("pkcs12");
			File f = new File(filename);
			if(f.exists() && !f.isDirectory()) {
				FileInputStream fis = new FileInputStream(filename);
				ks.load(fis, password);
				fis.close();
			}
			else{
			ks.load(null, password);
			FileOutputStream fos = new FileOutputStream(filename);
			ks.store(fos, password);
			fos.close();
			}
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}

	public static void create_NewKS() {

		try {
			ks = KeyStore.getInstance("pkcs12");
			File f = new File(filename);
			if(f.exists() && !f.isDirectory()) { 
				FileInputStream fis = new FileInputStream(filename);
				ks.load(fis, password);
				fis.close();
			}
			else{ks.load(null, password);
			FileOutputStream fos = new FileOutputStream(filename);
			ks.store(fos, password);
			fos.close();
			}
			} catch (Exception e) {

			e.printStackTrace();
		}
	}

	public static KeyStore getInstance() {

		if (ks == null) {

			create_NewKS();

		}
		
		try {
			FileInputStream fis = new FileInputStream(filename);
			ks.load(fis, password);
			fis.close();
		} catch (NoSuchAlgorithmException | CertificateException | IOException e) {
			
			e.printStackTrace();
		}
		return ks;
	}

	public static void resetLocalKeystore() {

		if (ks != null) {

			ks = null;
			File file = new File(filename);
			boolean success = file.delete();

		}
	}

	public static String getKSName() {
		return filename;
	}

	public static void changeKSName(String new_name) {
		filename = new_name;
	}


	public static int loadKeypair(String alias){
	
		int value = -1;
		if(ks == null){
			return -1;
		}
	
		try {
			
			X509Certificate cert =(X509Certificate) ks.getCertificate(alias);
			boolean[] keyUsage = cert.getKeyUsage();
			if(!keyUsage[0]) value=0;
			else value=1;
			if (keyUsage[5]) value=2;
		
			
		} catch (KeyStoreException e) {
			
			e.printStackTrace();
		}
		
		return value;
	}


	public static void storeKS() {
		
		FileOutputStream fos;
		try {
			fos = new FileOutputStream(filename);
			ks.store(fos, password);
			fos.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
		
	}
	
	public static void releaseKS(){
		
		ks = null;
		
	}
	
	public static char[] getPassword(){
		
		return password;
	}
 	
	public static void setPassword(char[] pass){
		
		password = pass;
	}
	
}
