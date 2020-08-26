package implementation;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.math.BigInteger;
import java.net.URI;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PKCS12Attribute;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.cert.X509Extension;
import java.security.interfaces.RSAKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import javax.security.auth.x500.X500Principal;
import javax.xml.bind.DatatypeConverter;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.BERSequence;
import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERGeneralString;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x500.DirectoryString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.PolicyQualifierInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.x509.*;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.encoders.Base64Encoder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

import code.GuiException;
import x509.v3.CodeV3;

public class AuthorityApp extends CodeV3 {

	private JcaPKCS10CertificationRequest req = null;
	private Date nbefore = null;
	private Date nafter = null;
	private BigInteger serial = null;
	
	public AuthorityApp(boolean[] algorithm_conf, boolean[] extensions_conf) throws GuiException {
		super(algorithm_conf, extensions_conf);
		// TODO Auto-generated constructor stub
	}

	@Override
	public boolean exportCertificate(File arg0, int arg1) {

		KeyStore ks = KS.getInstance();
		try {
			String commonName = access.getSubjectCommonName();
			Enumeration<String> en;
			en = ks.aliases();

			X509Certificate storecert = null;
			while (en.hasMoreElements()) {
				
				String ali = (String) en.nextElement();
				storecert = (X509Certificate) ks.getCertificate(ali);
				String name = storecert.getSubjectX500Principal().getName();
				String segments[] = name.split(",");
				String CN = segments[0].substring(segments[0].lastIndexOf("=") + 1);
				if (CN.equals(commonName)) {
					break;
				} else {
					storecert = null;
				}
			}

			if (arg1 == 0) {

				FileOutputStream stream = new FileOutputStream(arg0);
				try {
					stream.write(storecert.getEncoded());
				} finally {
					stream.close();
				}
			} else if (arg1 == 1) {

				final StringWriter stringWriter = new StringWriter();
				final PemWriter pemWriter = new PemWriter(stringWriter);

				final PemObject pemObject = new PemObject("CERTIFICATE", storecert.getEncoded());
				pemWriter.writeObject(pemObject);
				pemWriter.close();
				
				FileOutputStream stream = new FileOutputStream(arg0);
				try {
					stream.write(pemObject.getContent());
				} finally {
					stream.close();
				}
			}

		} catch (Exception e) {
			e.printStackTrace();
			return false;
		}
		return true;
	}

	@Override
	public boolean exportKeypair(String arg0, String arg1, String arg2) {

		try {
			KeyStore ks = KS.getInstance();
			PrivateKey pk = (PrivateKey) ks.getKey(arg0, null);
			Certificate[] chain = ks.getCertificateChain(arg0);

			KeyStore ks1 = KeyStore.getInstance("pkcs12");
			File f = new File(arg1);
			if(f.exists() && !f.isDirectory()) { 
				
			}
			else{
				ks1.load(null, arg2.toCharArray());
			FileOutputStream fos = new FileOutputStream(arg1);
			ks1.store(fos, arg2.toCharArray());
			fos.close();
			}
			
			FileInputStream fis = new FileInputStream(arg1);
			ks1.load(fis, arg2.toCharArray());
			fis.close();
			
			ks1.setKeyEntry(arg0, pk, arg2.toCharArray(), chain);
			FileOutputStream fos = new FileOutputStream(arg1);
			ks1.store(fos, arg2.toCharArray());
			fos.close();

		} catch (Exception e) {
			e.printStackTrace();
			return false;
		}
		return true;
	}

	@Override
	public boolean generateCSR(String arg0) {

		KeyStore ks = KS.getInstance();
		try {
			X509Certificate cert = (X509Certificate) ks.getCertificate(arg0);
			PrivateKey pk = (PrivateKey) ks.getKey(arg0, null);
			X500Principal name = cert.getSubjectX500Principal();
			PKCS10CertificationRequestBuilder crb = new JcaPKCS10CertificationRequestBuilder(name, cert.getPublicKey());
			PKCS10CertificationRequest req1 = crb.build(new JcaContentSignerBuilder(cert.getSigAlgName())
					.setProvider(new BouncyCastleProvider()).build(pk));
			JcaPKCS10CertificationRequest req2 = new JcaPKCS10CertificationRequest(req1.getEncoded())
					.setProvider(new BouncyCastleProvider());
			req = req2;
			nbefore = cert.getNotBefore();
			nafter = cert.getNotAfter();
			serial = cert.getSerialNumber();
		} catch (Exception e) {
			e.printStackTrace();
			return false;
		}
		return true;
	}

	@Override
	public String getIssuer(String arg0) {

		String name = "";

		KeyStore ks = KS.getInstance();
		try {
			X509Certificate cert = (X509Certificate) ks.getCertificate(arg0);
			X500Principal str = cert.getIssuerX500Principal();
			name = str.getName();

		} catch (Exception e) {
			e.printStackTrace();
		}
		return name;
	}

	@Override
	public String getIssuerPublicKeyAlgorithm(String arg0) {

		String name = "";

		KeyStore ks = KS.getInstance();
		try {
			X509Certificate cert = (X509Certificate) ks.getCertificate(arg0);
			name = cert.getPublicKey().getAlgorithm();
		} catch (Exception e) {

			e.printStackTrace();
		}
		return name;
	}

	@Override
	public List<String> getIssuers(String arg0) {

		KeyStore ks = KS.getInstance();
		X509Certificate cert;
		Enumeration<String> en = null;
		try {
			cert = (X509Certificate) ks.getCertificate(arg0);
			en = ks.aliases();
		} catch (KeyStoreException e) {
			e.printStackTrace();
			return null;
		}
		List<String> list = new ArrayList<>();
		X509Certificate storecert = null;

		while (en.hasMoreElements()) {
			String ali = (String) en.nextElement();
			try {
				storecert = (X509Certificate) ks.getCertificate(ali);
				boolean[] keyusage = storecert.getKeyUsage();
				if (keyusage != null) {
					if (keyusage[5] == true) {
						list.add(ali);
					}
				} else if (storecert.getBasicConstraints() != -1) {
					list.add(ali);
				}
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
		return list;
	}

	@Override
	public int getRSAKeyLength(String arg0) {

		int value = 0;
		try {
			KeyStore ks = KS.getInstance();
			X509Certificate cert = (X509Certificate) ks.getCertificate(arg0);
			String alg = cert.getPublicKey().getAlgorithm();
			if (alg.equals("RSA")) {
				value = ((RSAKey) cert.getPublicKey()).getModulus().bitLength();
			}
		} catch (KeyStoreException e) {
			e.printStackTrace();
		}
		return value;
	}

	@Override
	public boolean importCertificate(File arg0, String arg1) {

		FileInputStream fis;
		try {
			fis = new FileInputStream(arg0);
			CertificateFactory cf = CertificateFactory.getInstance("X509");
			X509Certificate cert = (X509Certificate) cf.generateCertificate(fis);
			fis.close();
			KeyStore ks = KS.getInstance();
			ks.setCertificateEntry(arg1, cert);
			FileOutputStream fos = new FileOutputStream(KS.getKSName());
			ks.store(fos, KS.getPassword());
			fos.close();
		} catch (Exception e) {
			e.printStackTrace();
			return false;
		}
		return true;
	}

	@Override
	public boolean importKeypair(String arg0, String arg1, String arg2) {

		try {
			KeyStore ks = KeyStore.getInstance("pkcs12");
			FileInputStream fis = new FileInputStream(arg1);
			ks.load(fis, arg2.toCharArray());
			fis.close();
			Certificate[] chain = ks.getCertificateChain(arg0);
			PrivateKey pk = (PrivateKey) ks.getKey(arg0, arg2.toCharArray());

			KeyStore ks1 = KS.getInstance();
			if (ks1 == null) {
				System.out.println("Greska u importKeypair");
			}
			ks1.setKeyEntry(arg0, pk, null, chain);
			FileOutputStream fos = new FileOutputStream(KS.getKSName());
			ks1.store(fos, KS.getPassword());
			fos.close();

		} catch (Exception e) {
			e.printStackTrace();
			return false;
		}

		return true;
	}

	
	@Override
	public int loadKeypair(String arg0) {

		KeyStore ks = KS.getInstance();
		int value = -1;
		if (ks == null) {
			return -1;
		}

		try {
			
			Certificate[] chain = ks.getCertificateChain(arg0);
			X509Certificate cert = (X509Certificate)chain[0];
			int n = chain.length;
			X509Certificate ca = (X509Certificate)chain[n-1];
			String subject = cert.getSubjectDN().getName();
			String issuerdn = ca.getIssuerDN().getName();
			String segment[] = subject.split(",");
			String subjectdn = "CN=" + segment[0].substring(segment[0].lastIndexOf("=") + 1);
			
			if (cert.getKeyUsage() != null) {
				boolean[] keyusage = cert.getKeyUsage();
				if ((keyusage[5] == true) && (cert.getBasicConstraints() != -1)) {
					value = 2;
				}} else if (subjectdn.equals(issuerdn) || (cert.getSerialNumber().equals(ca.getSerialNumber()))) {
				value = 0;
			} else
				value = 1;	
			X500Principal str = ca.getIssuerX500Principal();
			String name = str.getName();
			access.setIssuer(name);
			access.setIssuerSignatureAlgorithm(cert.getSigAlgName());
			X500Principal str1 = cert.getSubjectX500Principal();
			String name1 = str1.getName();
			access.setSubject(name1);
			access.setSubjectSignatureAlgorithm(cert.getSigAlgName());
			access.setNotBefore(cert.getNotBefore());
			access.setNotAfter(cert.getNotAfter());
			access.setPublicKeyECCurve(cert.getPublicKey().getAlgorithm());
			access.setVersion(cert.getVersion() - 1);

			if (cert.getVersion() != 0) {

				Collection<List<?>> altnames = null;
				altnames = cert.getSubjectAlternativeNames();
				if (altnames != null) {
					String names = "";
					Set<String> set = cert.getCriticalExtensionOIDs();
					for (List<?> list : altnames)
						for (Object st : list)
						{	String se = "";
							if(st instanceof String) se = (String)st;
							if(st instanceof Integer){
							int s = (Integer)st;
							if(s==0) {if (names.length() == 0) names += "otherName=" ; else {
								names += ",otherName=";
							}}
							else if(s==1) {if (names.length() == 0) names += "rfc822Name=" ; else {
								names += ",rfc822Name=";
							}}
							else if(s==2) {if (names.length() == 0) names += "DNSName=" ; else {
								names += ",DNSName=";
							}}
							else if(s==3) {if (names.length() == 0) names += "x400Address=" ; else {
								names += ",x400Address=";
							}}
							else if(s==4) {if (names.length() == 0) names += "directoryName=" ; else {
								names += ",directoryName=";
							}}
							else if(s==5) {if (names.length() == 0) names += "ediPartyName=" ; else {
								names += ",ediPartyName=";
							}}
							else if(s==6) {if (names.length() == 0) names += "uniformResourceIdentifier=" ; else {
								names += ",uniformResourceIdentifier=";
							}}
							else if(s==7) {if (names.length() == 0) names += "IPAddress=" ; else {
								names += ",IPAddress=";
							}}
							else if(s==8) {if (names.length() == 0) names += "registeredID=" ; else {
								names += ",registeredID=";
							}}}
		
							else names += "" + se;
							
						}
				
					access.setAlternativeName(5, names.toString());

					for (String s : set) {
						if (s.equals("2.5.29.17")) {
							access.setCritical(5, true);
							break;
						}
					}
				}

				access.setSerialNumber(cert.getSerialNumber() + "");
				
				byte[] arr = cert.getExtensionValue("2.5.29.32");
				if (arr != null) {
					Set<String> set = cert.getCriticalExtensionOIDs();
					String s = new String(arr);
					int num = s.indexOf("h");
					String ss = s.substring(num);
					access.setCpsUri(ss);
					
					for (String s1 : set) {
						if (s1.equals("2.5.29.32")) {
							access.setCritical(3, true);
							break;
						}
					}
				}
				
			}
			
			byte[] arr = cert.getExtensionValue("2.5.29.54");

			if (arr != null) {

				Set<String> set = cert.getCriticalExtensionOIDs();
				
				access.setSkipCerts(arr[4] + "");

				for (String s2 : set) {
					if (s2.equals("2.5.29.54")) {
						access.setCritical(13, true);
						break;
					}
				}

			}
		} catch (KeyStoreException e) {

			e.printStackTrace();
		} catch (CertificateParsingException e) {
			e.printStackTrace();
		}

		return value;
	}

	@Override
	public Enumeration<String> loadLocalKeystore() {

		try {
			return KS.getInstance().aliases();
		} catch (KeyStoreException e) {

			e.printStackTrace();
		}
		return null;
	}

	@Override
	public boolean removeKeypair(String arg0) {

		try {
			KS.getInstance().deleteEntry(arg0);
			KS.storeKS();
		} catch (KeyStoreException e) {
			return false;
		}
		return true;
	}

	@Override
	public void resetLocalKeystore() {

		File file = new File(KS.getKSName());
		file.delete();
		
	}

	@Override
	public boolean saveKeypair(String arg0) {

		try {
			
			String alg = access.getPublicKeyECCurve();
			
			ECParameterSpec aps = ECNamedCurveTable.getParameterSpec(alg);

			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ECDSA", new BouncyCastleProvider());
			SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
			keyGen.initialize(aps, random);
			KeyPair pair = keyGen.generateKeyPair();

			Date validityBeginDate = access.getNotBefore();
			Date validityEndDate = access.getNotAfter();

			X500Principal dnName = new X500Principal(access.getSubject());
			BigInteger bgint = new BigInteger(access.getSerialNumber() + "");
			String SignatureAlgorithm = access.getPublicKeySignatureAlgorithm();
			
			X509v3CertificateBuilder cb = new JcaX509v3CertificateBuilder(dnName, bgint, validityBeginDate,
					validityEndDate, dnName, pair.getPublic());

			String[] altnames = access.getAlternativeName(5);
			if (altnames.length > 0) {
				boolean value = access.isCritical(5);

				GeneralName[] names = new GeneralName[altnames.length];
				for (int i = 0; i < names.length; i++) {
					String type = altnames[i].substring(0,altnames[i].lastIndexOf("="));
					String altn = altnames[i].substring(altnames[i].lastIndexOf("=")+1);
					if(type.toLowerCase().contains("dns")){ names[i] = new GeneralName(GeneralName.dNSName, altn); }
					else if(type.toLowerCase().contains("ip")) { names[i] = new GeneralName(GeneralName.iPAddress, altn); }
					else if(type.toLowerCase().contains("rfc")) { names[i] = new GeneralName(GeneralName.rfc822Name, altn); }
					else if(type.toLowerCase().contains("directory")) { names[i] = new GeneralName(GeneralName.directoryName, altn); }
					else if(type.toLowerCase().contains("partyname")) { names[i] = new GeneralName(GeneralName.ediPartyName, altn); }
					else if(type.toLowerCase().contains("registeredid")) { names[i] = new GeneralName(GeneralName.registeredID, altn); }
					else if(type.toLowerCase().contains("uniformresource")) { names[i] = new GeneralName(GeneralName.uniformResourceIdentifier, altn); }
					else if(type.toLowerCase().contains("x400")) { names[i] = new GeneralName(GeneralName.x400Address, altn); }
					else if(type.toLowerCase().contains("other")) { names[i] = new GeneralName(GeneralName.otherName, altn); }
					else System.out.println("ERROR: Incorrect Subject Alternative Name type.");
				}
				cb.addExtension(Extension.subjectAlternativeName, value, new GeneralNames(names));

			}

			if (access.getInhibitAnyPolicy()) {
				boolean value = access.isCritical(13);
				String num = access.getSkipCerts();
				int num1 = Integer.parseInt(num);
				cb.addExtension(Extension.inhibitAnyPolicy, value, new DERInteger(num1));
			}

			if (access.getAnyPolicy()) {
				boolean value = access.isCritical(3);
				String url = access.getCpsUri();
				PolicyQualifierInfo info = new PolicyQualifierInfo(url);
				PolicyInformation pi = new PolicyInformation(new ASN1ObjectIdentifier("2.5.29.32"), new DERSequence(info));
				DERSequence seq = new DERSequence(pi);
				cb.addExtension(Extension.certificatePolicies, value, seq);
			
			}

			ContentSigner signer = new JcaContentSignerBuilder(SignatureAlgorithm)
					.setProvider(new BouncyCastleProvider()).build(pair.getPrivate());
			X509Certificate crt = new JcaX509CertificateConverter().setProvider(new BouncyCastleProvider())
					.getCertificate(cb.build(signer));
			
			X509Certificate[] chain = new X509Certificate[1];
			chain[0] = crt;
			
			KeyStore ks1 = KS.getInstance();
			ks1.setKeyEntry(arg0, pair.getPrivate(), null, chain);
			FileOutputStream fos = new FileOutputStream(KS.getKSName());
			ks1.store(fos, KS.getPassword());
			fos.close();
			
		} catch (Exception e) {
			e.printStackTrace();
			return false;
		}

		return true;
	}

	@Override
	public boolean signCertificate(String arg0, String arg1) {

		try {
			KeyStore ks = KS.getInstance();
			PrivateKey pk = (PrivateKey) ks.getKey(arg0, null);
			X509Certificate cert = (X509Certificate) ks.getCertificate(arg0);
			BigInteger bgint1 = serial; 
			Enumeration<String> en = ks.aliases();
			String alias = "";
			X500Name subj = req.getSubject();
			String commonName1 = subj.toString();
			String commonName = commonName1.substring(commonName1.indexOf("CN="));
			
			X509Certificate storecert = null;
			while (en.hasMoreElements()) {
				String ali = (String) en.nextElement();
				storecert = (X509Certificate) ks.getCertificate(ali);
				String name = storecert.getSubjectX500Principal().getName();
				String segments[] = name.split(",");
				String CN1 = segments[0].substring(segments[0].lastIndexOf("=") + 1);
				String CN = "CN="+CN1;
				
				if ((CN.equals(commonName)) && (storecert.getSerialNumber().equals(bgint1))) {
					alias = ali;
					break;
				} else {
					storecert = null;
				}
			}

			Date validityBeginDate = nbefore;
			Date validityEndDate = nafter;
			
			X500Principal issuer = cert.getIssuerX500Principal();
			X500Principal dnName = storecert.getSubjectX500Principal();
			BigInteger bgint = new BigInteger(storecert.getSerialNumber() + "");
			X509v3CertificateBuilder cb = new JcaX509v3CertificateBuilder(issuer, bgint, validityBeginDate, validityEndDate,
					dnName, storecert.getPublicKey());
			
			Collection<List<?>> altnames = null;
			altnames = storecert.getSubjectAlternativeNames();
			
			if(altnames != null){
			String[] altn = new String[altnames.size()];
			
			int i = 0;
			if (altnames != null) {
				String names = "";
				for (List<?> list : altnames)
					for (Object st : list)
					{	
						String se = "";
						if(st instanceof String) se = (String)st;
						if(st instanceof Integer){
							altn[i] = "";
						int s = (Integer)st;
						if(s==0) { altn[i] += "otherName=" ; }
						else if(s==1) { altn[i] += "rfc822Name=" ; }
						else if(s==2) { altn[i] += "DNSName=" ; }
						else if(s==3) { altn[i] += "x400Address=" ; }
						else if(s==4) { altn[i] += "directoryName=" ;}
						else if(s==5) { altn[i] += "ediPartyName=" ; }
						else if(s==6) { altn[i] += "uniformResourceIdentifier=" ; }
						else if(s==7) { altn[i] += "IPAddress=" ; }
						else if(s==8) { altn[i] += "registeredID=" ; }}
						
						else { altn[i] += "" + se; i++;}
						
					}
			
				
			}
			
			if (altn.length > 0) {
				boolean value = false;
				Set<String> set = storecert.getCriticalExtensionOIDs();
				GeneralName[] names = new GeneralName[altn.length];
				for (int k = 0; k < altn.length; k++) {
					String type = altn[k].substring(0,altn[k].lastIndexOf("="));
					String altna = altn[k].substring(altn[k].lastIndexOf("=")+1);
					if(type.toLowerCase().contains("dns")){ names[k] = new GeneralName(GeneralName.dNSName, altna); }
					else if(type.toLowerCase().contains("ip")) { names[k] = new GeneralName(GeneralName.iPAddress, altna); }
					else if(type.toLowerCase().contains("rfc")) { names[k] = new GeneralName(GeneralName.rfc822Name, altna); }
					else if(type.toLowerCase().contains("directory")) { names[k] = new GeneralName(GeneralName.directoryName, altna); }
					else if(type.toLowerCase().contains("partyname")) { names[k] = new GeneralName(GeneralName.ediPartyName, altna); }
					else if(type.toLowerCase().contains("registeredid")) { names[k] = new GeneralName(GeneralName.registeredID, altna); }
					else if(type.toLowerCase().contains("uniformresource")) { names[k] = new GeneralName(GeneralName.uniformResourceIdentifier, altna); }
					else if(type.toLowerCase().contains("x400")) { names[k] = new GeneralName(GeneralName.x400Address, altna); }
					else if(type.toLowerCase().contains("other")) { names[k] = new GeneralName(GeneralName.otherName, altna); }
					else System.out.println("ERROR: Incorrect Subject Alternative Name type.");
				}
				
				for (String s : set) {
					if (s.equals("2.5.29.17")) {
						value = true;
						break;
					}
				}
				cb.addExtension(Extension.subjectAlternativeName, value, new GeneralNames(names));
			}
			}
			byte[] set1 = storecert.getExtensionValue("2.5.29.54");
			if (set1 != null) {
				boolean value = false;
				Set<String> set = storecert.getCriticalExtensionOIDs();
				int num1 = set1[4];
				

				for (String s2 : set) {
					if (s2.equals("2.5.29.54")) {
						value = true;
						break;
					}
				}
				cb.addExtension(Extension.inhibitAnyPolicy, value, new DERInteger(num1));
			}
			
			byte[] set2 = storecert.getExtensionValue("2.5.29.32");
			if (set2 != null) {
				String ss = "";
				Set<String> set = storecert.getCriticalExtensionOIDs();
				boolean value = false;
				byte[] arr = storecert.getExtensionValue("2.5.29.32");
				if (arr != null) {

					String s = new String(arr);
					int num = s.indexOf("h");
					ss = s.substring(num);

					for (String s2 : set) {
						if (s2.equals("2.5.29.32")) {
							value = true;
							break;
						}
					}
				}

				PolicyQualifierInfo info = new PolicyQualifierInfo(ss);
				PolicyInformation pi = new PolicyInformation(new ASN1ObjectIdentifier("2.5.29.32"),
						new DERSequence(info));
				DERSequence seq = new DERSequence(pi);
				cb.addExtension(Extension.certificatePolicies, value, seq);
			}

			ContentSigner signer = new JcaContentSignerBuilder(arg1).setProvider(new BouncyCastleProvider()).build(pk);
			X509Certificate crt = new JcaX509CertificateConverter().setProvider(new BouncyCastleProvider())
					.getCertificate(cb.build(signer));

			X509Certificate[] chain = new X509Certificate[2];
			chain[0] = crt;
			chain[1] = cert;

			PrivateKey pk1 = (PrivateKey) ks.getKey(alias, null);
			ks.deleteEntry(alias);
			ks.setKeyEntry(alias, pk1, null, chain);
			FileOutputStream fis = new FileOutputStream(KS.getKSName());
			ks.store(fis, KS.getPassword());
			fis.close();
			
		} catch (Exception e) {
			System.out.print(e.getMessage());
			e.printStackTrace();
			return false;
		}
		return true;
	}

}
