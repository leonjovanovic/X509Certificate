package implementation;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.StringWriter;
import java.io.Writer;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECParameterSpec;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.Vector;


import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DLSet;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.Attribute;
import org.bouncycastle.asn1.x500.DirectoryString;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectDirectoryAttributes;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.Store;

import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;

import code.GuiException;
import gui.Constants;
import x509.v3.CodeV3;

public class MyCode extends CodeV3{

	private static final String password = "root";
	private static final String localKS = "LocalKeyStore.p12";
	private KeyStore keyStore;
	private SubjectPublicKeyInfo pkInfo;
	
	public MyCode(boolean[] algorithm_conf, boolean[] extensions_conf, boolean extensions_rules) throws GuiException {
		super(algorithm_conf, extensions_conf, extensions_rules);
		try {
			if(keyStore==null) {
				keyStore = KeyStore.getInstance("pkcs12");
				keyStore.load(null, null);
			}
			Security.addProvider(new BouncyCastleProvider());
		} catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	@Override
	public boolean canSign(String arg0) {
		try {
			return ((X509Certificate)keyStore.getCertificate(arg0)).getBasicConstraints()!=-1;
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return false;
	}

	@Override
	public boolean exportCSR(String arg0, String arg1, String arg2) {//file, key_pair, algorithm
		try {
			X509Certificate x509 = (X509Certificate) keyStore.getCertificate(arg1);
			JcaPKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(new JcaX509CertificateHolder(x509).getSubject(), x509.getPublicKey());
			PrivateKey privateKey = (PrivateKey)keyStore.getKey(arg1, password.toCharArray());
			ContentSigner signer = new JcaContentSignerBuilder(arg2).build(privateKey);

			PKCS10CertificationRequest pkcs10 = builder.build(signer);
			JcaPEMWriter pem = new JcaPEMWriter( new FileWriter(arg0));
			pem.writeObject(pkcs10);
			pem.flush();
			pem.close();
			return true;
		} catch (KeyStoreException | CertificateEncodingException | UnrecoverableKeyException | NoSuchAlgorithmException | OperatorCreationException | IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return false;
	}

	@Override
	public boolean exportCertificate(String arg0, String arg1, int arg2, int arg3) {//file, key_pair, encoding(0-DER,1-PEM), format(0-Head, 1-Ceo lanac)
		try {
			if(!keyStore.containsAlias(arg1)) return false;
			Certificate x509 = (X509Certificate)keyStore.getCertificate(arg1);
			Certificate[] chain = keyStore.getCertificateChain(arg1);
			FileOutputStream file = new FileOutputStream(new File(arg0));

			if(arg2 == 0) {//DER moze samo Head only(arg3=0)
				file.write(x509.getEncoded());
			}else {//PEM
				Writer writer = new FileWriter(arg0);
				JcaPEMWriter pemWriter = new JcaPEMWriter(writer);
				if(arg3==0) {//Head only
					pemWriter.writeObject(x509);
				}
				else {//Ceo chain
					for(int i = 0; i<chain.length;i++) {
						pemWriter.writeObject(chain[i]);
					}
				}
				pemWriter.flush();
				pemWriter.close();
				writer.close();
			}
			file.close();
			return true;
				
		} catch (KeyStoreException | IOException | CertificateEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return false;
	}

	@Override
	public boolean exportKeypair(String arg0, String arg1, String arg2) {//keypair_name, file, password
		try {
			if(!keyStore.containsAlias(arg0)) return false;
			KeyStore temp = KeyStore.getInstance("PKCS12");//pravimo novi KeyStore
			temp.load(null,null);//Inicijalizujemo ga
			//X509Certificate x509 = (X509Certificate)keyStore.getCertificate(arg0);
			//Ubacujemo kljuc iz keyStora u temp Key Store
			temp.setKeyEntry(arg0, keyStore.getKey(arg0, arg2.toCharArray()) , arg2.toCharArray(), keyStore.getCertificateChain(arg0));
			FileOutputStream file = new FileOutputStream(arg1);//pravimo fajl sa arg1 nazivom
			temp.store(file, password.toCharArray());
			file.close();
			return true;
		} catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException | UnrecoverableKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return false;
	}

	@Override
	public String getCertPublicKeyAlgorithm(String arg0) {
		try {
			X509Certificate x509 = (X509Certificate)keyStore.getCertificate(arg0);
			return x509.getPublicKey().getAlgorithm();
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}

	@Override
	public String getCertPublicKeyParameter(String arg0) {
		try {
			int len = 0;
			X509Certificate x509 = (X509Certificate)keyStore.getCertificate(arg0);
			switch(getCertPublicKeyAlgorithm(arg0)) {
			  case "DSA":
				  len = (((DSAPublicKey)x509.getPublicKey()).getY().bitLength())>1500?2048:1024;
				  break;
			  case "RSA":
				  len = (((RSAPublicKey)x509.getPublicKey()).getModulus().bitLength());
				  if(len<1500)len=1024;
				  else if(len<3000)len=2048;
				  else len = 4096;
				  break;
			  case "EC":
				  ECParameterSpec curve = ((ECPrivateKey)keyStore.getKey(arg0, password.toCharArray())).getParams();
				  return curve.getCurve().toString();
			  default:
			}
			return String.valueOf(len);
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (UnrecoverableKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}

	@Override
	public String getSubjectInfo(String arg0) {
		try {
			X509Certificate x509= (X509Certificate)keyStore.getCertificate(arg0);
			String ret = "";
			ret+=x509.getSubjectDN().toString()+",SA="+x509.getSigAlgName();
			ret=ret.replace(", ", ",");
			return ret;
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return null;
	}

	@Override
	public boolean importCAReply(String arg0, String arg1) {//file,key_pair
		File file = new File(arg0);
		if(!file.exists()) return false;
		try {
			FileInputStream fileIn = new FileInputStream(file);
			CMSSignedData data = new CMSSignedData(fileIn);
			//X509Certificate x509 = (X509Certificate)keyStore.getCertificate(arg1);
			//X509CertificateHolder x509Holder = new JcaX509CertificateHolder(x509);
			Store<X509CertificateHolder> store = data.getCertificates();
			Collection<X509CertificateHolder> coll = store.getMatches(null);//parametar Selector je null
			//da napravimo novi chain
			X509Certificate[] chain = new X509Certificate[coll.size()];//chain je duzine broj sertifikata u CMS fajlu
			int i = 0;
			for(X509CertificateHolder holder: coll) {
				chain[i]= new JcaX509CertificateConverter().setProvider(new BouncyCastleProvider()).getCertificate(holder);
				i++;
			}
			
			PrivateKey key = (PrivateKey)keyStore.getKey(arg1, password.toCharArray());
			//holder da bi proverili da li je vec potpisan tj da li je Subject == Issuer
			/*if(x509Holder.getIssuer().equals(x509Holder.getSubject())) {
				GuiV3.reportError("Certificate already signed!");
				return false;
			}*/
			
			keyStore.deleteEntry(arg1);
			keyStore.setKeyEntry(arg1, key , password.toCharArray(), chain);
			
			//Upis u lokalno skladiste
			FileOutputStream file1 = new FileOutputStream(localKS);
			keyStore.store(file1, password.toCharArray());
			file1.close();
			return true;
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CMSException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (UnrecoverableKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public String importCSR(String arg0) {
		try {
			if(!arg0.contains(".csr"))return null;
			PEMParser parser = new PEMParser(new FileReader(arg0));
			PKCS10CertificationRequest csr = (PKCS10CertificationRequest) parser.readObject();
			parser.close();
			
			pkInfo = csr.getSubjectPublicKeyInfo();
			String alg;
			if(PublicKeyFactory.createKey(pkInfo) instanceof RSAKeyParameters) alg = "RSA";
			else alg = "DSA";

			String ret = csr.getSubject().toString()+ ",SA="+alg;
			return ret;
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}

	@Override
	public boolean importCertificate(String arg0, String arg1) {//file, key_pair
    	//if(!(arg0.contains(".cer")||arg0.contains(".crt")||arg0.contains(".der")||arg0.contains(".pem"))) return false;
    	try {
    		FileInputStream file = new FileInputStream(arg0);
    		keyStore.setCertificateEntry(arg1, (Certificate)CertificateFactory.getInstance("X.509", "BC").generateCertificate(file));    		
    		file.close();
    		
			//Upis u lokalno skladiste
			FileOutputStream file1 = new FileOutputStream(localKS);
			keyStore.store(file1, password.toCharArray());
			file1.close();
    		return true;
		} catch (KeyStoreException | CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return false;
		} catch (FileNotFoundException e) {
			System.out.println("Fajl se ne nalazi na datoj lokaciji!");
			return false;
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return false;
	}

	@Override
	public boolean importKeypair(String arg0, String arg1, String arg2) {
    	if(!arg1.contains(".p12")) return false;
        try {
        	KeyStore temp = KeyStore.getInstance("pkcs12");
			temp.load(new FileInputStream(arg1), arg2.toCharArray());
			if(temp.getKey(arg0, arg2.toCharArray()) == null) return false;
			keyStore.setKeyEntry(arg0, temp.getKey(arg0, password.toCharArray()), password.toCharArray(), temp.getCertificateChain(arg0));
			//Upis u lokalno skladiste
			FileOutputStream file = new FileOutputStream(localKS);
			keyStore.store(file, password.toCharArray());
			file.close();
        } catch (KeyStoreException | UnrecoverableKeyException | NoSuchAlgorithmException | CertificateException e ) {
			e.printStackTrace();
			return false;
		} catch (FileNotFoundException e) {
			System.out.println("Fajl se ne nalazi na datoj lokaciji!");
			return false;
		} catch (IOException e) {
			System.out.println("Pogresna lozinka!");
			return false;
		}
		return true;
	}

	@Override
	public int loadKeypair(String arg0) { 
		try {
			Certificate cert = keyStore.getCertificate(arg0);
			if(cert == null) return -1;
			X509Certificate x509 = (X509Certificate)cert;
			setSubjectInfo(x509);
			setCAInfo(x509);
			this.access.setVersion(2);//Version 3
			this.access.setSerialNumber(x509.getSerialNumber().toString());
			this.access.setNotAfter(x509.getNotAfter());
			this.access.setNotBefore(x509.getNotBefore());
			this.access.setPublicKeyAlgorithm(x509.getPublicKey().getAlgorithm());
			this.access.setPublicKeyParameter(getCertPublicKeyParameter(arg0));
			this.access.setPublicKeyDigestAlgorithm(x509.getSigAlgName());
			if(x509.getPublicKey().getAlgorithm()=="EC") {
				this.access.setPublicKeyECCurve(getCertPublicKeyParameter(arg0));//curve
				/*ECParameterSpec curve = ((ECPrivateKey)keyStore.getKey(arg0, password.toCharArray())).getParams();
				System.out.println(curve.getCurve());
				System.out.println(curve.getCofactor());
				System.out.println(curve.getGenerator());
				System.out.println(curve.getOrder());
				//this.access.setPublicKeyParameter();*/
			}
			//***Ekstenzije***
			setKeyUsage(x509);
			setSubjectDirectoryAttribute(x509);
			setBasicConstraints(x509);
			if(keyStore.isCertificateEntry(arg0)) return 2;
			else if(x509.getIssuerX500Principal().getName().equals(x509.getSubjectX500Principal().getName()))return 0;
			else return 1;
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return 0;
	}
	
	void setSubjectInfo(X509Certificate x509) {
		//****Subject info******
		X500Name x500name;
		try {
			x500name = new org.bouncycastle.cert.jcajce.JcaX509CertificateHolder(x509).getSubject();		
			RDN cn;
			//Country/
			if(x500name.getRDNs(BCStyle.C).length!=0) {
				cn = x500name.getRDNs(BCStyle.C)[0];
				this.access.setSubjectCountry(IETFUtils.valueToString(cn.getFirst().getValue()));
			}
			//State
			if(x500name.getRDNs(BCStyle.ST).length!=0) {
				cn = x500name.getRDNs(BCStyle.ST)[0];
				this.access.setSubjectState(IETFUtils.valueToString(cn.getFirst().getValue()));
			}
			//Locality
			if(x500name.getRDNs(BCStyle.L).length!=0) {
				cn = x500name.getRDNs(BCStyle.L)[0];
				this.access.setSubjectLocality(IETFUtils.valueToString(cn.getFirst().getValue()));
			}
			//Organization
			if(x500name.getRDNs(BCStyle.O).length!=0) {
				cn = x500name.getRDNs(BCStyle.O)[0];
				this.access.setSubjectOrganization(IETFUtils.valueToString(cn.getFirst().getValue()));
			}
			//Organization Unit
			if(x500name.getRDNs(BCStyle.OU).length!=0) {
				cn = x500name.getRDNs(BCStyle.OU)[0];
				this.access.setSubjectOrganizationUnit(IETFUtils.valueToString(cn.getFirst().getValue()));
			}
			//Common Name
			if(x500name.getRDNs(BCStyle.CN).length!=0) {
				cn = x500name.getRDNs(BCStyle.CN)[0];
				this.access.setSubjectCommonName(IETFUtils.valueToString(cn.getFirst().getValue()));
			}
			//Public key algorithm
			this.access.setSubjectSignatureAlgorithm(x509.getPublicKey().getAlgorithm());
		
		} catch (CertificateEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	void setCAInfo(X509Certificate x509) {
		//*****CA Info****
		X500Name x500name;
		try {
			x500name = new org.bouncycastle.cert.jcajce.JcaX509CertificateHolder(x509).getIssuer();
			this.access.setIssuer(x500name.toString());
			this.access.setIssuerSignatureAlgorithm(x509.getSigAlgName());
		} catch (CertificateEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	void setKeyUsage(X509Certificate x509) {
		if(x509.getKeyUsage()==null)return;
		this.access.setKeyUsage(x509.getKeyUsage());
		JcaX509CertificateHolder x509Holder;
		try {
			x509Holder = new JcaX509CertificateHolder(x509);
			if (x509Holder.getExtension(Extension.keyUsage).isCritical())
				this.access.setCritical(Constants.KU, true);
			else
				this.access.setCritical(Constants.KU, false);
		} catch (CertificateEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}				
	}
	
	void setSubjectDirectoryAttribute(X509Certificate x509) {
		//**** Subject directory attributes ******
		JcaX509CertificateHolder x509Holder;
		try {
			x509Holder = new JcaX509CertificateHolder(x509);
			if(x509Holder.getExtensions().getExtension(Extension.subjectDirectoryAttributes) == null) return;
			ASN1Encodable ext = x509Holder.getExtensions().getExtension(Extension.subjectDirectoryAttributes).getParsedValue();
			@SuppressWarnings("unchecked")
			Vector<Attribute> attributes = (Vector<Attribute>) (SubjectDirectoryAttributes.getInstance(ext)).getAttributes();

			Attribute a = attributes.get(0);
			this.access.setDateOfBirth(a.getAttrValues().toString().substring(1, a.getAttrValues().toString().length()-1));
			a = attributes.get(1);
			this.access.setSubjectDirectoryAttribute(Constants.POB,a.getAttrValues().toString().substring(1, a.getAttrValues().toString().length()-1));
			a = attributes.get(2);
			this.access.setSubjectDirectoryAttribute(Constants.COC,a.getAttrValues().toString().substring(1, a.getAttrValues().toString().length()-1));
			a = attributes.get(3);
			this.access.setGender(a.getAttrValues().toString().substring(1, a.getAttrValues().toString().length()-1));		
			if (x509Holder.getExtension(Extension.subjectDirectoryAttributes).isCritical())
				this.access.setCritical(Constants.SDA, true);
			else
				this.access.setCritical(Constants.SDA, false);
		} catch (CertificateEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	void setBasicConstraints(X509Certificate x509) {
		if(x509.getBasicConstraints()==0)return;	
		if(x509.getBasicConstraints()!=-1) this.access.setCA(true);
		else this.access.setCA(false);
		if(x509.getBasicConstraints()!=-1)this.access.setPathLen(String.valueOf(x509.getBasicConstraints()));
		JcaX509CertificateHolder x509Holder;
		try {
			x509Holder = new JcaX509CertificateHolder(x509);
			if (x509Holder.getExtension(Extension.basicConstraints).isCritical())
				this.access.setCritical(Constants.BC, true);
			else
				this.access.setCritical(Constants.BC, false);
		} catch (CertificateEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	@Override
	public Enumeration<String> loadLocalKeystore() {
		try {			
        	KeyStore temp = KeyStore.getInstance("pkcs12");
        	File fileIn = new File(localKS);
        	if(fileIn.exists()) {
    			keyStore = KeyStore.getInstance("pkcs12");
    			keyStore.load(new FileInputStream(fileIn), password.toCharArray());
        	}else {
        		FileOutputStream file = new FileOutputStream(localKS);//pravimo fajl sa arg1 nazivom
            	temp.load(null, null);
    			temp.store(file, password.toCharArray());
    			file.close();
        	}
			if(keyStore != null) return keyStore.aliases();
			else return null;
		} catch (KeyStoreException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}

	@Override
	public boolean removeKeypair(String arg0) {
		try {
			if(!keyStore.containsAlias(arg0)) return false;
			keyStore.deleteEntry(arg0);
			return true;
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return false;
	}

	@Override
	public void resetLocalKeystore() {
		try {
			keyStore = KeyStore.getInstance("pkcs12");
			keyStore.load(null, null);
		} catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}

	@Override
	public boolean saveKeypair(String arg0) {
		Provider bcProvider = new BouncyCastleProvider();
		Security.addProvider(bcProvider);
		
		Date startDate = this.access.getNotBefore();
		Date endDate = this.access.getNotAfter();
		X500Name subject = new X500Name(this.access.getSubject());
		BigInteger certSerialNumber = new BigInteger(this.access.getSerialNumber());
		//String PKAlgorithm = this.access.getPublicKeyAlgorithm();//DSA
		int keysize = Integer.valueOf(this.access.getPublicKeyParameter());//1024/2048
		String PKSignatureAlgorithm = this.access.getPublicKeyDigestAlgorithm();//SHA1withDSA		
		
		BasicConstraints bc;
		if(this.access.isCA()) {
			if(!this.access.getPathLen().isEmpty())bc = new BasicConstraints(Integer.valueOf(this.access.getPathLen()));//ako je CA dodaj duzinu
			else bc = new BasicConstraints(Integer.MAX_VALUE);
		}
		else bc = new BasicConstraints(this.access.isCA());//ako nije samo reci da nije
		
		KeyUsage ku=null;
		if(this.access.getKeyUsage()!=null) {
			int param=0;
			for(int i = 0;i<8;i++) 
				if(this.access.getKeyUsage()[i]) param=param | (int)Math.pow(2, 7-i);
			if(this.access.getKeyUsage()[8]) param=param | KeyUsage.decipherOnly;
			ku = new KeyUsage(param);
		}
		
		SubjectDirectoryAttributes sda=null;
		if(!(this.access.getDateOfBirth()=="" && this.access.getSubjectDirectoryAttribute(Constants.POB)=="" && this.access.getSubjectDirectoryAttribute(Constants.COC)=="" && this.access.getGender()=="")) {
			Vector<Attribute> attributes = new Vector<Attribute>();
			Attribute a = new Attribute(BCStyle.DATE_OF_BIRTH, new DLSet(new DirectoryString(this.access.getDateOfBirth())));
			attributes.add(a);
			a = new Attribute(BCStyle.PLACE_OF_BIRTH, new DLSet(new DirectoryString(this.access.getSubjectDirectoryAttribute(Constants.POB))));
			attributes.add(a);
			a = new Attribute(BCStyle.COUNTRY_OF_CITIZENSHIP, new DLSet(new DirectoryString(this.access.getSubjectDirectoryAttribute(Constants.COC))));
			attributes.add(a);
			a = new Attribute(BCStyle.GENDER, new DLSet(new DirectoryString(this.access.getGender())));
			attributes.add(a);
			sda = new SubjectDirectoryAttributes(attributes);			
		}
		
		try {
			KeyPairGenerator gen = KeyPairGenerator.getInstance("DSA", bcProvider);
			gen.initialize(keysize);
			KeyPair key = gen.generateKeyPair();
			
			ContentSigner contentSigner = new JcaContentSignerBuilder(PKSignatureAlgorithm).build(key.getPrivate());
			JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(subject, certSerialNumber, startDate, endDate, subject, key.getPublic());
			
			if(bc!=null)certBuilder.addExtension(new ASN1ObjectIdentifier("2.5.29.19"), this.access.isCritical(Constants.BC), bc);
			if(ku!=null)certBuilder.addExtension(new ASN1ObjectIdentifier("2.5.29.15"), true, ku);
			if(sda!=null)certBuilder.addExtension(new ASN1ObjectIdentifier("2.5.29.9"), this.access.isCritical(Constants.SDA), sda);
			
			X509Certificate x509 = new JcaX509CertificateConverter().setProvider(bcProvider)
.getCertificate(certBuilder.build(contentSigner));	
			
			X509Certificate[] chain = new X509Certificate[1]; //posto je selfsigned on je pocetak lanca
			chain[0] = x509;
			
			keyStore.setKeyEntry(arg0, key.getPrivate(), password.toCharArray(), chain);//Ubacujemo kljuceve u keyStore	
			//Upis u lokalno skladiste
			FileOutputStream file = new FileOutputStream(localKS);
			keyStore.store(file, password.toCharArray());
			file.close();
			return true;
			
		} catch (NoSuchAlgorithmException | CertIOException | CertificateException | OperatorCreationException | KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return false;
		
	}

	@Override
	public boolean signCSR(String arg0, String arg1, String arg2) {//file, key_pair, algorithm
		try {
			Certificate x509 = (Certificate)keyStore.getCertificate(arg1); //Issuer On potpisuje
			Certificate[] chain = (Certificate[])keyStore.getCertificateChain(arg1);
			
			PrivateKey privateKey = (PrivateKey) keyStore.getKey(arg1, password.toCharArray());//njegovim privatnim kljucem
			
			X509CertificateHolder holder = new X509CertificateHolder(x509.getEncoded());
			X500Name name = new X500Name(this.access.getSubject());
			BigInteger serial = new BigInteger(this.access.getSerialNumber());//serijski broj sertifikata koji potpisujemo
			X509v3CertificateBuilder builder = new X509v3CertificateBuilder(holder.getSubject(), serial, this.access.getNotBefore(), this.access.getNotAfter(), name, pkInfo);
			
			//*********Ekstenzije************
			//Basic Constraints
			BasicConstraints bc;
			if(this.access.isCA()) {
				if(!this.access.getPathLen().isEmpty())bc = new BasicConstraints(Integer.valueOf(this.access.getPathLen()));//ako je CA dodaj duzinu
				else bc = new BasicConstraints(Integer.MAX_VALUE);
			}
			else bc = new BasicConstraints(this.access.isCA());//ako nije samo reci da nije
			//KeyUsage
			KeyUsage ku=null;
			if(this.access.getKeyUsage()!=null) {
				int param=0;
				for(int i = 0;i<8;i++) 
					if(this.access.getKeyUsage()[i]) param=param | (int)Math.pow(2, 7-i);
				if(this.access.getKeyUsage()[8]) param=param | KeyUsage.decipherOnly;
				ku = new KeyUsage(param);
			}
			//SubjectDirectoryAttributes
			SubjectDirectoryAttributes sda=null;
			if(!(this.access.getDateOfBirth()=="" && this.access.getSubjectDirectoryAttribute(Constants.POB)=="" && this.access.getSubjectDirectoryAttribute(Constants.COC)=="" && this.access.getGender()=="")) {
				Vector<Attribute> attributes = new Vector<Attribute>();
				Attribute a = new Attribute(BCStyle.DATE_OF_BIRTH, new DLSet(new DirectoryString(this.access.getDateOfBirth())));
				attributes.add(a);
				a = new Attribute(BCStyle.PLACE_OF_BIRTH, new DLSet(new DirectoryString(this.access.getSubjectDirectoryAttribute(Constants.POB))));
				attributes.add(a);
				a = new Attribute(BCStyle.COUNTRY_OF_CITIZENSHIP, new DLSet(new DirectoryString(this.access.getSubjectDirectoryAttribute(Constants.COC))));
				attributes.add(a);
				a = new Attribute(BCStyle.GENDER, new DLSet(new DirectoryString(this.access.getGender())));
				attributes.add(a);
				sda = new SubjectDirectoryAttributes(attributes);			
			}
			if(bc!=null)builder.addExtension(new ASN1ObjectIdentifier("2.5.29.19"), this.access.isCritical(Constants.BC), bc);
			if(ku!=null)builder.addExtension(new ASN1ObjectIdentifier("2.5.29.15"), true, ku);
			if(sda!=null)builder.addExtension(new ASN1ObjectIdentifier("2.5.29.9"), this.access.isCritical(Constants.SDA), sda);
			//*****************************************
			
			
			ContentSigner signer = new JcaContentSignerBuilder(arg2).build(privateKey);//pravimo potpisioca
			CMSSignedDataGenerator gen = new CMSSignedDataGenerator();//generator potpisanog cms
			X509Certificate signedX509 = new JcaX509CertificateConverter().getCertificate(builder.build(signer));//napravljenom sertifikatu dodajemo potpis
			ArrayList<Certificate> listX509 = new ArrayList<>();
			listX509.add(signedX509);//dodajemo u praznu listu potpisan sertifikat
			for(Certificate cert: chain) listX509.add(cert);//kao i sve ostale u lancu
			gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().build()).build(signer, new X509CertificateHolder(x509.getEncoded())));
			gen.addCertificates( new JcaCertStore(listX509));//Mora da se doda Store ciji je argument lista X509 sert
			//Generate a CMS Signed Data object which is carrying encapsulated data (drugi param je true)
			CMSSignedData data = gen.generate(new CMSProcessableByteArray(PKCSObjectIdentifiers.x509Certificate, signedX509.getEncoded()), true);
			
			File file = new File(arg0);
			if(file.exists())file.delete();
			FileOutputStream fileOut = new FileOutputStream(file);
			fileOut.write(data.getEncoded());
			fileOut.close();
			return true;			
			
		} catch (UnrecoverableKeyException | KeyStoreException | NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertificateEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (OperatorCreationException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CMSException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return false;
	}

}
