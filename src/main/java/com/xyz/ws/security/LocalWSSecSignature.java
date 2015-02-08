package com.xyz.ws.security;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CertificateException;

import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;

import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.message.WSSecSignature;

import ru.CryptoPro.JCP.JCP;
import ru.CryptoPro.JCPxml.xmldsig.JCPXMLDSigInit;

public class LocalWSSecSignature extends WSSecSignature {
	 
	 public LocalWSSecSignature() {
	  super();
	  init();
	 }
	 
	 public LocalWSSecSignature(WSSConfig config) {
	  super(config);
	  init();
	 }
	 
	 private void init() {
	  Provider jceProvider = loadJceProvider();
	  signatureFactory = XMLSignatureFactory.getInstance("DOM", jceProvider);
	  keyInfoFactory = KeyInfoFactory.getInstance("DOM", jceProvider);
	 }
	 
	 private Provider loadJceProvider() {
	  Provider jceProvider = Security.getProvider("CryptoProXMLDSig");
	  if(jceProvider == null) {
		// Инициализация сервис-провайдера.
	    	if(!JCPXMLDSigInit.isInitialized()) {
	    	    JCPXMLDSigInit.init();
	    	}
	    	
	    	// Инициализация ключевого контейнера и получение сертификата и закрытого ключа.
	        KeyStore keyStore = null;
			try {
				keyStore = KeyStore.getInstance(JCP.HD_STORE_NAME);
				keyStore.load(null, "".toCharArray());
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
	        
	        
	   jceProvider = new ru.CryptoPro.JCPxml.dsig.internal.dom.XMLDSigRI();
	   Security.addProvider(jceProvider);
	  }
	  return jceProvider;
	 }
	}