package com.xyz.ws.security;

import java.io.IOException;
import java.net.URL;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.NodeSetData;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.XMLValidateContext;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.KeyValue;

import org.apache.ws.security.PublicKeyPrincipal;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSDataRef;
import org.apache.ws.security.WSDocInfo;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.WSSecurityEngine;
import org.apache.ws.security.WSSecurityEngineResult;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.WSUsernameTokenPrincipal;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoType;
import org.apache.ws.security.handler.RequestData;
import org.apache.ws.security.message.CallbackLookup;
import org.apache.ws.security.message.DOMCallbackLookup;
import org.apache.ws.security.message.token.SecurityTokenReference;
import org.apache.ws.security.processor.Processor;
import org.apache.ws.security.processor.ReferenceListProcessor;
import org.apache.ws.security.processor.SignatureProcessor;
import org.apache.ws.security.str.STRParser;
import org.apache.ws.security.str.SignatureSTRParser;
import org.apache.ws.security.transform.STRTransform;
import org.apache.ws.security.transform.STRTransformUtil;
import org.apache.ws.security.util.WSSecurityUtil;
import org.apache.ws.security.validate.Credential;
import org.apache.ws.security.validate.Validator;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import ru.CryptoPro.JCP.JCP;
import ru.CryptoPro.JCPxml.xmldsig.JCPXMLDSigInit;

public class LocalSignatureProcessor implements Processor {
	

    private static org.apache.commons.logging.Log LOG = org.apache.commons.logging.LogFactory.getLog(SignatureProcessor.class);
    
    private XMLSignatureFactory signatureFactory;
    private KeyInfoFactory keyInfoFactory;
    
    public LocalSignatureProcessor() {
    	init();
    }
    
    private void init() {
    	Class klass = XMLSignatureFactory.class;
    	URL location = klass.getResource('/'+klass.getName().replace('.', '/')+".class");
    	
    	klass = ru.CryptoPro.JCPxml.dsig.internal.dom.DOMXMLSignatureFactory.class;
    	location = klass.getResource('/'+klass.getName().replace('.', '/')+".class");
    	
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

        public List<WSSecurityEngineResult> handleToken(
            Element elem,
            RequestData data,
            WSDocInfo wsDocInfo 
        ) throws WSSecurityException {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Found signature element");
            }
            Element keyInfoElement = 
                WSSecurityUtil.getDirectChildElement(
                    elem,
                    "KeyInfo",
                    WSConstants.SIG_NS
                );
            X509Certificate[] certs = null;
            Principal principal = null;
            PublicKey publicKey = null;
            byte[] secretKey = null;
            String signatureMethod = getSignatureMethod(elem);

            Validator validator = data.getValidator(WSSecurityEngine.SIGNATURE);
            if (keyInfoElement == null) {
                certs = getDefaultCerts(data.getSigCrypto());
                principal = certs[0].getSubjectX500Principal();
            } else {
                List<Element> strElements = 
                    WSSecurityUtil.getDirectChildElements(
                        keyInfoElement,
                        SecurityTokenReference.SECURITY_TOKEN_REFERENCE,
                        WSConstants.WSSE_NS
                    );
                if (data.getWssConfig().isWsiBSPCompliant()) {
                    if (strElements.isEmpty()) {
                        throw new WSSecurityException(
                            WSSecurityException.INVALID_SECURITY, "noSecurityTokenReference"
                        );
                    } else if (strElements.size() > 1) {
                        throw new WSSecurityException(
                            WSSecurityException.INVALID_SECURITY, "badSecurityTokenReference"
                        );
                    }
                }
                    
                if (strElements.isEmpty()) {
                    publicKey = parseKeyValue(keyInfoElement);
                    if (validator != null) {
                        Credential credential = new Credential();
                        credential.setPublicKey(publicKey);
                        principal = new PublicKeyPrincipal(publicKey);
                        credential.setPrincipal(principal);
                        validator.validate(credential, data);
                    }
                } else {
                    STRParser strParser = new SignatureSTRParser();
                    Map<String, Object> parameters = new HashMap<String, Object>();
                    parameters.put(SignatureSTRParser.SIGNATURE_METHOD, signatureMethod);
                    parameters.put(
                        SignatureSTRParser.SECRET_KEY_LENGTH, new Integer(data.getWssConfig().getSecretKeyLength())
                    );
                    strParser.parseSecurityTokenReference(
                        strElements.get(0), data, wsDocInfo, parameters
                    );
                    principal = strParser.getPrincipal();
                    certs = strParser.getCertificates();
                    publicKey = strParser.getPublicKey();
                    secretKey = strParser.getSecretKey();
                    
                    boolean trusted = strParser.isTrustedCredential();
                    if (trusted && LOG.isDebugEnabled()) {
                        LOG.debug("Direct Trust for SAML/BST credential");
                    }
                    if (!trusted && (publicKey != null || certs != null) && (validator != null)) {
                        Credential credential = new Credential();
                        credential.setPublicKey(publicKey);
                        credential.setCertificates(certs);
                        credential.setPrincipal(principal);
                        validator.validate(credential, data);
                    }
                }
            }
            
            //
            // Check that we have a certificate, a public key or a secret key with which to
            // perform signature verification
            //
            if ((certs == null || certs.length == 0 || certs[0] == null) 
                && secretKey == null
                && publicKey == null) {
                throw new WSSecurityException(WSSecurityException.FAILED_CHECK);
            }
            
            XMLSignature xmlSignature = 
                verifyXMLSignature(elem, certs, publicKey, secretKey, signatureMethod, wsDocInfo);
            byte[] signatureValue = xmlSignature.getSignatureValue().getValue();
            String c14nMethod = xmlSignature.getSignedInfo().getCanonicalizationMethod().getAlgorithm();
            // The c14n algorithm must be as specified by the BSP spec
            if (data.getWssConfig().isWsiBSPCompliant() 
                && !WSConstants.C14N_EXCL_OMIT_COMMENTS.equals(c14nMethod)) {
                throw new WSSecurityException(
                    WSSecurityException.INVALID_SECURITY, "badC14nAlgo"
                );
            }
            List<WSDataRef> dataRefs =  
                buildProtectedRefs(
                    elem.getOwnerDocument(), xmlSignature.getSignedInfo(), data.getWssConfig(), wsDocInfo
                );
            if (dataRefs.size() == 0) {
                throw new WSSecurityException(WSSecurityException.FAILED_CHECK);
            }
            
            int actionPerformed = WSConstants.SIGN;
            if (principal instanceof WSUsernameTokenPrincipal) {
                actionPerformed = WSConstants.UT_SIGN;
            }

            WSSecurityEngineResult result = new WSSecurityEngineResult(
                    actionPerformed, principal,
                    certs, dataRefs, signatureValue);
            result.put(WSSecurityEngineResult.TAG_SIGNATURE_METHOD, signatureMethod);
            result.put(WSSecurityEngineResult.TAG_CANONICALIZATION_METHOD, c14nMethod);
            result.put(WSSecurityEngineResult.TAG_ID, elem.getAttribute("Id"));
            result.put(WSSecurityEngineResult.TAG_SECRET, secretKey);
            result.put(WSSecurityEngineResult.TAG_PUBLIC_KEY, publicKey);
            if (validator != null) {
                result.put(WSSecurityEngineResult.TAG_VALIDATED_TOKEN, Boolean.TRUE);
            }
            wsDocInfo.addResult(result);
            wsDocInfo.addTokenElement(elem);
            return java.util.Collections.singletonList(result);
        }
        
        /**
         * Get the default certificates from the KeyStore
         * @param crypto The Crypto object containing the default alias
         * @return The default certificates
         * @throws WSSecurityException
         */
        private X509Certificate[] getDefaultCerts(
            Crypto crypto
        ) throws WSSecurityException {
            if (crypto == null) {
                throw new WSSecurityException(WSSecurityException.FAILURE, "noSigCryptoFile");
            }
            if (crypto.getDefaultX509Identifier() != null) {
                CryptoType cryptoType = new CryptoType(CryptoType.TYPE.ALIAS);
                cryptoType.setAlias(crypto.getDefaultX509Identifier());
                return crypto.getX509Certificates(cryptoType);
            } else {
                throw new WSSecurityException(
                    WSSecurityException.INVALID_SECURITY, "unsupportedKeyInfo"
                );
            }
        }
        
        private PublicKey parseKeyValue(
            Element keyInfoElement
        ) throws WSSecurityException {
            KeyValue keyValue = null;
            try {
                //
                // Look for a KeyValue object
                //
                keyValue = getKeyValue(keyInfoElement);
            } catch (javax.xml.crypto.MarshalException ex) {
                throw new WSSecurityException(WSSecurityException.FAILED_CHECK, null, null, ex);
            } 

            if (keyValue != null) {
                try {
                    //
                    // Look for a Public Key in Key Value
                    //
                    return keyValue.getPublicKey();
                } catch (java.security.KeyException ex) {
                    LOG.error(ex.getMessage(), ex);
                    throw new WSSecurityException(WSSecurityException.FAILED_CHECK, null, null, ex);
                }     
            } else {
                throw new WSSecurityException(
                        WSSecurityException.INVALID_SECURITY, "unsupportedKeyInfo"
                );
            }
        }
        
        /**
         * Get the KeyValue object from the KeyInfo DOM element if it exists
         */
        private KeyValue getKeyValue(
            Element keyInfoElement
        ) throws MarshalException {
            XMLStructure keyInfoStructure = new DOMStructure(keyInfoElement);
            KeyInfo keyInfo = keyInfoFactory.unmarshalKeyInfo(keyInfoStructure);
            List<?> list = keyInfo.getContent();

            for (int i = 0; i < list.size(); i++) {
                XMLStructure xmlStructure = (XMLStructure) list.get(i);
                if (xmlStructure instanceof KeyValue) {
                    return (KeyValue)xmlStructure;
                }
            }
            return null;
        }
        

        /**
         * Verify the WS-Security signature.
         * 
         * The functions at first checks if then <code>KeyInfo</code> that is
         * contained in the signature contains standard X509 data. If yes then
         * get the certificate data via the standard <code>KeyInfo</code> methods.
         * 
         * Otherwise, if the <code>KeyInfo</code> info does not contain X509 data, check
         * if we can find a <code>wsse:SecurityTokenReference</code> element. If yes, the next
         * step is to check how to get the certificate. Two methods are currently supported
         * here:
         * <ul>
         * <li> A URI reference to a binary security token contained in the <code>wsse:Security
         * </code> header.  If the dereferenced token is
         * of the correct type the contained certificate is extracted.
         * </li>
         * <li> Issuer name an serial number of the certificate. In this case the method
         * looks up the certificate in the keystore via the <code>crypto</code> parameter.
         * </li>
         * </ul>
         * 
         * @param elem        the XMLSignature DOM Element.
         * @param crypto      the object that implements the access to the keystore and the
         *                    handling of certificates.
         * @param protectedRefs A list of (references) to the signed elements
         * @param cb CallbackHandler instance to extract key passwords
         * @return the subject principal of the validated X509 certificate (the
         *         authenticated subject). The calling function may use this
         *         principal for further authentication or authorization.
         * @throws WSSecurityException
         */
        private XMLSignature verifyXMLSignature(
            Element elem,
            X509Certificate[] certs,
            PublicKey publicKey,
            byte[] secretKey,
            String signatureMethod,
            WSDocInfo wsDocInfo
        ) throws WSSecurityException {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Verify XML Signature");
            }
            
            //
            // Perform the signature verification and build up a List of elements that the
            // signature refers to
            //
            Key key = null;
            if (certs != null && certs[0] != null) {
                key = certs[0].getPublicKey();
            } else if (publicKey != null) {
                key = publicKey;
            } else {
                key = WSSecurityUtil.prepareSecretKey(signatureMethod, secretKey);
            }
            
            XMLValidateContext context = new DOMValidateContext(key, elem);
            context.setProperty("javax.xml.crypto.dsig.cacheReference", Boolean.TRUE);
            context.setProperty(STRTransform.TRANSFORM_WS_DOC_INFO, wsDocInfo);
            
            try {
                XMLSignature xmlSignature = signatureFactory.unmarshalXMLSignature(context);
                setElementsOnContext(xmlSignature, (DOMValidateContext)context, wsDocInfo, elem.getOwnerDocument());
                boolean signatureOk = xmlSignature.validate(context);
                if (signatureOk) {
                    return xmlSignature;
                }
                //
                // Log the exact signature error
                //
                if (LOG.isDebugEnabled()) {
                    LOG.debug("XML Signature verification has failed");
                    boolean signatureValidationCheck = 
                        xmlSignature.getSignatureValue().validate(context);
                    LOG.debug("Signature Validation check: " + signatureValidationCheck);
                    java.util.Iterator<?> referenceIterator = 
                        xmlSignature.getSignedInfo().getReferences().iterator();
                    while (referenceIterator.hasNext()) {
                        Reference reference = (Reference)referenceIterator.next();
                        boolean referenceValidationCheck = reference.validate(context);
                        String id = reference.getId();
                        if (id == null) {
                            id = reference.getURI();
                        }
                        LOG.debug("Reference " + id + " check: " + referenceValidationCheck);
                    }
                }
            } catch (Exception ex) {
                throw new WSSecurityException(
                    WSSecurityException.FAILED_CHECK, null, null, ex
                );
            }
            throw new WSSecurityException(WSSecurityException.FAILED_CHECK);
        }
        
        /**
         * Retrieve the Reference elements and set them on the ValidateContext
         * @param xmlSignature the XMLSignature object to get the references from
         * @param context the ValidateContext
         * @param wsDocInfo the WSDocInfo object where tokens are stored
         * @param doc the owner document from which to find elements
         * @throws WSSecurityException
         */
        private void setElementsOnContext(
            XMLSignature xmlSignature, 
            DOMValidateContext context,
            WSDocInfo wsDocInfo,
            Document doc
        ) throws WSSecurityException {
            java.util.Iterator<?> referenceIterator = 
                xmlSignature.getSignedInfo().getReferences().iterator();
            CallbackLookup callbackLookup = wsDocInfo.getCallbackLookup();
            if (callbackLookup == null) {
                callbackLookup = new DOMCallbackLookup(doc);
            }
            while (referenceIterator.hasNext()) {
                Reference reference = (Reference)referenceIterator.next();
                String uri = reference.getURI();
                Element element = callbackLookup.getElement(uri, null, true);
                if (element == null) {
                    element = wsDocInfo.getTokenElement(uri);
                }
                if (element != null) {
                    WSSecurityUtil.storeElementInContext(((DOMValidateContext)context), element);
                }
            }
        }
        
        /**
         * Get the signature method algorithm URI from the associated signature element.
         * @param signatureElement The signature element
         * @return the signature method URI
         */
        private static String getSignatureMethod(
            Element signatureElement
        ) {
            Element signedInfoElement = 
                WSSecurityUtil.getDirectChildElement(
                    signatureElement,
                    "SignedInfo",
                    WSConstants.SIG_NS
                );
            if (signedInfoElement != null) {
                Element signatureMethodElement = 
                    WSSecurityUtil.getDirectChildElement(
                        signedInfoElement,
                        "SignatureMethod",
                        WSConstants.SIG_NS
                    );
                if (signatureMethodElement != null) {
                    return signatureMethodElement.getAttributeNS(null, "Algorithm");
                }
            }
            return null;
        }
        
        
        /**
         * This method digs into the Signature element to get the elements that
         * this Signature covers. Build the QName of these Elements and return them
         * to caller
         * @param doc The owning document
         * @param signedInfo The SignedInfo object
         * @param wssConfig A WSSConfig instance
         * @param protectedRefs A list of protected references
         * @return A list of protected references
         * @throws WSSecurityException
         */
        private List<WSDataRef> buildProtectedRefs(
            Document doc,
            SignedInfo signedInfo,
            WSSConfig wssConfig,
            WSDocInfo wsDocInfo
        ) throws WSSecurityException {
            List<WSDataRef> protectedRefs = new java.util.ArrayList<WSDataRef>();
            List<?> referencesList = signedInfo.getReferences();
            for (int i = 0; i < referencesList.size(); i++) {
                Reference siRef = (Reference)referencesList.get(i);
                String uri = siRef.getURI();
                
                if (!"".equals(uri)) {
                    Element se = null;
                    
                    List<?> transformsList = siRef.getTransforms();
                    
                    for (int j = 0; j < transformsList.size(); j++) {
                        
                        Transform transform = (Transform)transformsList.get(j);
                        
                        if (STRTransform.TRANSFORM_URI.equals(transform.getAlgorithm())) {
                            NodeSetData data = (NodeSetData)siRef.getDereferencedData();
                            if (data != null) {
                                java.util.Iterator<?> iter = data.iterator();
                                
                                Node securityTokenReference = null;
                                while (iter.hasNext()) {
                                    Node node = (Node)iter.next();
                                    if ("SecurityTokenReference".equals(node.getLocalName())) {
                                        securityTokenReference = node;
                                        break;
                                    }
                                }
                                
                                if (securityTokenReference != null) {
                                    SecurityTokenReference secTokenRef = 
                                        new SecurityTokenReference(
                                            (Element)securityTokenReference,
                                            wssConfig.isWsiBSPCompliant()
                                        );
                                    se = STRTransformUtil.dereferenceSTR(doc, secTokenRef, wsDocInfo);
                                }
                            }
                        }
                    }
                    
                    if (se == null) {
                        CallbackLookup callbackLookup = wsDocInfo.getCallbackLookup();
                        if (callbackLookup == null) {
                            callbackLookup = new DOMCallbackLookup(doc);
                        }
                        se = callbackLookup.getElement(uri, null, false);
                    }
                    if (se == null) {
                        throw new WSSecurityException(WSSecurityException.FAILED_CHECK);
                    }
                    
                    WSDataRef ref = new WSDataRef();
                    ref.setWsuId(uri);
                    ref.setProtectedElement(se);
                    ref.setAlgorithm(signedInfo.getSignatureMethod().getAlgorithm());
                    ref.setDigestAlgorithm(siRef.getDigestMethod().getAlgorithm());
                    ref.setXpath(ReferenceListProcessor.getXPath(se));
                    protectedRefs.add(ref);
                }
            }
            return protectedRefs;
        }
        
        

    }
