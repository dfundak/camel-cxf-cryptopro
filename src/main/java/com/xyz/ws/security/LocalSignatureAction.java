package com.xyz.ws.security;

import javax.security.auth.callback.CallbackHandler;

import org.apache.ws.security.WSPasswordCallback;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.action.Action;
import org.apache.ws.security.handler.RequestData;
import org.apache.ws.security.handler.WSHandler;
import org.apache.ws.security.message.WSSecSignature;
import org.w3c.dom.Document;

public class LocalSignatureAction implements Action {
    public void execute(WSHandler handler, int actionToDo, Document doc, RequestData reqData)
            throws WSSecurityException {
    	
        CallbackHandler callbackHandler = handler.getPasswordCallbackHandler(reqData);
        WSPasswordCallback passwordCallback = handler.getPasswordCB(reqData.getSignatureUser(), actionToDo, callbackHandler, reqData);
        
        LocalWSSecSignature wsSign = loadWSSecSignature(reqData);
        
        if (reqData.getSigKeyId() != 0) {
            wsSign.setKeyIdentifierType(reqData.getSigKeyId());
        }
        if (reqData.getSigAlgorithm() != null) {
            wsSign.setSignatureAlgorithm(reqData.getSigAlgorithm());
        }
        if (reqData.getSigDigestAlgorithm() != null) {
            wsSign.setDigestAlgo(reqData.getSigDigestAlgorithm());
        }

        wsSign.setUserInfo(reqData.getSignatureUser(), passwordCallback.getPassword());
        wsSign.setUseSingleCertificate(reqData.isUseSingleCert());
        if (reqData.getSignatureParts().size() > 0) {
            wsSign.setParts(reqData.getSignatureParts());
        }
        
        if (passwordCallback.getKey() != null) {
            wsSign.setSecretKey(passwordCallback.getKey());
        }

        try {
            wsSign.build(doc, reqData.getSigCrypto(), reqData.getSecHeader());
            reqData.getSignatureValues().add(wsSign.getSignatureValue());
        } catch (WSSecurityException e) {
            throw new WSSecurityException("Error during Signature: ", e);
        }
    }
    
	protected LocalWSSecSignature loadWSSecSignature(RequestData reqData) {
		LocalWSSecSignature wsSign = new LocalWSSecSignature(
				reqData.getWssConfig());
		return wsSign;
	}

}