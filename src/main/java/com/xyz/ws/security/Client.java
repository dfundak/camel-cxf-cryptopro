package com.xyz.ws.security;

import java.io.Closeable;
import java.lang.reflect.UndeclaredThrowableException;
import java.security.KeyStore;
import java.util.HashMap;
import java.util.Map;

import org.apache.camel.example.reportincident.InputReportIncident;
import org.apache.camel.example.reportincident.OutputReportIncident;
import org.apache.camel.example.reportincident.ReportIncidentEndpoint;
import org.apache.camel.example.reportincident.ReportIncidentEndpointService;
import org.apache.cxf.binding.soap.interceptor.SoapInterceptor;
import org.apache.cxf.frontend.ClientProxy;
import org.apache.cxf.interceptor.LoggingOutInterceptor;
import org.apache.cxf.ws.security.wss4j.WSS4JOutInterceptor;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.handler.WSHandlerConstants;

import ru.CryptoPro.JCP.JCP;
import ru.CryptoPro.JCPxml.xmldsig.JCPXMLDSigInit;

public class Client {

	private static final String WSSE_NS = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
	private static final String WSU_NS = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";

	private Client() {
	}

	public static void main(String args[]) throws Exception {
		try {
	    	
	    	// Инициализация сервис-провайдера.
	    	if(!JCPXMLDSigInit.isInitialized()) {
	    	    JCPXMLDSigInit.init();
	    	}
	    	
	    	// Инициализация ключевого контейнера и получение сертификата и закрытого ключа.
	        KeyStore keyStore = KeyStore.getInstance(JCP.HD_STORE_NAME);
	        keyStore.load(null, "".toCharArray());
	        
			ReportIncidentEndpointService service = new ReportIncidentEndpointService();
			ReportIncidentEndpoint port = service.getReportIncidentService();

			org.apache.cxf.endpoint.Client client = ClientProxy.getClient(port);
			client.getOutInterceptors().add(createSignatureOutInterceptor());
			client.getOutInterceptors().add(new LoggingOutInterceptor());
			System.out.println("Invoking greetMe...");
			InputReportIncident in = new InputReportIncident();
			in.setEmail("dfundak@gmail.com");
			in.setDetails("Details");
			in.setFamilyName("Fundak");
			in.setGivenName("Dmitry");
			in.setPhone("89166870829");
			OutputReportIncident response = port.reportIncident(in);
			System.out.println("response: " + response.getCode() + "\n");

			if (port instanceof Closeable) {
				((Closeable) port).close();
			}
		} catch (UndeclaredThrowableException ex) {
			ex.getUndeclaredThrowable().printStackTrace();
		} catch (Exception ex) {
			ex.printStackTrace();
		} finally {
			System.exit(0);
		}
	}
	
	 private static SoapInterceptor createSignatureOutInterceptor() {
		  // определяем собственный класс системы подписывания
		  Map<Integer, Class<?>> wssConnfigMap = new HashMap<Integer, Class<?>>();
		  wssConnfigMap.put(Integer.valueOf(WSConstants.SIGN), LocalSignatureAction.class);
//		 
		  Map<String, Object> outProps = new HashMap<String, Object>();
		  outProps.put("wss4j.action.map", wssConnfigMap);
			outProps.put(WSHandlerConstants.ACTION, "Signature");
			outProps.put(WSHandlerConstants.USER, "myKey");
			outProps.put(WSHandlerConstants.SIGNATURE_USER, "myKey");
			outProps.put("passwordCallbackClass", "com.xyz.ws.security.KeystorePasswordCallback");
			outProps.put(WSHandlerConstants.SIG_PROP_FILE, "etc/Client_Sign.properties");
			outProps.put("signatureKeyIdentifier", "DirectReference");
			outProps.put("signatureParts","{}{http://schemas.xmlsoap.org/soap/envelope/}Body;");
			outProps.put("signatureAlgorithm", "http://www.w3.org/2001/04/xmldsig-more#gostr34102001-gostr3411");
			outProps.put("signatureDigestAlgorithm", "http://www.w3.org/2001/04/xmldsig-more#gostr3411");
		   
		    //параметры для SMEV
			outProps.put("actor", "http://smev.gosuslugi.ru/actors/smev");
			outProps.put("mustUnderstand", "false");
		   
		  WSS4JOutInterceptor interceptor = new WSS4JOutInterceptor(outProps);
		  return interceptor;
	}
}
