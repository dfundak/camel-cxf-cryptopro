package com.xyz.ws.security;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.apache.ws.security.WSPasswordCallback;

public class KeystorePasswordCallback implements CallbackHandler {
	private Map<String, String> passwords = new HashMap<String, String>();

	public KeystorePasswordCallback() {
		passwords.put("Alice", "ecilA");
		passwords.put("abcd", "dcba");
		passwords.put("clientx509v1", "storepassword");
		passwords.put("serverx509v1", "storepassword");
		passwords.put("myKey", "11111111");
	}

	/**
	 * Here, we attempt to get the password from the private alias/passwords
	 * map.
	 */
	public void handle(Callback[] callbacks) throws IOException,
			UnsupportedCallbackException {
		for (int i = 0; i < callbacks.length; i++) {
			WSPasswordCallback pc = (WSPasswordCallback) callbacks[i];
			String pass = passwords.get(pc.getIdentifier());
			if (pass != null) {
				pc.setPassword(pass);
				return;
			}
		}
	}

	/**
	 * Add an alias/password pair to the callback mechanism.
	 */
	public void setAliasPassword(String alias, String password) {
		passwords.put(alias, password);
	}
}
