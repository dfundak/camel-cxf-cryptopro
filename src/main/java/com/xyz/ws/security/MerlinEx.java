package com.xyz.ws.security;

import java.io.IOException;
import java.security.PrivateKey;
import java.util.Properties;

import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.CredentialException;
import org.apache.ws.security.components.crypto.Merlin;

public class MerlinEx extends Merlin {

    private PrivateKey cachedPrivateKey = null;
    private String cachedAlias = null;

        public MerlinEx(Properties properties) throws CredentialException,
                        IOException {
                super(properties);
        }

        public MerlinEx(Properties properties, ClassLoader loader) throws CredentialException,
                        IOException {
                super(properties, loader);
        }

    public PrivateKey getPrivateKey(String alias, String password) {

        if (cachedPrivateKey == null ||
                        (cachedAlias != null && !cachedAlias.equalsIgnoreCase(alias))) {
                cachedAlias = alias;
                try {
                                cachedPrivateKey = super.getPrivateKey(alias, password);
                        } catch (WSSecurityException e) {
                                // TODO Auto-generated catch block
                                e.printStackTrace();
                        }
        }

        return cachedPrivateKey;
    }
}
