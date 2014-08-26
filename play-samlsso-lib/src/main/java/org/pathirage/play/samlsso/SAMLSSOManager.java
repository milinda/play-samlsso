/**
 * Copyright 2014 Milinda Pathirage
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.pathirage.play.samlsso;

import com.google.common.base.Preconditions;
import org.joda.time.DateTime;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.*;
import org.opensaml.saml2.core.impl.AuthnRequestBuilder;
import org.opensaml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml2.core.impl.NameIDPolicyBuilder;
import org.opensaml.saml2.metadata.*;
import org.opensaml.saml2.metadata.impl.*;
import org.opensaml.saml2.metadata.provider.FilesystemMetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.parse.StaticBasicParserPool;
import org.opensaml.xml.parse.XMLParserException;
import org.opensaml.xml.security.*;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.credential.CredentialResolver;
import org.opensaml.xml.security.credential.KeyStoreCredentialResolver;
import org.opensaml.xml.security.credential.UsageType;
import org.opensaml.xml.security.criteria.EntityIDCriteria;
import org.opensaml.xml.signature.KeyInfo;
import play.libs.F;
import play.mvc.Http;
import play.mvc.SimpleResult;

import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.util.*;

import static play.mvc.Results.forbidden;
import static play.mvc.Results.ok;

public enum SAMLSSOManager {

    INSTANCE;

    private String privateKeyAlias;

    private CredentialResolver credentialResolver;

    private String identityProviderEntityId;

    private String spEntityId;

    private String callbackUrl;

    private String keyStorePath;

    private String keyStorePassword;

    private String privateKeyPassword;

    private String idpMetadataXMLPath;

    private IDPSSODescriptor idpSSODescriptor;

    private SPSSODescriptor spSSODescriptor;

    public void setSpEntityId(String spEntityId) {
        this.spEntityId = spEntityId;
    }

    public void setCallbackUrl(String callbackUrl) {
        this.callbackUrl = callbackUrl;
    }

    public void setKeyStorePath(String keyStorePath) {
        this.keyStorePath = keyStorePath;
    }

    public void setKeyStorePassword(String keyStorePassword) {
        this.keyStorePassword = keyStorePassword;
    }

    public void setPrivateKeyPassword(String privateKeyPassword) {
        this.privateKeyPassword = privateKeyPassword;
    }

    public void setIdpMetadataXMLPath(String idpMetadataXMLPath) {
        this.idpMetadataXMLPath = idpMetadataXMLPath;
    }

    /**
     * Initialize SAML SSO Manager. Make sure the key store contains proper keys and idp metadata
     * file contains correct details about your identity provider.
     */
    public void initSAMLSSOManager() {
        /**
         * Read IDP metadata and key stores and initialize object required for
         * building authentication, logout requests and processing authentication
         * responses from IDP.
         */
        Preconditions.checkNotNull(spEntityId);
        Preconditions.checkNotNull(keyStorePath);
        Preconditions.checkNotNull(idpMetadataXMLPath);
        Preconditions.checkNotNull(callbackUrl);

        initCredentialResolver(keyStorePath, keyStorePassword, privateKeyPassword);

        StaticBasicParserPool parserPool = new StaticBasicParserPool();

        try{
            parserPool.initialize();
        } catch (XMLParserException e) {
            throw new RuntimeException("Unable to initialize parser pool.", e);
        }

        FilesystemMetadataProvider idpMetadataProvider;

        try{
            idpMetadataProvider = new FilesystemMetadataProvider(new Timer(true), new File(idpMetadataXMLPath));
            idpMetadataProvider.setParserPool(parserPool);
            idpMetadataProvider.initialize();
        } catch (MetadataProviderException e) {
            throw new RuntimeException("Unable to read identity provider meta data.", e);
        }

        try {
            XMLObject idpMetadata = idpMetadataProvider.getMetadata();
            if(idpMetadata instanceof EntitiesDescriptor){
                for(EntityDescriptor entityDescriptor : ((EntitiesDescriptor)idpMetadata).getEntityDescriptors()){
                    // Select the first entity descriptor
                    this.identityProviderEntityId = entityDescriptor.getEntityID();
                    break;
                }
            } else if(idpMetadata instanceof EntitiesDescriptor){
                this.identityProviderEntityId = ((EntityDescriptor)idpMetadata).getEntityID();
            }

            this.idpSSODescriptor = (IDPSSODescriptor)idpMetadataProvider.getRole(this.identityProviderEntityId, IDPSSODescriptor.DEFAULT_ELEMENT_NAME, SAMLConstants.SAML20P_NS);
        } catch (MetadataProviderException e) {
            throw new RuntimeException("Couldn't get metadata from identity provider metadata provider.", e);
        }

        buildSPSSODescriptor();
    }

    private void buildSPSSODescriptor(){
        SPSSODescriptorBuilder builder = new SPSSODescriptorBuilder();
        SPSSODescriptor spSSODescriptor = builder.buildObject();

        spSSODescriptor.setAuthnRequestsSigned(true);
        spSSODescriptor.setWantAssertionsSigned(true);
        spSSODescriptor.addSupportedProtocol(SAMLConstants.SAML20P_NS);
        spSSODescriptor.getNameIDFormats().addAll(buildNameIDFormats());

        AssertionConsumerServiceBuilder assertionConsumerServiceBuilder = new AssertionConsumerServiceBuilder();
        AssertionConsumerService assertionConsumerService = assertionConsumerServiceBuilder.buildObject();

        assertionConsumerService.setLocation(this.callbackUrl);
        assertionConsumerService.setBinding(SAMLConstants.SAML2_POST_BINDING_URI);
        assertionConsumerService.setIsDefault(true);
        assertionConsumerService.setIndex(0);

        spSSODescriptor.getAssertionConsumerServices().add(assertionConsumerService);

        spSSODescriptor.getSingleLogoutServices().add(genSingleLogoutService());

        spSSODescriptor.getKeyDescriptors().add(genKeyDescriptor(UsageType.SIGNING, credentialToKeyInfo(getSPCredential())));
        spSSODescriptor.getKeyDescriptors().add(genKeyDescriptor(UsageType.ENCRYPTION, credentialToKeyInfo(getSPCredential())));

        this.spSSODescriptor = spSSODescriptor;

    }

    private SingleLogoutService genSingleLogoutService(){
        SingleLogoutServiceBuilder singleLogoutServiceBuilder = new SingleLogoutServiceBuilder();
        SingleLogoutService singleLogoutService = singleLogoutServiceBuilder.buildObject();

        singleLogoutService.setBinding(SAMLConstants.SAML2_POST_BINDING_URI);
        singleLogoutService.setLocation(this.callbackUrl);

        return singleLogoutService;
    }

    private Credential getSPCredential(){
        try{
            CriteriaSet criteriaSet = new CriteriaSet();
            EntityIDCriteria entityIDCriteria = new EntityIDCriteria(this.privateKeyAlias);

            criteriaSet.add(entityIDCriteria);

            return credentialResolver.resolveSingle(criteriaSet);
        } catch (org.opensaml.xml.security.SecurityException e) {
            throw new RuntimeException("Cannot resolve credential for the service provider.", e);
        }
    }

    private KeyInfo credentialToKeyInfo(Credential credential){
        try{
            return SecurityHelper.getKeyInfoGenerator(credential, null, "SPMetadataKeyInfoGenerator").generate(credential);
        } catch (SecurityException e) {
            throw new RuntimeException("Cannot generate key info from credential.", e);
        }
    }

    private KeyDescriptor genKeyDescriptor(UsageType usageType, KeyInfo keyInfo){
        KeyDescriptorBuilder keyDescriptorBuilder = new KeyDescriptorBuilder();
        KeyDescriptor keyDescriptor = keyDescriptorBuilder.buildObject();
        keyDescriptor.setUse(usageType);
        keyDescriptor.setKeyInfo(keyInfo);

        return  keyDescriptor;
    }

    private Collection<NameIDFormat> buildNameIDFormats(){
        Collection<NameIDFormat> nameIDFormats = new ArrayList<NameIDFormat>();

        NameIDFormatBuilder builder = new NameIDFormatBuilder();

        NameIDFormat transientNameID = builder.buildObject();
        transientNameID.setFormat(NameIDType.TRANSIENT);
        nameIDFormats.add(transientNameID);

        NameIDFormat persistentNameID = builder.buildObject();
        persistentNameID.setFormat(NameIDType.PERSISTENT);
        nameIDFormats.add(persistentNameID);

        NameIDFormat emailNameID = builder.buildObject();
        emailNameID.setFormat(NameIDType.EMAIL);

        return nameIDFormats;
    }


    private void initCredentialResolver(String keyStorePath, String keyStorePassword, String privateKeyPassword) {
        File keyStoreFile = new File(keyStorePath);
        try {
            FileInputStream keyStoreInputStream = new FileInputStream(keyStoreFile);
            KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(keyStoreInputStream, keyStorePassword == null ? null : keyStorePassword.toCharArray());

            Enumeration<String> aliaes = keyStore.aliases();
            if(aliaes.hasMoreElements()){
                this.privateKeyAlias = aliaes.nextElement();
            } else {
                throw new RuntimeException("No private keys found in key store.");
            }

            Map<String, String> passwords = new HashMap<String, String>();
            passwords.put(this.privateKeyAlias, privateKeyPassword);

            this.credentialResolver = new KeyStoreCredentialResolver(keyStore, passwords);
        } catch (Exception e) {
            throw new RuntimeException("Cannot initialize credential resolver.", e);
        }

    }

    private String getPrivateKeyAlias(final KeyStore keyStore) {
        try {
            Enumeration<String> aliases = keyStore.aliases();
            if (aliases.hasMoreElements()) {
                return aliases.nextElement();
            } else {
                throw new RuntimeException("Keystore has no private keys");
            }
        } catch (KeyStoreException e) {
            throw new RuntimeException("Unable to get aliases from keyStore", e);
        }
    }

    /**
     * Build authentication request to be sent to SAML identity provider.
     *
     * @return authentication request as a play redirect.
     */
    public F.Promise<SimpleResult> buildAuthenticationRequest(Http.Request request) {
        IssuerBuilder issuerBuilder = new IssuerBuilder();
        Issuer issuer = issuerBuilder.buildObject("urn:oasis:names:tc:SAML:2.0:assertion",
                "Issuer", "samla");

        // Identifies the service provider.
        issuer.setValue(spEntityId);

        NameIDPolicyBuilder nameIDPolicyBuilder = new NameIDPolicyBuilder();
        NameIDPolicy nameIDPolicy = nameIDPolicyBuilder.buildObject();
        nameIDPolicy.setFormat("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent");
        nameIDPolicy.setSPNameQualifier("Issuer");
        nameIDPolicy.setAllowCreate(true);

        AuthnRequestBuilder authnRequestBuilder = new AuthnRequestBuilder();
        AuthnRequest authnRequest = authnRequestBuilder.buildObject("urn:oasis:names:tc:SAML:2.0:protocol",
                "AuthnRequest", "samlp");

        authnRequest.setVersion(SAMLVersion.VERSION_20);
        authnRequest.setIsPassive(false);
        authnRequest.setForceAuthn(false);
        authnRequest.setIssueInstant(new DateTime());
        authnRequest.setDestination(getSSOServiceForPostBinding(idpSSODescriptor).getLocation());

        AssertionConsumerService assertionConsumerService = getAssertionConsumerServiceForSP(spSSODescriptor);
        authnRequest.setAssertionConsumerServiceURL(assertionConsumerService.getLocation());
        authnRequest.setProtocolBinding(assertionConsumerService.getBinding());


        F.Promise<SimpleResult> promise = F.Promise.promise(new F.Function0<SimpleResult>() {
            @Override
            public SimpleResult apply() throws Throwable {
                return ok().as(Constants.TEXT_HTML_CONTENT_TYPE);
            }
        });

        return promise;
    }

    private SingleSignOnService getSSOServiceForPostBinding(IDPSSODescriptor idpssoDescriptor){
        for(SingleSignOnService singleSignOnService : idpssoDescriptor.getSingleSignOnServices()){
            if(singleSignOnService.getBinding().equals(SAMLConstants.SAML2_POST_BINDING_URI)){
                return singleSignOnService;
            }
        }

        throw new RuntimeException("IDP doesn't have single sign on service available for post binding.");
    }

    private AssertionConsumerService getAssertionConsumerServiceForSP(SPSSODescriptor spssoDescriptor){
        if(spssoDescriptor.getDefaultAssertionConsumerService() != null){
            return spssoDescriptor.getDefaultAssertionConsumerService();
        }

        if(spssoDescriptor.getAssertionConsumerServices().size() > 0){
            return spssoDescriptor.getAssertionConsumerServices().get(0);
        }

        throw new RuntimeException("SP doesn't have assertion consumer service defined.");
    }
}
