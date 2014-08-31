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
import org.apache.velocity.app.VelocityEngine;
import org.apache.velocity.runtime.RuntimeConstants;
import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.common.binding.SAMLMessageContext;
import org.opensaml.common.binding.security.SAMLProtocolMessageXMLSignatureSecurityPolicyRule;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.binding.decoding.HTTPPostDecoder;
import org.opensaml.saml2.binding.encoding.HTTPPostEncoder;
import org.opensaml.saml2.binding.security.SAML2HTTPPostSimpleSignRule;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameIDPolicy;
import org.opensaml.saml2.core.NameIDType;
import org.opensaml.saml2.core.impl.AuthnRequestBuilder;
import org.opensaml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml2.core.impl.NameIDPolicyBuilder;
import org.opensaml.saml2.metadata.*;
import org.opensaml.saml2.metadata.impl.*;
import org.opensaml.saml2.metadata.provider.*;
import org.opensaml.security.MetadataCredentialResolver;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.ws.security.SecurityPolicy;
import org.opensaml.ws.security.provider.BasicSecurityPolicy;
import org.opensaml.ws.security.provider.StaticSecurityPolicyResolver;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.parse.ParserPool;
import org.opensaml.xml.parse.StaticBasicParserPool;
import org.opensaml.xml.parse.XMLParserException;
import org.opensaml.xml.security.CriteriaSet;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.credential.CredentialResolver;
import org.opensaml.xml.security.credential.KeyStoreCredentialResolver;
import org.opensaml.xml.security.credential.UsageType;
import org.opensaml.xml.security.criteria.EntityIDCriteria;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.signature.impl.ExplicitKeySignatureTrustEngine;
import org.pathirage.play.samlsso.utils.InMemoryOutTransport;
import org.pathirage.play.samlsso.utils.PlayInTransport;
import play.libs.F;
import play.mvc.Http;
import play.mvc.SimpleResult;

import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.util.*;

import static play.mvc.Results.ok;

public enum SAMLSSOManager {

    INSTANCE;

    public static final String SAML2_WEBSSO_PROFILE_URI = "urn:oasis:names:tc:SAML:2.0:profiles:SSO:browser";

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

    private EntityDescriptor spMetadata;

    private ChainingMetadataProvider globalMetadataProvider;

    private VelocityEngine velocityEngine;

    private HTTPPostEncoder samlEncoder;

    private HTTPPostDecoder samlDecoder;

    private ParserPool parserPool;

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

        try {
            parserPool.initialize();
        } catch (XMLParserException e) {
            throw new RuntimeException("Unable to initialize parser pool.", e);
        }

        this.parserPool = parserPool;

        FilesystemMetadataProvider idpMetadataProvider;

        try {
            idpMetadataProvider = new FilesystemMetadataProvider(new Timer(true), new File(idpMetadataXMLPath));
            idpMetadataProvider.setParserPool(parserPool);
            idpMetadataProvider.initialize();
        } catch (MetadataProviderException e) {
            throw new RuntimeException("Unable to read identity provider meta data.", e);
        }

        try {
            XMLObject idpMetadata = idpMetadataProvider.getMetadata();
            if (idpMetadata instanceof EntitiesDescriptor) {
                for (EntityDescriptor entityDescriptor : ((EntitiesDescriptor) idpMetadata).getEntityDescriptors()) {
                    // Select the first entity descriptor
                    this.identityProviderEntityId = entityDescriptor.getEntityID();
                    break;
                }
            } else if (idpMetadata instanceof EntitiesDescriptor) {
                this.identityProviderEntityId = ((EntityDescriptor) idpMetadata).getEntityID();
            }

            this.idpSSODescriptor = (IDPSSODescriptor) idpMetadataProvider.getRole(this.identityProviderEntityId, IDPSSODescriptor.DEFAULT_ELEMENT_NAME, SAMLConstants.SAML20P_NS);
        } catch (MetadataProviderException e) {
            throw new RuntimeException("Couldn't get metadata from identity provider metadata provider.", e);
        }

        buildSPSSODescriptor();

        this.globalMetadataProvider = new ChainingMetadataProvider();

        try {
            this.globalMetadataProvider.addMetadataProvider(idpMetadataProvider);
            this.globalMetadataProvider.addMetadataProvider(getSPMetadataProvider());
        } catch (MetadataProviderException e) {
            throw new RuntimeException("Cannot add sp or idp metadata providers.", e);
        }

        try {
            velocityEngine = getClassPathVelocityEngine();
            samlEncoder = new HTTPPostEncoder(velocityEngine, "/templates/saml2-post-binding.vm");

            // TODO: Validate the use of this.
            samlDecoder = new HTTPPostDecoder(parserPool);
        } catch (Exception e) {
            throw new RuntimeException("Cannot initiate classpath velocity engine.");
        }


    }

    private MetadataProvider getSPMetadataProvider(){
        EntityDescriptorBuilder entityDescriptorBuilder = new EntityDescriptorBuilder();
        EntityDescriptor entityDescriptor = entityDescriptorBuilder.buildObject();
        entityDescriptor.setEntityID(this.spEntityId);
        entityDescriptor.getRoleDescriptors().add(this.spSSODescriptor);

        this.spMetadata = entityDescriptor;

        return new AbstractMetadataProvider() {
            @Override
            protected XMLObject doGetMetadata() throws MetadataProviderException {
                return spMetadata;
            }
        };
    }

    private void buildSPSSODescriptor() {
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

    private SingleLogoutService genSingleLogoutService() {
        SingleLogoutServiceBuilder singleLogoutServiceBuilder = new SingleLogoutServiceBuilder();
        SingleLogoutService singleLogoutService = singleLogoutServiceBuilder.buildObject();

        singleLogoutService.setBinding(SAMLConstants.SAML2_POST_BINDING_URI);
        singleLogoutService.setLocation(this.callbackUrl);

        return singleLogoutService;
    }

    private Credential getSPCredential() {
        try {
            CriteriaSet criteriaSet = new CriteriaSet();
            EntityIDCriteria entityIDCriteria = new EntityIDCriteria(this.privateKeyAlias);

            criteriaSet.add(entityIDCriteria);

            return credentialResolver.resolveSingle(criteriaSet);
        } catch (org.opensaml.xml.security.SecurityException e) {
            throw new RuntimeException("Cannot resolve credential for the service provider.", e);
        }
    }

    private KeyInfo credentialToKeyInfo(Credential credential) {
        try {
            return SecurityHelper.getKeyInfoGenerator(credential, null, "SPMetadataKeyInfoGenerator").generate(credential);
        } catch (SecurityException e) {
            throw new RuntimeException("Cannot generate key info from credential.", e);
        }
    }

    private KeyDescriptor genKeyDescriptor(UsageType usageType, KeyInfo keyInfo) {
        KeyDescriptorBuilder keyDescriptorBuilder = new KeyDescriptorBuilder();
        KeyDescriptor keyDescriptor = keyDescriptorBuilder.buildObject();
        keyDescriptor.setUse(usageType);
        keyDescriptor.setKeyInfo(keyInfo);

        return keyDescriptor;
    }

    private Collection<NameIDFormat> buildNameIDFormats() {
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
            if (aliaes.hasMoreElements()) {
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
    public F.Promise<SimpleResult> buildAuthenticationRequest(Http.Context context, final String currentTargetUrl) {
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
        final AuthnRequest authnRequest = authnRequestBuilder.buildObject("urn:oasis:names:tc:SAML:2.0:protocol",
                "AuthnRequest", "samlp");

        Random random = new Random();
        authnRequest.setID(Long.toHexString(random.nextLong()) + '_' + Long.toHexString(random.nextLong()));
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
                SingleSignOnService ssoService = getSSOServiceForPostBinding(idpSSODescriptor);

                SAMLMessageContext messageContext = new BasicSAMLMessageContext();
                messageContext.setCommunicationProfileId(SAML2_WEBSSO_PROFILE_URI);
                messageContext.setOutboundMessage(authnRequest);
                messageContext.setOutboundSAMLMessage(authnRequest);
                messageContext.setPeerEntityEndpoint(ssoService);

                // Setting url of the current request as relay state. So callback can redirect to correct resource.
                messageContext.setRelayState(currentTargetUrl);

                messageContext.setOutboundSAMLMessageSigningCredential(getSPCredential());

                // Prevent OpenSAML from sending post message and record message in byte array output stream.
                // Based on pac4j.
                messageContext.setOutboundMessageTransport(new InMemoryOutTransport());

                // TODO: How to handle exception thrown here.
                samlEncoder.encode(messageContext);

                // We can do this safely because we are using our own outbound transport.
                // This generate a html form with idp saml sso url set as forms action.
                String content = messageContext.getOutboundMessageTransport().getOutgoingStream().toString();

                return ok(content).as(Constants.TEXT_HTML_CONTENT_TYPE);
            }
        });

        return promise;
    }

    public F.Promise<SimpleResult> processAuthenticationResponse(Http.Request request, Http.Response response, Http.Session session){
        BasicSAMLMessageContext samlMessageContext = new BasicSAMLMessageContext();

        samlMessageContext.setInboundMessageTransport(new PlayInTransport(request, response, session));
        samlMessageContext.setLocalEntityId(spEntityId);
        samlMessageContext.setLocalEntityRole(SSODescriptor.DEFAULT_ELEMENT_NAME);
        // TODO: Looks like full entity descriptor is also required. Test and add it if role metadata is not enough.
        samlMessageContext.setLocalEntityRoleMetadata(spSSODescriptor);
        // TODO: May be peer entity descriptor is also required.
        samlMessageContext.setPeerEntityRoleMetadata(idpSSODescriptor);
        samlMessageContext.setInboundSAMLProtocol(SAMLConstants.SAML20P_NS);

        ExplicitKeySignatureTrustEngine signatureTrustEngine = new ExplicitKeySignatureTrustEngine(new MetadataCredentialResolver(globalMetadataProvider), Configuration.getGlobalSecurityConfiguration().getDefaultKeyInfoCredentialResolver());


        SecurityPolicy securityPolicy = new BasicSecurityPolicy();
        securityPolicy.getPolicyRules().add(new SAML2HTTPPostSimpleSignRule(signatureTrustEngine, parserPool, signatureTrustEngine.getKeyInfoResolver()));
        securityPolicy.getPolicyRules().add(new SAMLProtocolMessageXMLSignatureSecurityPolicyRule(signatureTrustEngine));

        StaticSecurityPolicyResolver securityPolicyResolver = new StaticSecurityPolicyResolver(securityPolicy);

        samlMessageContext.setSecurityPolicyResolver(securityPolicyResolver);

        try {
            this.samlDecoder.decode(samlMessageContext);
        } catch (Exception e) {
            throw new RuntimeException("Unable to decode authentication response.", e);
        }

        if(samlMessageContext.getPeerEntityMetadata() == null){
            throw new RuntimeException("Cannot find IDP metadata");
        }

        samlMessageContext.setPeerEntityId(samlMessageContext.getPeerEntityMetadata().getEntityID());
        samlMessageContext.setCommunicationProfileId(SAML2_WEBSSO_PROFILE_URI);


        return F.Promise.promise(new F.Function0<SimpleResult>() {
            @Override
            public SimpleResult apply() throws Throwable {
                // TODO: Fill rest.
                return null;
            }
        });
    }

    private SingleSignOnService getSSOServiceForPostBinding(IDPSSODescriptor idpssoDescriptor) {
        for (SingleSignOnService singleSignOnService : idpssoDescriptor.getSingleSignOnServices()) {
            if (singleSignOnService.getBinding().equals(SAMLConstants.SAML2_POST_BINDING_URI)) {
                return singleSignOnService;
            }
        }

        throw new RuntimeException("IDP doesn't have single sign on service available for post binding.");
    }

    private AssertionConsumerService getAssertionConsumerServiceForSP(SPSSODescriptor spssoDescriptor) {
        if (spssoDescriptor.getDefaultAssertionConsumerService() != null) {
            return spssoDescriptor.getDefaultAssertionConsumerService();
        }

        if (spssoDescriptor.getAssertionConsumerServices().size() > 0) {
            return spssoDescriptor.getAssertionConsumerServices().get(0);
        }

        throw new RuntimeException("SP doesn't have assertion consumer service defined.");
    }

    /**
     * Based on https://joinup.ec.europa.eu/svn/moa-idspss/branches/1.5.2-stork-integration/id/server/idserverlib/src/main/java/at/gv/egovernment/moa/id/auth/stork/VelocityProvider.java
     *
     * @return classpath velocity engine.
     * @throws Exception
     */
    private VelocityEngine getClassPathVelocityEngine() throws Exception {
        VelocityEngine velocityEngine = new VelocityEngine();
        velocityEngine.setProperty(RuntimeConstants.ENCODING_DEFAULT, "UTF-8");
        velocityEngine.setProperty(RuntimeConstants.OUTPUT_ENCODING, "UTF-8");
        velocityEngine.setProperty(RuntimeConstants.RESOURCE_LOADER, "classpath");
        velocityEngine.setProperty("classpath.resource.loader.class",
                "org.apache.velocity.runtime.resource.loader.ClasspathResourceLoader");

        velocityEngine.init();

        return velocityEngine;
    }
}
