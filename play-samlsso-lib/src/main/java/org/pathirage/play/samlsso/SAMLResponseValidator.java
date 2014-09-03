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

import org.joda.time.DateTime;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.binding.SAMLMessageContext;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.*;
import org.opensaml.saml2.encryption.Decrypter;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.security.MetadataCriteria;
import org.opensaml.security.SAMLSignatureProfileValidator;
import org.opensaml.xml.encryption.DecryptionException;
import org.opensaml.xml.security.*;
import org.opensaml.xml.security.credential.UsageType;
import org.opensaml.xml.security.criteria.EntityIDCriteria;
import org.opensaml.xml.security.criteria.UsageCriteria;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureTrustEngine;
import org.opensaml.xml.validation.ValidationException;
import org.opensaml.xml.validation.ValidatorSuite;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

/**
 * Based on pac4j org.pac4j.saml.sso.Saml2ResponseValidator and CXF SAMLProtocolResponseValidator
 */
public class SAMLResponseValidator {
    private static final Logger log = LoggerFactory.getLogger(SAMLResponseValidator.class);

    public static final String SAML2_STATUSCODE_SUCCESS =
            "urn:oasis:names:tc:SAML:2.0:status:Success";

    /* maximum skew in seconds between SP and IDP clocks */
    private int acceptedSkew = 120;

    /* maximum lifetime after a successfull authentication on an IDP */
    private int maximumAuthenticationLifetime = 3600;

    private SignatureTrustEngine trustEngine;

    private Decrypter decrypter;

    private String callbackUrl;

    public SAMLResponseValidator(SignatureTrustEngine trustEngine, Decrypter decrypter, String callbackUrl) {
        this.trustEngine = trustEngine;
        this.decrypter = decrypter;
        this.callbackUrl = callbackUrl;
    }

    public void isValidResponse(SAMLMessageContext messageContext) throws Exception {
        SAMLObject responseObject = messageContext.getInboundSAMLMessage();

        if (!(responseObject instanceof Response)) {
            throw new Exception("Unknown SAML2 response type.");
        }

        Response response = (Response) responseObject;

        if (response.getStatus() == null ||
                response.getStatus().getStatusCode() == null) {
            log.error("Either SAML response status or status code is null.");
            throw new Exception("Invalid SAML response.");
        }

        if (!SAML2_STATUSCODE_SUCCESS.equals(response.getStatus().getStatusCode().getValue())) {
            log.error("SAML response status code " + response.getStatus().getStatusCode().getValue() + " doesn't" +
                    "equal to expected status code " + SAML2_STATUSCODE_SUCCESS);
            throw new Exception("Invalid SAML response.");
        }

        validateResponseAgainstSchema(response);
        validateResponseSignature(response, messageContext);

        for (EncryptedAssertion encryptedAssertion : response.getEncryptedAssertions()) {
            try {
                response.getAssertions().add(decrypter.decrypt(encryptedAssertion));
            } catch (Exception e) {
                log.error("Decryption failed for a assertion.", e);
            }
        }

        Assertion subjectAssertion = validateSAMLSSOResponse(response, messageContext);

        if(subjectAssertion == null){
            throw new Exception("No valid subject assestion found in response.");
        }
    }

    private Assertion validateSAMLSSOResponse(Response samlResponse, SAMLMessageContext messageContext) throws Exception {
        for(Assertion assertion : samlResponse.getAssertions()){
            if(assertion.getAuthnStatements().size() > 0){
                try{
                    validateAssertion(assertion, messageContext);
                } catch (Exception e){
                    log.error("Current assertion validation failed, continue with the next one", e);
                    continue;
                }

                return assertion;
            }
        }

        return null;
    }

    /**
     * 09-03-2014(Milinda) - Copied from pac4j and modify to make it work in this code.
     * Validate the given assertion:
     *  - issueInstant
     *  - issuer
     *  - subject
     *  - conditions
     *  - authnStatements
     *  - signature
     *
     * @param assertion
     * @param messageContext
     */
    protected void validateAssertion(final Assertion assertion, final SAMLMessageContext messageContext) {

        if (!isIssueInstantValid(assertion.getIssueInstant())) {
            throw new RuntimeException("Assertion issue instant is too old or in the future");
        }

        validateIssuer(assertion.getIssuer(), messageContext);

        if (assertion.getSubject() != null) {
            validateSubject(assertion.getSubject(), messageContext, decrypter);
        } else {
            throw new RuntimeException("Assertion subject cannot be null");
        }

        validateAssertionConditions(assertion.getConditions(), messageContext);

        validateAuthenticationStatements(assertion.getAuthnStatements(), messageContext);

        validateAssertionSignature(assertion.getSignature(), messageContext);

    }


    /**
     * 09-03-2014(Milinda) - Copied from pac4j and modify to make it work in this code.
     * Validate assertionConditions
     *  - notBefore
     *  - notOnOrAfter
     *
     * @param conditions
     * @param context
     */
    protected void validateAssertionConditions(final Conditions conditions, final SAMLMessageContext context) {

        if (conditions == null) {
            throw new RuntimeException("Assertion conditions cannot be null");
        }

        if (conditions.getNotBefore() != null) {
            if (conditions.getNotBefore().minusSeconds(acceptedSkew).isAfterNow()) {
                throw new RuntimeException("Assertion condition notBefore is not valid");
            }
        }

        if (conditions.getNotOnOrAfter() != null) {
            if (conditions.getNotOnOrAfter().plusSeconds(acceptedSkew).isBeforeNow()) {
                throw new RuntimeException("Assertion condition notOnOrAfter is not valid");
            }
        }

        validateAudienceRestrictions(conditions.getAudienceRestrictions(), context.getLocalEntityId());

    }

    /**
     * 09-03-2014(Milinda) - Copied from pac4j and modify to make it work in this code.
     * Validate audience by matching the SP entityId.
     *
     * @param audienceRestrictions
     * @param spEntityId
     */
    protected void validateAudienceRestrictions(final List<AudienceRestriction> audienceRestrictions,
                                                final String spEntityId) {

        if (audienceRestrictions == null || audienceRestrictions.size() == 0) {
            throw new RuntimeException("Audience restrictions cannot be null or empty");
        }
        if (!matchAudienceRestriction(audienceRestrictions, spEntityId)) {
            throw new RuntimeException("Assertion audience does not match SP configuration");
        }

    }

    private boolean matchAudienceRestriction(final List<AudienceRestriction> audienceRestrictions,
                                             final String spEntityId) {
        for (AudienceRestriction audienceRestriction : audienceRestrictions) {
            if (audienceRestriction.getAudiences() != null) {
                for (Audience audience : audienceRestriction.getAudiences()) {
                    if (spEntityId.equals(audience.getAudienceURI())) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    /**
     * 09-03-2014(Milinda) - Copied from pac4j and modify to make it work in this code.
     * Validate assertion signature. If none is found and the SAML response did not have one and the SP requires
     * the assertions to be signed, the validation fails.
     *
     * @param signature
     * @param context
     */
    protected void validateAssertionSignature(final Signature signature, final SAMLMessageContext context) {
        if (signature != null) {
            validateSignature(signature, context.getPeerEntityMetadata().getEntityID());
        } else if (((SPSSODescriptor) context.getLocalEntityRoleMetadata()).getWantAssertionsSigned()
                && !context.isInboundSAMLMessageAuthenticated()) {
            throw new RuntimeException("Assertion or response must be signed");
        }
    }

    /**
     * 09-03-2014(Milinda) - Copied from pac4j and modify to make it work in this code.
     * Validate the given digital signature by checking its profile and value.
     *
     * @param signature
     * @param idpEntityId
     */
    protected void validateSignature(final Signature signature, final String idpEntityId) {

        SAMLSignatureProfileValidator validator = new SAMLSignatureProfileValidator();
        try {
            validator.validate(signature);
        } catch (ValidationException e) {
            throw new RuntimeException("SAMLSignatureProfileValidator failed to validate signature", e);
        }

        CriteriaSet criteriaSet = new CriteriaSet();
        criteriaSet.add(new UsageCriteria(UsageType.SIGNING));
        criteriaSet.add(new MetadataCriteria(IDPSSODescriptor.DEFAULT_ELEMENT_NAME, SAMLConstants.SAML20P_NS));
        criteriaSet.add(new EntityIDCriteria(idpEntityId));

        boolean valid;
        try {
            valid = trustEngine.validate(signature, criteriaSet);
        } catch (org.opensaml.xml.security.SecurityException e) {
            throw new RuntimeException("An error occured during signature validation", e);
        }
        if (!valid) {
            throw new RuntimeException("Signature is not trusted");
        }
    }



    /**
     * 09-03-2014(Milinda) - Copied from pac4j and modify to make it work in this code.
     * Validate the given authnStatements:
     *  - authnInstant
     *  - sessionNotOnOrAfter
     *
     * @param authnStatements
     * @param messageContext
     */
    protected void validateAuthenticationStatements(final List<AuthnStatement> authnStatements,
                                                    final SAMLMessageContext messageContext) {

        for (AuthnStatement statement : authnStatements) {
            if (!isAuthnInstantValid(statement.getAuthnInstant())) {
                throw new RuntimeException("Authentication issue instant is too old or in the future");
            }
            if (statement.getSessionNotOnOrAfter() != null && statement.getSessionNotOnOrAfter().isBeforeNow()) {
                throw new RuntimeException("Authentication session between IDP and subject has ended");
            }
            // TODO implement authnContext validation
        }
    }

    private boolean isAuthnInstantValid(DateTime authnInstant) {
        return isDateValid(authnInstant, maximumAuthenticationLifetime);
    }


    /**
     * 09-03-2014(Milinda) - Copied from pac4j and modify to make it work in this code.
     * Validate issuer format and value.
     *
     * @param issuer
     * @param messageContext
     */
    protected void validateIssuer(final Issuer issuer, final SAMLMessageContext messageContext) {
        if (issuer.getFormat() != null && !issuer.getFormat().equals(NameIDType.ENTITY)) {
            throw new RuntimeException("Issuer type is not entity but " + issuer.getFormat());
        }
        if (!messageContext.getPeerEntityMetadata().getEntityID().equals(issuer.getValue())) {
            throw new RuntimeException("Issuer " + issuer.getValue() + " does not match idp entityId "
                    + messageContext.getPeerEntityMetadata().getEntityID());
        }
    }

    /**
     * 09-03-2014(Milinda) - Copied from pac4j and modify to make it work in this code.
     * Validate the given subject by finding a valid Bearer confirmation. If the subject is valid,
     * put its nameID in the context.
     *
     * @param subject
     * @param messageContext
     * @param decrypter
     */
    @SuppressWarnings("unchecked")
    protected void validateSubject(final Subject subject, final SAMLMessageContext messageContext,
                                   final Decrypter decrypter) {

        for (SubjectConfirmation confirmation : subject.getSubjectConfirmations()) {
            if (SubjectConfirmation.METHOD_BEARER.equals(confirmation.getMethod())) {
                if (isValidBearerSubjectConfirmationData(confirmation.getSubjectConfirmationData(), messageContext)) {
                    NameID nameID = null;
                    if (subject.getEncryptedID() != null) {
                        try {
                            nameID = (NameID) decrypter.decrypt(subject.getEncryptedID());
                        } catch (DecryptionException e) {
                            throw new RuntimeException("Decryption of nameID's subject failed", e);
                        }
                    } else {
                        nameID = subject.getNameID();
                    }
                    messageContext.setSubjectNameIdentifier(nameID);
                    return;
                }
            }
        }

        throw new RuntimeException("Subject confirmation validation failed");
    }

    /**
     * 09-03-2014(Milinda) - Copied from pac4j and modify to make it work in this code.
     * Validate Bearer subject confirmation data
     *  - notBefore
     *  - NotOnOrAfter
     *  - recipient
     *
     * @param data
     * @param context
     * @return true if all Bearer subject checks are passing
     */
    protected boolean isValidBearerSubjectConfirmationData(final SubjectConfirmationData data,
                                                           final SAMLMessageContext context) {
        if (data == null) {
            log.debug("SubjectConfirmationData cannot be null for Bearer confirmation");
            return false;
        }

        // TODO Validate inResponseTo

        if (data.getNotBefore() != null) {
            log.debug("SubjectConfirmationData notBefore must be null for Bearer confirmation");
            return false;
        }

        if (data.getNotOnOrAfter() == null) {
            log.debug("SubjectConfirmationData notOnOrAfter cannot be null for Bearer confirmation");
            return false;
        }

        if (data.getNotOnOrAfter().plusSeconds(acceptedSkew).isBeforeNow()) {
            log.debug("SubjectConfirmationData notOnOrAfter is too old");
            return false;
        }

        if (data.getRecipient() == null) {
            log.debug("SubjectConfirmationData recipient cannot be null for Bearer confirmation");
            return false;
        } else {
            if (!data.getRecipient().equals(callbackUrl)) {
                log.debug("SubjectConfirmationData recipient {} does not match SP assertion consumer URL, found",
                        data.getRecipient());
                return false;
            }
        }
        return true;
    }

    /**
     * 09-03-2014(Milinda) - Copied from pac4j and modify to make it work in this code.
     * @param issueInstant
     * @param interval
     * @return
     */
    private boolean isDateValid(final DateTime issueInstant, int interval) {
        long now = System.currentTimeMillis();
        return issueInstant.isBefore(now + acceptedSkew * 1000)
                && issueInstant.isAfter(now - (acceptedSkew + interval) * 1000);
    }

    /**
     * 09-03-2014(Milinda) - Copied from pac4j and modify to make it work in this code.
     * @param issueInstant
     * @return
     */
    private boolean isIssueInstantValid(final DateTime issueInstant) {
        return isDateValid(issueInstant, 0);
    }

    /**
     * 09-03-2014(Milinda) - Copied from pac4j and modify to make it work in this code.
     * @param samlResponse
     * @throws Exception
     */
    private void validateResponseAgainstSchema(Response samlResponse) throws Exception {
        ValidatorSuite schemaValidators =
                org.opensaml.Configuration.getValidatorSuite("saml2-core-schema-validator");
        try {
            schemaValidators.validate(samlResponse);
        } catch (ValidationException e) {
            log.error("SAML response schema validation error.", e);
            throw new Exception("Invalid SAML response.", e);
        }
    }

    /**
     * 09-03-2014(Milinda) - Copied from pac4j and modify to make it work in this code.
     * @param samlResponse
     * @param messageContext
     * @throws Exception
     */
    private void validateResponseSignature(Response samlResponse, SAMLMessageContext messageContext) throws Exception {
        if (!samlResponse.isSigned()) {
            return;
        }

        SAMLSignatureProfileValidator signatureProfileValidator = new SAMLSignatureProfileValidator();

        try {
            signatureProfileValidator.validate(samlResponse.getSignature());
        } catch (ValidationException ve) {
            log.error("SAML response contains invalid signature profile.");
            throw new Exception("Invalid SAML response.", ve);
        }

        CriteriaSet criteriaSet = new CriteriaSet();
        criteriaSet.add(new UsageCriteria(UsageType.SIGNING));
        criteriaSet.add(new MetadataCriteria(IDPSSODescriptor.DEFAULT_ELEMENT_NAME, SAMLConstants.SAML20P_NS));
        criteriaSet.add(new EntityIDCriteria(messageContext.getPeerEntityId()));

        boolean valid;

        try {
            valid = trustEngine.validate(samlResponse.getSignature(), criteriaSet);
        } catch (Exception e) {
            throw new Exception("SAML response signature validation failed.", e);
        }

        if (!valid) {
            log.error("Invalid signature in SAML response.");
            throw new Exception("Invalid SAML response.");
        }

        messageContext.setInboundSAMLMessageAuthenticated(true);
    }
}
