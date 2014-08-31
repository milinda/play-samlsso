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

import org.opensaml.common.SAMLObject;
import org.opensaml.common.binding.SAMLMessageContext;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.EncryptedAssertion;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.encryption.Decrypter;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.security.MetadataCriteria;
import org.opensaml.security.SAMLSignatureProfileValidator;
import org.opensaml.xml.security.CriteriaSet;
import org.opensaml.xml.security.credential.UsageType;
import org.opensaml.xml.security.criteria.EntityIDCriteria;
import org.opensaml.xml.security.criteria.UsageCriteria;
import org.opensaml.xml.signature.SignatureTrustEngine;
import org.opensaml.xml.validation.ValidationException;
import org.opensaml.xml.validation.ValidatorSuite;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Based on pac4j org.pac4j.saml.sso.Saml2ResponseValidator and CXF SAMLProtocolResponseValidator
 */
public class SAMLResponseValidator {
    private static final Logger log = LoggerFactory.getLogger(SAMLResponseValidator.class);

    public static final String SAML2_STATUSCODE_SUCCESS =
            "urn:oasis:names:tc:SAML:2.0:status:Success";

    private SignatureTrustEngine trustEngine;

    private Decrypter decrypter;

    public SAMLResponseValidator(SignatureTrustEngine trustEngine, Decrypter decrypter) {
        this.trustEngine = trustEngine;
        this.decrypter = decrypter;
    }

    public void isValidResponse(SAMLMessageContext messageContext) throws Exception {
        SAMLObject responseObject = messageContext.getInboundSAMLMessage();

        if (!(responseObject instanceof Response)) {
            throw new RuntimeException("Unknown SAML2 response type.");
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

        validateSAMLSSOResponse(response);
    }

    private void validateSAMLSSOResponse(Response samlResponse) throws Exception {
        // TODO: Add assertion validation.
    }

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
