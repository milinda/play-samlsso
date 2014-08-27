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

package org.pathirage.play.samlsso.utils;

import org.opensaml.ws.transport.http.HTTPOutTransport;
import org.opensaml.ws.transport.http.HTTPTransport;
import org.opensaml.xml.security.credential.Credential;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.util.List;

/**
 * Default transport used in Open SAML uses servlet transport and do the post to IDP it self. In our
 * case we need to let Play authentication action handle this. So we capture all the
 */
public class InMemoryOutTransport implements HTTPOutTransport {

    private final OutputStream outputStream = new ByteArrayOutputStream();


    @Override
    public void setVersion(HTTP_VERSION version) {
        throw new UnsupportedOperationException("Not implemented.");
    }

    @Override
    public void setHeader(String name, String value) {
        // Do Nothing. Open SAML HTTPPostEncoder calls this method.
    }

    @Override
    public void addParameter(String name, String value) {
        throw new UnsupportedOperationException("Not implemented.");
    }

    @Override
    public void setStatusCode(int code) {
        throw new UnsupportedOperationException("Not implemented.");
    }

    @Override
    public void sendRedirect(String location) {
        throw new UnsupportedOperationException("Not implemented.");
    }

    @Override
    public String getHeaderValue(String name) {
        throw new UnsupportedOperationException("Not implemented.");
    }

    @Override
    public String getHTTPMethod() {
        throw new UnsupportedOperationException("Not implemented.");
    }

    @Override
    public int getStatusCode() {
        throw new UnsupportedOperationException("Not implemented.");
    }

    @Override
    public String getParameterValue(String name) {
        throw new UnsupportedOperationException("Not implemented.");
    }

    @Override
    public List<String> getParameterValues(String name) {
        throw new UnsupportedOperationException("Not implemented.");
    }

    @Override
    public HTTP_VERSION getVersion() {
        throw new UnsupportedOperationException("Not implemented.");
    }

    @Override
    public void setAttribute(String name, Object value) {
        throw new UnsupportedOperationException("Not implemented.");
    }

    @Override
    public void setCharacterEncoding(String encoding) {
        // Do nothing. Open SAML HTTPPostEncoder calls this method.
    }

    @Override
    public OutputStream getOutgoingStream() {
        return outputStream;
    }

    @Override
    public Object getAttribute(String name) {
        throw new UnsupportedOperationException("Not implemented.");
    }

    @Override
    public String getCharacterEncoding() {
        throw new UnsupportedOperationException("Not implemented.");
    }

    @Override
    public Credential getLocalCredential() {
        throw new UnsupportedOperationException("Not implemented.");
    }

    @Override
    public Credential getPeerCredential() {
        throw new UnsupportedOperationException("Not implemented.");
    }

    @Override
    public boolean isAuthenticated() {
        throw new UnsupportedOperationException("Not implemented.");
    }

    @Override
    public void setAuthenticated(boolean isAuthenticated) {
        throw new UnsupportedOperationException("Not implemented.");
    }

    @Override
    public boolean isConfidential() {
        throw new UnsupportedOperationException("Not implemented.");
    }

    @Override
    public void setConfidential(boolean isConfidential) {
        throw new UnsupportedOperationException("Not implemented.");
    }

    @Override
    public boolean isIntegrityProtected() {
        throw new UnsupportedOperationException("Not implemented.");
    }

    @Override
    public void setIntegrityProtected(boolean isIntegrityProtected) {
        throw new UnsupportedOperationException("Not implemented.");
    }
}
