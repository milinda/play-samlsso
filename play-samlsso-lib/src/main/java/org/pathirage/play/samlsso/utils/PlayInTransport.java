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

import org.opensaml.ws.transport.http.HTTPInTransport;
import org.opensaml.xml.security.credential.Credential;
import play.mvc.Http;

import java.io.InputStream;
import java.util.*;

public class PlayInTransport implements HTTPInTransport {

    private Http.Request request;

    private Http.Response response;

    private Http.Session session;

    public PlayInTransport(Http.Request request, Http.Response response, Http.Session session) {
        this.request = request;
        this.response = response;
        this.session = session;
    }

    @Override
    public String getPeerAddress() {
        throw new UnsupportedOperationException("not implemented.");
    }

    @Override
    public String getPeerDomainName() {
        throw new UnsupportedOperationException("not implemented.");
    }

    @Override
    public String getHeaderValue(String name) {
        throw new UnsupportedOperationException("not implemented.");
    }

    @Override
    public String getHTTPMethod() {
        return request.method();
    }

    @Override
    public int getStatusCode() {
        throw new UnsupportedOperationException("not implemented.");
    }

    @Override
    public String getParameterValue(String name) {
        Map<String, String[]> parameters = requestParameters();

        if(parameters.containsKey(name)){
            String[] paramValues =  parameters.get(name);
            if(paramValues.length > 0){
                return paramValues[0];
            }
        }

        return null;
    }

    private Map<String, String[]> requestParameters(){
        HashMap<String, String[]> parameters = new HashMap<String, String[]>();
        Map<String, String[]> formParams = request.body().asFormUrlEncoded();
        Map<String, String[]> queryParams = request.queryString();

        if (formParams != null) {
            parameters.putAll(formParams);
        }

        if (queryParams != null) {
            parameters.putAll(queryParams);
        }

        return parameters;
    }

    @Override
    public List<String> getParameterValues(String name) {
        Map<String, String[]> requestParameters = requestParameters();

        if(requestParameters.containsKey(name)){
            String[] paramValues = requestParameters.get(name);
            if(paramValues.length > 0){
                return Arrays.asList(paramValues);
            }
        }
        return Collections.emptyList();
    }

    @Override
    public HTTP_VERSION getVersion() {
        throw new UnsupportedOperationException("not implemented.");
    }

    @Override
    public InputStream getIncomingStream() {
        throw new UnsupportedOperationException("not implemented.");
    }

    @Override
    public Object getAttribute(String name) {
        throw new UnsupportedOperationException("not implemented.");
    }

    @Override
    public String getCharacterEncoding() {
        throw new UnsupportedOperationException("not implemented.");
    }

    @Override
    public Credential getLocalCredential() {
        throw new UnsupportedOperationException("not implemented.");
    }

    @Override
    public Credential getPeerCredential() {
        throw new UnsupportedOperationException("not implemented.");
    }

    @Override
    public boolean isAuthenticated() {
        throw new UnsupportedOperationException("not implemented.");
    }

    @Override
    public void setAuthenticated(boolean isAuthenticated) {
        throw new UnsupportedOperationException("not implemented.");
    }

    @Override
    public boolean isConfidential() {
        throw new UnsupportedOperationException("not implemented.");
    }

    @Override
    public void setConfidential(boolean isConfidential) {
        throw new UnsupportedOperationException("not implemented.");
    }

    @Override
    public boolean isIntegrityProtected() {
        throw new UnsupportedOperationException("not implemented.");
    }

    @Override
    public void setIntegrityProtected(boolean isIntegrityProtected) {
        throw new UnsupportedOperationException("not implemented.");
    }
}
