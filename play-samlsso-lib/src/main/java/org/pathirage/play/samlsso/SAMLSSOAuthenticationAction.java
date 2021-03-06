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

import org.pathirage.play.samlsso.session.SSOSessionStorageHelper;
import play.mvc.Http.Session;
import play.libs.F.Promise;
import play.mvc.Action;
import play.mvc.Http;
import play.mvc.Result;
import play.mvc.SimpleResult;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;

public class SAMLSSOAuthenticationAction extends Action<Result> {
    private static final Logger log = LoggerFactory.getLogger(SAMLSSOAuthenticationAction.class);

    @Override
    @SuppressWarnings("unchecked")
    public Promise<SimpleResult> call(Http.Context ctx) throws Throwable {
        Session session = ctx.session();
        String sessionId = null;
        String tagrgetUrl = ctx.request().uri();
        String absoluteTargetUrl = getAbsoluteUrl(tagrgetUrl, ctx);

        if(!SSOSessionStorageHelper.isSSOSessionExists(session)){
            sessionId = SSOSessionStorageHelper.createSession(session);
        } else {
            sessionId = SSOSessionStorageHelper.getSessionId(session);
        }

        // Check whether user profile information there and initiate SSO process
        UserProfile userProfile = SSOSessionStorageHelper.getUserProfile(sessionId);

        if(userProfile == null){
            return SAMLSSOManager.INSTANCE.buildAuthenticationRequest(ctx, absoluteTargetUrl);
        }

        return delegate.call(ctx);
    }

    private String getAbsoluteUrl(String url, Http.Context ctx){
        if(url != null && !url.startsWith("http://") && !url.startsWith("https://")){
            StringBuilder stringBuilder = new StringBuilder();
            // TODO: Add support for https and proxying.
            String[] parts = ctx.request().host().split(":");
            String serverName = parts[0];
            String port = parts.length > 1 ? parts[1] : "80";


            stringBuilder.append("http://").append(serverName).append(port);

            if(url.startsWith("/")){
                stringBuilder.append(url);
            } else {
                stringBuilder.append("/").append(url);
            }

            return stringBuilder.toString();
        }

        return url;
    }
}
