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

package org.pathirage.play.samlsso.session;

import org.pathirage.play.samlsso.Constants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import play.mvc.Http.Session;

import java.util.UUID;

/**
 * Manages SAML SSO session using Play session object and Play Cache. This is
 * based on https://github.com/leleuj/play-pac4j/blob/master/play-pac4j_java/src/main/java/org/pac4j/play/StorageHelper.java
 */
public class SSOSessionStorageHelper {
    private static final Logger log = LoggerFactory.getLogger(SSOSessionStorageHelper.class);

    /**
     * Check for existing session.
     * @param session Play session object.
     * @return true if SSO session exists or false otherwise.
     */
    public static boolean isSSOSessionExists(final Session session){
        return session.containsKey(Constants.SSO_SESSION_ID) && session.get(Constants.SSO_SESSION_ID) != null;
    }

    /**
     * Get the current session id.
     * @param session Play session object.
     * @return ID of the current SSO session.
     */
    public static String getSessionId(final Session session){
        return session.get(Constants.SSO_SESSION_ID);
    }

    /**
     * Create a new SSO session.
     * @param session Play session object.
     * @return new SSO sessions's id.
     */
    public static String createSession(final Session session){
        String sessionId = session.get(Constants.SSO_SESSION_ID);

        if(sessionId == null){
            sessionId = UUID.randomUUID().toString();
            session.put(Constants.SSO_SESSION_ID, sessionId);

            if(log.isDebugEnabled()){
                log.debug(String.format("No session was found. Created new session with ID %s ", sessionId));
            }
        } else {
            if(log.isDebugEnabled()){
                log.debug(String.format("Session with ID %s found", sessionId));
            }
        }

        return sessionId;
    }
}
