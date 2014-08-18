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

import play.api.http.ContentTypes;
import play.libs.F;
import play.mvc.Result;
import static play.mvc.Results.*;

public class SAMLSSOHelper {

    public F.Promise<Result> buildAuthenticationRequest(){
        F.Promise<Result> promise = F.Promise.promise(new F.Function0<Result>() {
            @Override
            public Result apply() throws Throwable {
                return ok().as(Constants.TEXT_HTML_CONTENT_TYPE);
            }
        });

        return promise;
    }
}
