play-samlsso
============

SAML 2.0 SSO for Play Framework. Only supports Play Java and tested with WSO2 Identity Server.

## Design and Usage

Your Play controllers must extend ```SAMLSSOJavaController``` class for Play Java application.

```
public class MyApplication extends SAMLSSOJavaController {
    ...
}
```

Specific actions of your Play Java application can be protected by using ```RequiresAuthentication``` annotation.

```
@RequiresAuthentication
public static Result protectedResource(){
    // User profile is avaibale only if this session is authenticated with Identity Provider
    UserProfile userProfile = getUserProfile()
}
```

```SAMLSSOJavaController``` defines methods needed to handle SAML SSO related callbacks.
 
 * ```authenticatedCB``` - Identity provider should redirect back to this action after the authentication is done as a request from service provider. 
 * ```singleLogoutCB``` - Identity provider will send a request to this URL to complete single logout request from a other service provider.
 * ```singleLogout``` - If you need single logout support in your application, you can call this action.


Copyright © 2014 Milinda Pathirage

Distributed under the Apache License Version 2.0.
