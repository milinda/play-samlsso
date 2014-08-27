# play-samlsso

SAML 2.0 SSO for Play Framework with OAuth2 grant support. Only supports Play Java and tested with WSO2 Identity Server.

This project was inspired by [play-pac4j](https://github.com/leleuj/play-pac4j) library. I wanted to create a framework 
which supports SAML 2.0 SSO with OAuth2 grant. 

## Design and Usage

### Authentication Flow

1. User tries to access specific URL of Play App.
2. If the above URL is secured using @RequiresAuthentication annotation, RequiresAuthenticationAction will get invoked.
3. This action will check for whether there is a existing session and whether required user profile information is there
 in the session.
 
 3.1 If there is a valida session, action will hand over the request to actual web action.
 
 3.2 If no valid session is found, action will start the SSO process from step 4.
 
4. 

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
