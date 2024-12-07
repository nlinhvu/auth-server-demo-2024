package vn.cloud.auth_server_demo;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationContext;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.util.StringUtils;

import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;

public class RealmValidator implements Consumer<OAuth2AuthorizationCodeRequestAuthenticationContext> {

    private Map<String, Set<String>> allowedRealmsForClient = Map.of(
            "pkce-client", Set.of("invoice-realm", "order-realm", "product-realm"));

    @Override
    public void accept(OAuth2AuthorizationCodeRequestAuthenticationContext authenticationContext) {
        OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication =
                authenticationContext.getAuthentication();
        RegisteredClient registeredClient = authenticationContext.getRegisteredClient();
        String requestedRealm = (String) authorizationCodeRequestAuthentication
                .getAdditionalParameters()
                .getOrDefault("realm", null);

        if (requestedRealm == null || !allowedRealmsForClient.get(registeredClient.getClientId()).contains(requestedRealm)) {

            OAuth2Error error = new OAuth2Error("invalid_realm", "OAuth 2.0 My Company Parameter: realm", "https://my-company.com/how-to-use-realm");

            String redirectUri = StringUtils.hasText(authorizationCodeRequestAuthentication.getRedirectUri())
                    ? authorizationCodeRequestAuthentication.getRedirectUri()
                    : registeredClient.getRedirectUris().iterator().next();

            OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthenticationResult = new OAuth2AuthorizationCodeRequestAuthenticationToken(
                    authorizationCodeRequestAuthentication.getAuthorizationUri(),
                    authorizationCodeRequestAuthentication.getClientId(),
                    (Authentication) authorizationCodeRequestAuthentication.getPrincipal(), redirectUri,
                    authorizationCodeRequestAuthentication.getState(), authorizationCodeRequestAuthentication.getScopes(),
                    authorizationCodeRequestAuthentication.getAdditionalParameters());
            authorizationCodeRequestAuthenticationResult.setAuthenticated(true);

            throw new OAuth2AuthorizationCodeRequestAuthenticationException(error, authorizationCodeRequestAuthenticationResult);
        }
    }
}
