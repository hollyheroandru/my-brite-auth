package com.hollyheroandu.authservice.services.oauth2.user;

import com.hollyheroandu.authservice.exceptions.OAuth2AuthenticationProcessingException;
import com.hollyheroandu.authservice.models.AuthProvider;

import java.util.Map;

public class OAuth2UserInfoFactory {

    public static OAuth2UserInfo getOAuthUserInfo(String registrationId, Map<String, Object> attributes) {
        if(registrationId.equalsIgnoreCase(AuthProvider.google.toString())) {
            return new GoogleOAuth2UserInfo(attributes);
        } else {
            throw new OAuth2AuthenticationProcessingException("Login with " + registrationId + " is not supported yet.");
        }
    }
}
