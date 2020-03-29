package oauth2.config;

import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;

import java.util.HashMap;
import java.util.Map;

public class CustomTokenEnhancer implements TokenEnhancer {
    @Override
    public OAuth2AccessToken enhance(
            OAuth2AccessToken accessToken,
            OAuth2Authentication authentication) {
        Map<String, Object> additionalInfo = new HashMap<>();
        //additionalInfo.put("organization", authentication.getName() + randomAlphabetic(4));
        DefaultOAuth2AccessToken defaultOAuth2AccessToken=(DefaultOAuth2AccessToken) accessToken;
        defaultOAuth2AccessToken.setAdditionalInformation(additionalInfo);
        return accessToken;
    }
}