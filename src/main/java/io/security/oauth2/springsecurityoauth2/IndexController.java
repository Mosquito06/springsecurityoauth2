package io.security.oauth2.springsecurityoauth2;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class IndexController
{
    @GetMapping("/")
    public Authentication index(Authentication authentication, @AuthenticationPrincipal OAuth2AuthenticatedPrincipal principal)
    {
        BearerTokenAuthentication authenticationToken = (BearerTokenAuthentication) authentication;
        Map<String, Object> tokenAttributes = authenticationToken.getTokenAttributes();

        boolean active = (boolean) tokenAttributes.get("active");

        OpacueDto opacueDto = new OpacueDto();
        opacueDto.setActive(active);
        opacueDto.setAuthentication(authentication);
        opacueDto.setPrincipal(principal);

        return authentication;
    }
}
