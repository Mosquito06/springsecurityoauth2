package io.security.oauth2.springsecurityoauth2;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.ClientRegistrations;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;

import java.util.Map;

@Configuration
public class OAuth2ClientConfig
{
    @Bean
    public ClientRegistrationRepository clientRegistrationRepository()
    {
        return new InMemoryClientRegistrationRepository( keyCloakClientRegistration() );
    }

    private ClientRegistration keyCloakClientRegistration()
    {
        return ClientRegistrations.fromIssuerLocation("http://localhost:8080/realms/oauth2")
                            .registrationId("keycloak")
                            .clientId("oauth2-client-app")
                            .clientSecret("eZTvMeU5w0WnFIP4h1pZHcE8po0Gr46Z")
                            .redirectUri("http://localhost:8081/login/oauth2/code/keycloak")
                            .build();
    }
}
