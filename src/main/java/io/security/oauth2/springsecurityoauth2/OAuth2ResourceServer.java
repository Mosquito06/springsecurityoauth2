package io.security.oauth2.springsecurityoauth2;

import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.introspection.NimbusOpaqueTokenIntrospector;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.security.web.SecurityFilterChain;

import javax.servlet.Filter;

@Configuration
public class OAuth2ResourceServer
{
    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception
    {
        http.authorizeRequests(
                requests -> requests.anyRequest().authenticated());

        http.oauth2ResourceServer(OAuth2ResourceServerConfigurer::opaqueToken);

        return http.build();
    }

//    @Bean
//    public OpaqueTokenIntrospector opaqueTokenIntrospector(OAuth2ResourceServerProperties properties)
//    {
//        OAuth2ResourceServerProperties.Opaquetoken opaquetoken = properties.getOpaquetoken();
//
//        return new NimbusOpaqueTokenIntrospector( opaquetoken.getIntrospectionUri(), opaquetoken.getClientId(), opaquetoken.getClientSecret());
//    }

        @Bean
        public OpaqueTokenIntrospector opaqueTokenIntrospector(OAuth2ResourceServerProperties properties)
        {
            return new CustomOpaqueTokenIntrospector(properties);
        }
        }