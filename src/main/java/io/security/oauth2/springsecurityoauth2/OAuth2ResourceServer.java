package io.security.oauth2.springsecurityoauth2;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;

import javax.servlet.Filter;

@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class OAuth2ResourceServer
{
    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception
    {
        http.authorizeRequests(
                requests -> requests.antMatchers(HttpMethod.GET,"/photos/1").hasAuthority("ROLE_photo")
                                    .antMatchers(HttpMethod.GET,"/photos/3").hasAuthority("ROLE_default-roles-oauth2")
                                    .anyRequest().authenticated());

        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter( new CustomRoleConvert() );

        http.oauth2ResourceServer().jwt().jwtAuthenticationConverter(jwtAuthenticationConverter);

        return http.build();
    }

    @Bean
    SecurityFilterChain securityFilterChain2(HttpSecurity http) throws Exception
    {
        http.antMatcher("/photos/2").authorizeRequests( requests -> requests.antMatchers(HttpMethod.GET,"/photos/2").permitAll().anyRequest().authenticated());
        http.oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);

        return http.build();
    }
}