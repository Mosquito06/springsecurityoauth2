package io.security.oauth2.springsecurityoauth2;


import io.security.oauth2.springsecurityoauth2.service.CustomOAuth2UserService;
import io.security.oauth2.springsecurityoauth2.service.CustomOidcUserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
public class OAuth2ClientConfig
{
    @Autowired
    private CustomOAuth2UserService customoAuth2UserService;

    @Autowired
    private CustomOidcUserService customOidcUserService;



    @Bean
    public WebSecurityCustomizer webSecurityCustomizer()
    {
        return web ->
        {
            web.ignoring().antMatchers("/static/js/**", "/static/images/**", "/static/css/**", "/static/scss/**");
        };
    }

    @Bean
    SecurityFilterChain oauth2SecurityFilterChain(HttpSecurity http) throws Exception
    {
        http.authorizeRequests( authRequest -> authRequest
                .antMatchers("/api/user").access("hasAnyRole('SCOPE_prifile', 'SCOPE_emil')")
                .antMatchers("/api/oidc").access("hasAnyRole('SCOPE_openid')")
                .antMatchers("/").permitAll()
                .anyRequest().authenticated() );
        http.oauth2Login(
                oauth2 ->
                        oauth2.userInfoEndpoint(
                                userInfoEndpointConfig ->
                                    userInfoEndpointConfig.userService( customoAuth2UserService )
                                                          .oidcUserService( customOidcUserService )
                                               )
                        );
        http.logout().logoutSuccessUrl("/");

        return http.build();
    }

    @Bean
    public GrantedAuthoritiesMapper customAuthorityMapper()
    {
        return new CustomAuthorityMapper();
    }

}
