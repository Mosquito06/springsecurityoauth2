package io.security.oauth2.springsecurityoauth2.config;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.RSAKey;
import io.security.oauth2.springsecurityoauth2.filter.authentication.JwtAuthenticationFilter;
import io.security.oauth2.springsecurityoauth2.filter.authorization.JwtAuthorizationFilter;
import io.security.oauth2.springsecurityoauth2.filter.authorization.JwtAuthorizationMacFilter;
import io.security.oauth2.springsecurityoauth2.filter.authorization.JwtAuthorizationRsaFilter;
import io.security.oauth2.springsecurityoauth2.signature.MacSecuritySigner;
import io.security.oauth2.springsecurityoauth2.signature.RsaSecuritySigner;
import io.security.oauth2.springsecurityoauth2.signature.SecuritySigner;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.WebSecurityConfigurer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.Filter;

@Configuration
public class OAuth2ResourceServer
{
    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception
    {
        http.csrf().disable();
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        http.authorizeRequests((requests) -> requests.antMatchers("/").permitAll().anyRequest().authenticated());
        http.userDetailsService(userDetailsService());
        //http.addFilterBefore(jwtAuthenticationFilter(macSecuritySigner, octetSequenceKey), UsernamePasswordAuthenticationFilter.class);
        // http.addFilterBefore(new JwtAuthorizationMacFilter(octetSequenceKey), UsernamePasswordAuthenticationFilter.class);
        http.addFilterBefore(jwtAuthenticationFilter(null, null), UsernamePasswordAuthenticationFilter.class);
        //http.addFilterBefore(jwtAuthorizationRsaFilter(null), UsernamePasswordAuthenticationFilter.class);
        http.oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);
        return http.build();
    }

    @Bean
    public JwtAuthorizationRsaFilter jwtAuthorizationRsaFilter(RSAKey rsaKey) throws JOSEException
    {
        return new JwtAuthorizationRsaFilter(new RSASSAVerifier( rsaKey.toRSAPublicKey() ));
    }

//    @Bean
//    public JwtAuthorizationMacFilter jwtAuthorizationMacFilter(OctetSequenceKey octetSequenceKey) throws JOSEException
//    {
//        return new JwtAuthorizationMacFilter( new MACVerifier( octetSequenceKey.toSecretKey()) );
//    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception
    {
        return authenticationConfiguration.getAuthenticationManager();
    }

//    @Bean
//    public JwtAuthenticationFilter jwtAuthenticationFilter(MacSecuritySigner macSecuritySigner, OctetSequenceKey octetSequenceKey) throws Exception
//    {
//        JwtAuthenticationFilter jwtAuthenticationFilter = new JwtAuthenticationFilter(macSecuritySigner, octetSequenceKey);
//        jwtAuthenticationFilter.setAuthenticationManager(authenticationManager(null));
//        return jwtAuthenticationFilter;
//    }

    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter(RsaSecuritySigner rsaSecuritySigner, RSAKey rsaKey) throws Exception
    {
        JwtAuthenticationFilter jwtAuthenticationFilter = new JwtAuthenticationFilter(rsaSecuritySigner, rsaKey);
        jwtAuthenticationFilter.setAuthenticationManager(authenticationManager(null));
        return jwtAuthenticationFilter;
    }

    @Bean
    public UserDetailsService userDetailsService()
    {
        UserDetails user = User.withUsername("user").password("1234").authorities("ROLE_USER").build();
        return new InMemoryUserDetailsManager(user);
    }

    @Bean
    public PasswordEncoder passwordEncoder()
    {
        return NoOpPasswordEncoder.getInstance();
    }
}