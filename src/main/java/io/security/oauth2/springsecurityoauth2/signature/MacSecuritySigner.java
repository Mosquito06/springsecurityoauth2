package io.security.oauth2.springsecurityoauth2.signature;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.KeyLengthException;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import org.springframework.security.core.userdetails.UserDetails;

public class MacSecuritySigner extends SecuritySigner
{
    @Override
    public String getJwtToken(UserDetails user, JWK jwk) throws JOSEException
    {
        MACSigner jwsSinger = new MACSigner( ((OctetSequenceKey) jwk).toSecretKey() );

        return super.getJwtTokenInternal(jwsSinger, user,jwk);
    }
}
