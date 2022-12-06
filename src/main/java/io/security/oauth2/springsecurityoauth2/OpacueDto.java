package io.security.oauth2.springsecurityoauth2;

import lombok.Data;
import org.springframework.security.core.Authentication;

@Data
public class OpacueDto
{
    private boolean active;
    private Authentication authentication;
    private Object principal;
}
