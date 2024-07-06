package com.springboot.auth;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.Optional;

@Component
public class HelloUserAuthenticationProvider implements AuthenticationProvider {   // (1)
    private final HelloUserDetailsServiceV3 userDetailsService;
    private final PasswordEncoder passwordEncoder;

    public HelloUserAuthenticationProvider(HelloUserDetailsServiceV3 userDetailsService,
                                           PasswordEncoder passwordEncoder) {
        this.userDetailsService = userDetailsService;
        this.passwordEncoder = passwordEncoder;
    }


    // (3)
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        UsernamePasswordAuthenticationToken authToken = (UsernamePasswordAuthenticationToken) authentication;  // (3-1)

        // (3-2)
        String username = authToken.getName();
        Optional.ofNullable(username).orElseThrow(() -> new UsernameNotFoundException("Invalid User name or User Password"));
        try {
            // (3-3) 인가정보 userdetails에 있음
            UserDetails userDetails = userDetailsService.loadUserByUsername(username);

            String password = userDetails.getPassword();
            verifyCredentials(authToken.getCredentials(), password);    // (3-4)

            Collection<? extends GrantedAuthority> authorities = userDetails.getAuthorities();  // (3-5)

            // (3-6)
            return UsernamePasswordAuthenticationToken.authenticated(username, password, authorities);
        } catch (Exception e){
            throw new UsernameNotFoundException(e.getMessage());
        }
    }
    // (2) HelloUserAuthenticationProvider가 Username/Password 방식의 인증을 지원한다는 것을 Spring Security에 알려준다.
    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.equals(authentication);
    }

    private void verifyCredentials(Object credentials, String password) {
        if (!passwordEncoder.matches((String) credentials, password)) {
            throw new BadCredentialsException("Invalid User name or User Password");
        }
    }
}
