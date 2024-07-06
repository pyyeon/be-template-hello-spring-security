package com.springboot.config;

import com.springboot.auth.HelloAuthorityUtils;
import com.springboot.member.DBMemberService;
import com.springboot.member.InMemoryMemberService;
import com.springboot.member.MemberRepository;
import com.springboot.member.MemberService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.UserDetailsManager;

@Configuration
public class JavaConfiguration {
    @Bean
    public MemberService inMemoryMemberService(MemberRepository memberRepository,
                                               PasswordEncoder passwordEncoder,
                                               HelloAuthorityUtils helloAuthorityUtils) {
        return new DBMemberService(memberRepository, passwordEncoder, helloAuthorityUtils);
    }
}