package com.springboot.member;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.UserDetailsManager;

public interface MemberService  {


    public Member createMember(Member member);
}
