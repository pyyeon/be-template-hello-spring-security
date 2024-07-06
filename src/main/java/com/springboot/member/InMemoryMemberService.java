package com.springboot.member;

//import com.springboot.auth.utils.AuthorityUtils;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.UserDetailsManager;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public class InMemoryMemberService implements MemberService {  // (1)
    private final UserDetailsManager userDetailsManager;
    private final PasswordEncoder passwordEncoder;

    // (2)
    public InMemoryMemberService(UserDetailsManager userDetailsManager, PasswordEncoder passwordEncoder) {
        this.userDetailsManager = userDetailsManager;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public Member createMember(Member member) {
        // (3)
        List<GrantedAuthority> authorities = createAuthorities(Member.MemberRole.ROLE_USER.name());

        // (4)
        String encryptedPassword = passwordEncoder.encode(member.getPassword());

        // (5)
        UserDetails userDetails = new User(member.getEmail(), encryptedPassword, authorities);

        // (6)
        userDetailsManager.createUser(userDetails);

        return member;
    }

    private List<GrantedAuthority> createAuthorities(String... roles) {
        // List<GrantedAuthority> 개개인의 권한을 조회해서 요소로 갖는다는 것
        // 이거의 반환값인 new SimpleGrantedAuthority(role))권한을 갖고 있는 객체를 받음
        // 근데 왜 리스트로 권한을 받을까? 한 유저가 하나의 롤만 가지지않음,
        // 즉 인가 처리할 때 여러가지 롤을 받을 수있기 때문에 리스트로 받는게 기본임
        return Arrays.stream(roles)
                .map(role -> new SimpleGrantedAuthority(role))
                .collect(Collectors.toList());
    }
}
