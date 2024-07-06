package com.springboot.config;

import com.springboot.member.InMemoryMemberService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.method.P;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfiguration {
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .headers().frameOptions().sameOrigin()
                .and()
                .csrf().disable()
                .formLogin()
                //로그인을 실제 사용할 주소
                .loginPage("/auths/login-form")
                .loginProcessingUrl("/process_login")
                //실제 로그인이 실패하면 나올 주소
                .failureUrl("/auths/login-form?error")
                .and()
                .logout()
                .logoutUrl("/logout")
                .logoutSuccessUrl("/")
                .and()
                //권한이 없는 특정 사용자가 접근했을때 이걸 보여주겠다
                .exceptionHandling().accessDeniedPage("/auths/access-denied")
                .and()
                .authorizeHttpRequests(authorize -> authorize
                        //순서 중요함
                        .antMatchers("/orders/**").hasRole("ADMIN")
                        .antMatchers("/members/my-page").hasRole("USER")
                        //* 하나면 조회만 , ** 두개면 depth 2까지 허용
                        .antMatchers("/**").permitAll());

        return http.build();
    }

//    @Bean
//    public UserDetailsManager userDetailsManager() {
//        //UserDetailsManager는 인터페이스고 추상화 되어있다.
////        UserDetails user =
////                User.withDefaultPasswordEncoder()
////                        .username("luckykim@google.com")
////                        .password("qwerty123")
////                        .roles("USER")
////                        .build();
//        UserDetails admin =
//                User.withDefaultPasswordEncoder()
//                        .username("admin@google.com")
//                        .password("1111")
//                        .roles("ADMIN")
//                        .build();
//        return new InMemoryUserDetailsManager(admin);
//      //메서드 명으로 등록됨
//    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }
}
