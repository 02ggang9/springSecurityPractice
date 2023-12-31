package com.springSecurity.security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http.authorizeHttpRequests(auth -> auth.
                        anyRequest().authenticated()
                )
                .formLogin(formLogin -> formLogin
                        .loginPage("/loginPage") // 이 페이지는 로그인을 위한 페이지이므로 누구나 접근이 가능해야 한다.
                        .defaultSuccessUrl("/")
                        .failureUrl("/login")
                        .usernameParameter("userId") // 주의
                        .passwordParameter("password") // 주의
                        .loginProcessingUrl("/login_proc")
                        .successHandler((request, response, authentication) -> {
                            System.out.println("authentication" + authentication.getName());
                            response.sendRedirect("/");
                        })
                        .failureHandler((request, response, exception) -> {
                            System.out.println("exception" + exception.getMessage());
                            response.sendRedirect("/login");
                        })
                        .permitAll()
                )
                .build();
    }

}
