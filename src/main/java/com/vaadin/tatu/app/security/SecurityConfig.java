package com.vaadin.tatu.app.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;

import com.vaadin.tatu.app.Application;
@EnableWebSecurity
@Configuration
public class SecurityConfig {

    private final RedirectAuthenticationSuccessHandler successHandler;

    @Autowired
    public SecurityConfig(UserDetailsService userDetailsService,
            PasswordEncoder passwordEncoder,
            RedirectAuthenticationSuccessHandler successHandler) {
        this.successHandler = successHandler;
    }

    @Bean
    public SecurityFilterChain configure(HttpSecurity http) throws Exception {
        // Not using Spring CSRF here to be able to use plain HTML for the login
        // page

        http.securityContext(securityContext -> securityContext
            .securityContextRepository(
                new HttpSessionSecurityContextRepository())
            .requireExplicitSave(false));

        http.authorizeHttpRequests(auth -> auth
            .requestMatchers("/VAADIN/**", "/favicon.ico",
                Application.LOGIN_URL, Application.LOGIN_PROCESSING_URL,
                Application.LOGIN_FAILURE_URL, Application.LOGOUT_URL,
                Application.LOGOUT_PROCESSING_URL)
            .permitAll().anyRequest().authenticated());
        http.csrf(csrfCustomizer -> csrfCustomizer.disable());

        http.formLogin(config -> config.loginPage(Application.LOGIN_URL)
                .loginProcessingUrl(Application.LOGIN_PROCESSING_URL)
                .failureUrl(Application.LOGIN_FAILURE_URL)
                .successHandler(successHandler).permitAll());

        http.logout(config -> config
            .logoutRequestMatcher(request -> Application.LOGOUT_PROCESSING_URL
                .equals(request.getServletPath())
                && "GET".equals(request.getMethod()))
            .logoutUrl(Application.LOGOUT_PROCESSING_URL)
            .invalidateHttpSession(true)
            .clearAuthentication(true)
            .deleteCookies("JSESSIONID")
            .logoutSuccessUrl(Application.LOGOUT_URL)
            .permitAll());

        return http.build();
    }

}
