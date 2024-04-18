package com.myprojects.jwtimplementation.security;

import com.myprojects.jwtimplementation.jwt.JwtAuthenticationFilter;
import com.myprojects.jwtimplementation.jwt.JwtUnauthorizedAuthenticationEntryPoint;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.util.Arrays;
import java.util.List;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {


    @Bean
    public static PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    @Autowired
    private JwtUnauthorizedAuthenticationEntryPoint authenticationExeptionEntryPoint;

    @Autowired
    private JwtAuthenticationFilter jwtAuthFilter;



    @Bean
    public WebMvcConfigurer corsConfigurer(){
        return new WebMvcConfigurer() {
            @Override
            public void addCorsMappings(CorsRegistry registry) {
                registry.addMapping("/**").allowedOrigins("http://localhost:3000");
            }
        };
    }
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {


        http.csrf(AbstractHttpConfigurer::disable);

        //requests
        http.authorizeHttpRequests(c  ->
                c.requestMatchers("/api/auth/**").permitAll()
                        .anyRequest().authenticated()
        );


        // filtro di eccezione
         http
                .exceptionHandling(exception -> exception
                        .authenticationEntryPoint(authenticationExeptionEntryPoint));

         // filtro JWT
        http.addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }


    // METODO DUE PER IL FOR

    /*
     http.authorizeHttpRequests(authz -> {
            for (Endpoint e: endpoints) {
                if (e.getRoles().contains(RoleEndpoint.ADMIN) && e.getRoles().contains(RoleEndpoint.USER)) {
                    authz.requestMatchers(HttpMethod.GET, e.getPath()).hasAnyRole("ADMIN","USER");
                    authz.requestMatchers(e.getPath()).hasRole("ADMIN");
                }else if(e.getRoles().contains(RoleEndpoint.ADMIN) && e.getRoles().size() == 1){
                    authz.requestMatchers(e.getPath()).hasRole("ADMIN");
                } else if (e.getRoles().contains(RoleEndpoint.USER) && e.getRoles().size() == 1) {
                    authz.requestMatchers(e.getPath()).hasRole("USER");
                }
            }
            authz.requestMatchers(appContext + loginBaseUri).permitAll()
                    .requestMatchers(appContext +registerBaseUri).permitAll()
                    .requestMatchers(appContext + errorBaseUri).permitAll()
                    .requestMatchers(appContext + modifyUser).authenticated()
                    .anyRequest().authenticated();
        }).httpBasic(Customizer.withDefaults());


        //filtro eccezione e filtro di JWT rimangono gli stessi
     */

}
