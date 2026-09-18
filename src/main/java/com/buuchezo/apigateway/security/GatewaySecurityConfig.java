package com.buuchezo.apigateway.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;

import java.util.List;

@Configuration
@EnableWebFluxSecurity
public class GatewaySecurityConfig {

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(
            ServerHttpSecurity httpSecurity
    ) {

        return httpSecurity
                .csrf(ServerHttpSecurity.CsrfSpec::disable)

                .cors(cors -> cors.configurationSource(corsConfigurationSource()))

                .authorizeExchange(authorizeExchangeSpec ->
                        authorizeExchangeSpec

                                // Allow browser CORS preflight requests
                                .pathMatchers(HttpMethod.OPTIONS, "/**")
                                .permitAll()

                                // Allow authentication endpoints
                                .pathMatchers("/api/auth/**")
                                .permitAll()

                                // Global authentication filter handles
                                // protected endpoints
                                .anyExchange()
                                .permitAll()
                )

                .build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {

        CorsConfiguration configuration =
                new CorsConfiguration();

        configuration.setAllowedOrigins(
                List.of("http://localhost:5173")
        );

        configuration.setAllowedMethods(
                List.of(
                        "GET",
                        "POST",
                        "PUT",
                        "DELETE",
                        "PATCH",
                        "OPTIONS"
                )
        );

        configuration.setAllowedHeaders(
                List.of("*")
        );

        configuration.setAllowCredentials(true);

        configuration.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source =
                new UrlBasedCorsConfigurationSource();

        source.registerCorsConfiguration(
                "/**",
                configuration
        );

        return source;
    }

    @Bean
    public RouteLocator routeLocator(
            RouteLocatorBuilder builder
    ) {

        return builder.routes()

                .route(
                        "user-account-service",
                        r -> r.path(
                                        "/api/auth/**",
                                        "/api/users/**",
                                        "/api/accounts/**"
                                )
                                .uri("lb://USER-ACCOUNT-SERVICE")
                )

                .route(
                        "transaction-service",
                        r -> r.path(
                                        "/api/transactions/**"
                                )
                                .uri("lb://TRANSACTION-SERVICE")
                )

                .build();
    }
}