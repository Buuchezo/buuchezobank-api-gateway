package com.buuchezo.apigateway.security;

import jakarta.validation.constraints.NotNull;
import lombok.RequiredArgsConstructor;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
@RequiredArgsConstructor
public class AuthentificationFilter implements GlobalFilter {

    private static final String USER_EMAIL_HEADER = "X-User-Email";

    private final JwtValidationUtil jwtValidationUtil;

    @Override
    public Mono<Void> filter(
            @NotNull ServerWebExchange exchange,
            GatewayFilterChain chain
    ) {

        String path =
                exchange.getRequest()
                        .getURI()
                        .getPath();

        /*
         * Public endpoints that do not require
         * an existing JWT.
         */
        if (path.startsWith("/api/auth/")
                || path.startsWith("/api/admin/auth/")
                || path.equals("/api/businesses/onboarding")) {

            return chain.filter(exchange);
        }

        String authHeader =
                exchange.getRequest()
                        .getHeaders()
                        .getFirst(HttpHeaders.AUTHORIZATION);

        if (authHeader == null ||
                !authHeader.startsWith("Bearer ")) {

            return onError(
                    exchange,
                    "No Authorization Header",
                    HttpStatus.UNAUTHORIZED
            );
        }

        String token = authHeader.substring(7);

        try {

            /*
             * First validate the token.
             */
            jwtValidationUtil.validateToken(token);

            /*
             * Extract the authenticated user's email
             * from the validated JWT.
             */
            String email =
                    jwtValidationUtil.extractEmail(token);

            if (email == null || email.isBlank()) {

                return onError(
                        exchange,
                        "User email not found in token",
                        HttpStatus.UNAUTHORIZED
                );
            }

            /*
             * Remove any X-User-Email supplied by the client.
             *
             * This is important because otherwise a client
             * could send:
             *
             * X-User-Email: someone-else@example.com
             *
             * and impersonate another user.
             */
            ServerWebExchange modifiedExchange =
                    exchange.mutate()
                            .request(
                                    exchange.getRequest()
                                            .mutate()
                                            .headers(headers -> {
                                                headers.remove(
                                                        USER_EMAIL_HEADER
                                                );

                                                headers.set(
                                                        USER_EMAIL_HEADER,
                                                        email
                                                );
                                            })
                                            .build()
                            )
                            .build();

            return chain.filter(modifiedExchange);

        } catch (Exception ex) {

            return onError(
                    exchange,
                    "Invalid or expired token",
                    HttpStatus.UNAUTHORIZED
            );
        }
    }

    private Mono<Void> onError(
            ServerWebExchange exchange,
            String message,
            HttpStatus status
    ) {

        System.out.println(
                "Authentication error: " + message
        );

        exchange.getResponse()
                .setStatusCode(status);

        return exchange.getResponse()
                .setComplete();
    }
}