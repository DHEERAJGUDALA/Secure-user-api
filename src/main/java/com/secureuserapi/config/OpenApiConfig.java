package com.secureuserapi.config;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeIn;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.security.SecurityScheme;
import org.springframework.context.annotation.Configuration;

/**
 * Configures Swagger UI to show a "Authorize" button that sends
 * "Authorization: Bearer <token>" header with every request.
 *
 * Without this, Swagger UI has no way to send the JWT token
 * and all secured endpoints return 401 in the UI.
 */
@Configuration
@OpenAPIDefinition(
        info = @Info(
                title = "Secure User API",
                version = "1.0",
                description = "JWT-secured REST API with Role-Based Access Control"
        )
)
@SecurityScheme(
        name = "bearerAuth",
        type = SecuritySchemeType.HTTP,
        scheme = "bearer",
        bearerFormat = "JWT",
        in = SecuritySchemeIn.HEADER
)
public class OpenApiConfig {
    // Annotation-driven — no methods needed
}
