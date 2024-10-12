package org.example.authserver.config;

import io.swagger.v3.oas.annotations.enums.SecuritySchemeIn;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.extensions.Extension;
import io.swagger.v3.oas.annotations.extensions.ExtensionProperty;
import io.swagger.v3.oas.annotations.security.OAuthScope;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.servers.Server;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Configuration
@io.swagger.v3.oas.annotations.security.SecurityScheme(
        name = "Bearer Authentication",
        description = "JWT auth description",
        type = SecuritySchemeType.OAUTH2,
        bearerFormat = "JWT",
        scheme = "bearer",
        in = SecuritySchemeIn.HEADER,
        flows = @io.swagger.v3.oas.annotations.security.OAuthFlows(
                authorizationCode = @io.swagger.v3.oas.annotations.security.OAuthFlow(
                        authorizationUrl = "https://account.devsphere.id.vn/oauth2/authorize",
                        tokenUrl = "https://account.devsphere.id.vn/oauth2/token",
                        scopes = {
                                @OAuthScope(name = "openid", description = "openid"),
                        },
                        extensions = {
                                @Extension(name = "x-pkce", properties = {
                                        @ExtensionProperty(name = "required", value = "true")
                                })
                        }
                )
        )
)
public class OpenApiConfig {
    @Value("${url.base-url}")
    private String appUrl;

    @Bean
    public OpenAPI openAPI() {
        return new OpenAPI()
                .info(new Info()
                        .title("Location service API")
                        .description("Location service API")
                        .version("1.0.0")
                        .contact(new Contact()
                                .email("sonnguyen.20050319@gmail.com")
                                .url("https://github.com/NgocSonNguyen-Mikey")
                                .name("SonNguyenNgoc")
                        )
                )
                .servers(List.of(new Server()
                        .url(appUrl)
                        .description(appUrl.split("://")[0]))
                );
    }
}
