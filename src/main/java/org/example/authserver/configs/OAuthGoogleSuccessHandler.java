package org.example.authserver.configs;

import lombok.extern.log4j.Log4j2;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.example.authserver.entities.CustomOAuth2User;
import org.example.authserver.entities.Provider;
import org.example.authserver.entities.User;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

@Component
@Log4j2
public class OAuthGoogleSuccessHandler implements AuthenticationSuccessHandler {

    @Value("${url.confirm-google-page}")
    private String confirmUrl;

    @Value("${url.home-page-url}")
    private String homPageUrl;

    @Value("${url.register-google-handle}")
    private String handleOAuthUrl;

    @Override
    public void onAuthenticationSuccess(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication
    ) throws IOException, ServletException {
        HttpSessionRequestCache requestCache = new HttpSessionRequestCache();
        SavedRequest savedRequest = requestCache.getRequest(request, response);
        log.info(authentication.getPrincipal().toString());
        var principal = authentication.getPrincipal();
        if (authentication.getPrincipal() instanceof CustomOAuth2User) {
            CustomOAuth2User customUser = (CustomOAuth2User) principal;
            User user = customUser.getUser();
            if (user.getProvider() == Provider.LOCAL) {
                String redirectUrl = savedRequest.getRedirectUrl();
                String encodedUrl = URLEncoder.encode(redirectUrl, StandardCharsets.UTF_8);
                response.sendRedirect(confirmUrl + "?c=" + encodedUrl + "&id=" + user.getId());
                return;
            }
        }
        if (savedRequest != null) {
            response.sendRedirect(savedRequest.getRedirectUrl());
        }
        else {
            response.sendRedirect(homPageUrl + handleOAuthUrl);
        }
    }
}
