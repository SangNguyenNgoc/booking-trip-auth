package org.example.authserver.controllers;

import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.example.authserver.entities.Provider;
import org.example.authserver.exception.TokenExpiredException;
import org.example.authserver.exception.UserNotFoundException;
import org.example.authserver.services.UserService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

@Controller
@RequestMapping("/auth")
@RequiredArgsConstructor
@Log4j2
public class AuthController {

    @Value("${url.home-page-url}")
    private String homePageUrl;

    @Value("${url.confirm-google-handle}")
    private String confirmGoogleHandler;


    private final UserService userService;

    @GetMapping("/login")
    public String loginPage(
            @Value("${url.register-page-url}") String registerPageUrl,
            @RequestParam(name = "error", required = false) String error,
            Model model
    ) {
        if (error != null) {
            model.addAttribute("error", true);
        }
        model.addAttribute("register_page", registerPageUrl);
        model.addAttribute("home_page", homePageUrl);
        return "login";
    }


    @GetMapping("/verify")
    public String verify(
            @RequestParam(name = "t", required = false) String token,
            Model model
    ) {
        userService.verify(token);
        model.addAttribute("home_page", homePageUrl);
        model.addAttribute("image", "/images/tick.svg");
        model.addAttribute("notice", "Xác nhận thành công!");
        return "verified";
    }

    @GetMapping("/confirm-google")
    public String confirmGooglePage(
            @RequestParam(name = "c") String url,
            @RequestParam(name = "id") String id,
            Model model
    ) {
        var encodedUrl = URLEncoder.encode(url, StandardCharsets.UTF_8);
        var handleUrl = confirmGoogleHandler + "?c=" + encodedUrl + "&id=" + id;
        model.addAttribute("continue_url", handleUrl);
        return "confirm-google";
    }

    @GetMapping("/confirm-google-handler")
    public String handleConfirmGoogle(
            @RequestParam(name = "c") String url,
            @RequestParam(name = "id") String id
    ) {
        userService.updateProvider(Provider.GOOGLE, id);
        return "redirect:" + url;
    }


    @ExceptionHandler(TokenExpiredException.class)
    public String handleTokenExpiredException(
            TokenExpiredException ex,
            Model model
    ) {
        model.addAttribute("home_page", homePageUrl);
        model.addAttribute("image", "/images/warn.svg");
        model.addAttribute("notice",
                "Rất tiếc, đường dẫn đã hết hạn hoặc không hợp lệ!");
        return "verified";
    }

    // Bắt lỗi UserNotFoundException
    @ExceptionHandler(UserNotFoundException.class)
    public String handleUserNotFoundException(
            UserNotFoundException ex,
            Model model
    ) {
        model.addAttribute("home_page", homePageUrl);
        model.addAttribute("image", "/images/warn.svg");
        model.addAttribute("notice", "Không tìm thấy người dùng hợp lệ!");
        return "verified";
    }

}