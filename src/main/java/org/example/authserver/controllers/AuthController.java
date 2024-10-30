package org.example.authserver.controllers;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    @Value("${url.base-url}")
    private String baseUri;

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
        return "login";
    }


//    @GetMapping("/verify")
//    public ResponseEntity<Void> verify(@RequestParam(name = "t") String token) {
//        return ResponseEntity.status(HttpStatus.FOUND)
//                .location(userService.verify(token))
//                .build();
//    }

}