package com.azure_ad.controller;

import com.auth0.jwt.interfaces.Claim;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/v1")
public class FileUploadController {

    @GetMapping("/fileUpload")
    public String fileUpload(@RequestHeader("Authorization") String authorizationHeader) {
        // Check if the Authorization header starts with "Bearer "
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            String token = authorizationHeader.substring(7); // Extract the token part after "Bearer "
            // Here you can pass the token to your validateToken method
            ValidateAADToken validator = new ValidateAADToken();
            String validationResponse = validator.validateToken(token);
            return validationResponse.equals("Valid Token")
                    ? "File uploaded successfully"
                    : "Invalid Token";
        } else {
            return "Missing or invalid Authorization header";
            //Map<String, Claim> claims = jwt.getClaims();
        }
    }
}