package com.azure_ad.controller;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.exceptions.InvalidClaimException;

import java.net.URL;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.Map;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;

public class ValidateAADToken {

    public String validateToken(String token) {
        try {
            // Decode the token to read the headers and claims
            DecodedJWT jwt = JWT.decode(token);

            System.out.println(jwt.getKeyId());

            URL jwkURL = new URL("https://login.microsoftonline.com/common/discovery/keys");
            JWKSet jwkSet = JWKSet.load(jwkURL);
            JWK jwk = jwkSet.getKeyByKeyId(jwt.getKeyId());
            if (jwk == null) {
                System.out.println("JWK not found");
                return "Invalid Token";
            }
            RSAPublicKey publicKey = (RSAPublicKey) jwk.toRSAKey().toPublicKey();
            Algorithm algorithm = Algorithm.RSA256(publicKey, null);

            JWTVerifier verifier = JWT.require(algorithm)
                    .withAudience("api://255900ae-0f1f-40b2-b2b3-4e5b2553041a")
                    .build();

            DecodedJWT decodedJWT = verifier.verify(token);

            // Extract the 'roles' claim as a list of strings
            List<String> roles = decodedJWT.getClaim("roles").asList(String.class);

            if (roles != null && roles.contains("download")) {
                System.out.println("Valid Role: download");
                return "Valid Token";
            } else {
                System.out.println("Invalid Role for Audience");
                return "Invalid Token";
            }
        } catch (TokenExpiredException e) {
            System.out.println("Token is expired");
        } catch (InvalidClaimException e) {
            System.out.println("Invalid Claim for Audience "+e);
        } catch (JWTVerificationException e) {
            System.out.println("Invalid token");
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return "Invalid Token";
    }
}

/*
The common endpoint is useful when you want to retrieve keys that are not specific to any particular tenant or application (i.e. in multi-tenant setups), while the tenant endpoint is useful when you want to retrieve keys that are specific to a particular tenant and application. With the common endpoint, the tenant gets determined based on the account details of the user.

The issuer value in the token tells an application which tenant the user is from. When a response returns from the /common endpoint, the issuer value in the token corresponds to the user’s tenant. A key that is specific to a certain tenant may not exist in the global keys.

The kid value for keys will match with the identifier for key that that has been used for signing the token you receive.

{
  "typ": "JWT",
  "alg": "RS256",
  "x5t": "H9nj5AOSswMphg1SFx7jaV-lB9w",
  "kid": "H9nj5AOSswMphg1SFx7jaV-lB9w"
}.{
  "aud": "api://255900ae-0f1f-40b2-b2b3-4e5b2553041a",
  "iss": "https://sts.windows.net/bd0154b0-2dc8-46bd-901e-e1a372e01c09/",
  "iat": 1726403176,
  "nbf": 1726403176,
  "exp": 1726407076,
  "aio": "E2dgYOjmNPgyJyk/889S26hrW+J1AA==",
  "appid": "24044f6a-6ae6-4b16-b91f-5437de71522d",
  "appidacr": "1",
  "idp": "https://sts.windows.net/bd0154b0-2dc8-46bd-901e-e1a372e01c09/",
  "oid": "7a43e1e8-d73a-41a6-b48f-d127bd768599",
  "rh": "0.AcYAsFQBvcgtvUaQHuGjcuAcCa4AWSUfD7JAsrNOWyVTBBrGAAA.",
  "roles": [
    "download"
  ],
  "sub": "7a43e1e8-d73a-41a6-b48f-d127bd768599",
  "tid": "bd0154b0-2dc8-46bd-901e-e1a372e01c09",
  "uti": "FtUYJMo2a0-bKnT2HVjyAA",
  "ver": "1.0"
}
 */

