package com.ly.auth.jwt;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.security.core.Authentication;

import java.util.Date;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.UnsupportedJwtException;

@Component
public class JwtTokenProvider {

    Logger mLogger = LoggerFactory.getLogger(JwtTokenProvider.class);
    @Autowired
    private AuthParameters mAuthParameters;

    public String createJwtToken(Authentication authentication) {
        String userName = ((org.springframework.security.core.userdetails
                .User) authentication.getPrincipal()).getUsername();
        Date date = new Date(System.currentTimeMillis() + mAuthParameters.getTokenExpiredMs());
        return Jwts.builder()
                .setSubject(userName)
                .setExpiration(date)
                .setIssuedAt(new Date())
                .signWith(SignatureAlgorithm.HS512, mAuthParameters.getJwtTokenSecret())
                .compact();
    }

    public boolean validateToken(String token) {
        String VALIDATE_FAILED = "validate failed:";
        try {
            Jwts.parser().setSigningKey(mAuthParameters.getJwtTokenSecret())
                    .parseClaimsJws(token);
            return true;
        } catch (ExpiredJwtException | UnsupportedJwtException | MalformedJwtException | SignatureException | IllegalArgumentException e) {
            e.printStackTrace();
            mLogger.error(VALIDATE_FAILED + e.getMessage());
            return false;
        }

    }
}
