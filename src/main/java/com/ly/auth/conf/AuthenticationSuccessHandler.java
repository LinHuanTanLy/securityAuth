package com.ly.auth.conf;


import com.ly.auth.jwt.JwtTokenProvider;
import com.sun.org.apache.regexp.internal.RE;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.stereotype.Service;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Service("authenticationSuccessHandler")
public class AuthenticationSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {

    @Autowired
    JwtTokenProvider mJwtTokenProvider;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException {
        this.returnJson(authentication, response);
        logger.error("User--" + authentication.getName() + "LOGIN SUC");
    }


    private void returnJson(Authentication authentication, HttpServletResponse response) throws IOException {
        response.setStatus(HttpServletResponse.SC_OK);
        response.setCharacterEncoding("UTF-8");
        response.setContentType("application/json");
        response.getWriter().println("{\"tokenType\":\"Bearer\",\"token\": \"" + mJwtTokenProvider.createJwtToken(authentication) + "\"}");
    }
}
