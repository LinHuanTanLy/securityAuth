package com.ly.auth.jwt;

import com.ly.auth.service.UserService;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.filter.OncePerRequestFilter;


import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import io.jsonwebtoken.Jwts;

public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private Logger mLogger = LoggerFactory.getLogger(JwtAuthenticationFilter.class);
    @Autowired
    private JwtTokenProvider mJwtTokenProvider;
    @Autowired
    private AuthParameters mAuthParameters;
    @Autowired
    private UserService mUserService;

    //1.从每个请求header获取token
    //2.调用前面写的validateToken方法对token进行合法性验证
    //3.解析得到username，并从database取出用户相关信息权限
    //4.把用户信息以UserDetail形式放进SecurityContext以备整个请求过程使用。
    // （例如哪里需要判断用户权限是否足够时可以直接从SecurityContext取出去check
    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, FilterChain filterChain) throws ServletException, IOException {

        String token = getJwtFromRequest(httpServletRequest);
        if (token != null && mJwtTokenProvider.validateToken(token)) {
            String userName = getUserNameFromJwt(token, mAuthParameters.getJwtTokenSecret());
            UserDetails userDetails = mUserService.getUserDetailByUserName(userName);
            Authentication authentication = new UsernamePasswordAuthenticationToken(
                    userDetails, null, userDetails.getAuthorities()
            );
            SecurityContextHolder.getContext().setAuthentication(authentication);
        } else {
            mLogger.error("the userName " + httpServletRequest.getParameter("username") + "has not token");
        }

        super.doFilter(httpServletRequest, httpServletResponse, filterChain);
    }


    /**
     * get the token from request
     *
     * @param httpServletRequest
     * @return
     */
    private String getJwtFromRequest(HttpServletRequest httpServletRequest) {
        String token = httpServletRequest.getHeader("Authorization");
        if (token != null && token.startsWith("Bearer")) {
            return token.replace("Bearer", "");
        } else {
            return null;
        }
    }

    /**
     * get the userName from jwt,
     *
     * @param token
     * @param signKey
     * @return
     */
    private String getUserNameFromJwt(String token, String signKey) {
        return Jwts.parser().setSigningKey(signKey)
                .parseClaimsJws(token)
                .getBody().getSubject();
    }
}
