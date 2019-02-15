package com.ly.auth.conf;

import com.ly.auth.jwt.JwtAuthenticationFilter;
import com.ly.auth.service.DatabaseUserDetailsService;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
class WebSecurityConfig {

    @Configuration
    public static class MySecurityConfig extends WebSecurityConfigurerAdapter {

        @Autowired
        @Qualifier("databaseUserDetailService")
        private DatabaseUserDetailsService mDatabaseUserDetailsService;


        @Autowired
        @Qualifier("authenticationSuccessHandler")
        private AuthenticationSuccessHandler mAuthenticationSuccessHandler;

        @Autowired
        @Qualifier("authenticationFailHandler")
        private AuthenticationFailHandler mAuthenticationFailHandler;

        @Autowired
        @Qualifier("authenticationEntryPointImpl")
        private AuthenticationEntryPoint mAuthenticationEntryPoint;

        @Bean
        public PasswordEncoder passwordEncoder() {
            return new BCryptPasswordEncoder();
        }

        @Bean
        public JwtAuthenticationFilter getJwtAuthenticationFilter() {
            return new JwtAuthenticationFilter();
        }

        @Override
        protected void configure(HttpSecurity http) throws Exception {
//            http.sessionManagement()
//                    .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
//                    .and()
//                    .csrf()
//                    .disable()
//                    .authorizeRequests()
//                    .antMatchers("v2/api-docs/**")
//                    .permitAll()
//                    .anyRequest()
//                    .authenticated()
//                    .and()
//                    .formLogin()
//                    .loginProcessingUrl("/api/login")
//                    .successHandler(mAuthenticationSuccessHandler)
//                    .failureHandler(mAuthenticationFailHandler)
//                    .and()
//                    .exceptionHandling()
//                    .authenticationEntryPoint(mAuthenticationEntryPoint);

            http.addFilterBefore(getJwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class)
                    .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                    .and().csrf().disable()
                    .authorizeRequests()
                    .antMatchers("/v2/api-docs/**").permitAll()
                    .anyRequest().authenticated()
                    .and().formLogin().loginProcessingUrl("/api/login")
                    .successHandler(mAuthenticationSuccessHandler)
                    .failureHandler(mAuthenticationFailHandler)
                    .and().exceptionHandling().authenticationEntryPoint(mAuthenticationEntryPoint);
        }

        @Override
        protected void configure(AuthenticationManagerBuilder auth) throws Exception {
            auth.userDetailsService(mDatabaseUserDetailsService)
                    .passwordEncoder(passwordEncoder());
        }
    }

}
