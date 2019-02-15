package com.ly.auth.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service("databaseUserDetailService")
public class DatabaseUserDetailsService implements UserDetailsService {

    @Autowired
    private UserService mUserService;

    @Override
    public UserDetails loadUserByUsername(String s) throws UsernameNotFoundException {
        return mUserService.getUserDetailByUserName(s);
    }
}
