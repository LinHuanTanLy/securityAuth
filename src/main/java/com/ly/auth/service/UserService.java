package com.ly.auth.service;


import com.ly.auth.domain.User;
import com.ly.auth.repository.UserRepository;
import com.ly.auth.viewObject.UserView;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import javax.transaction.Transactional;

@Service
public class UserService {

    private final
    UserRepository mUserRepository;

    @Autowired
    public UserService(UserRepository mUserRepository) {
        this.mUserRepository = mUserRepository;
    }

    @Transactional
    public UserView getUserbyUserName(String userName) {
        UserView userView = new UserView();
        User user = mUserRepository.findByUserName(userName);
        userView.setUserDesc(user.getUserDescription());
        userView.setUserName(user.getUserName());
        List<String> roleCodes = new ArrayList<>();
        user.getRoles().forEach(role -> roleCodes.add(role.getRoleCode()));
        userView.setRoleCodes(roleCodes);
        return userView;
    }

    public UserDetails getUserDetailByUserName(String userName) {
        User user = mUserRepository.findByUserName(userName);
        if (user == null) {
            throw new UsernameNotFoundException("user:" + userName + "not found");
        }
        List<String> roleList = mUserRepository.queryUserOwnedRoleCodes(userName);
        List<GrantedAuthority> authorities = roleList.stream()
                .map(SimpleGrantedAuthority::new).collect(Collectors.toList());
        return new org.springframework.security.core.userdetails.User(userName
                , user.getPassWord(), authorities);
    }
}
