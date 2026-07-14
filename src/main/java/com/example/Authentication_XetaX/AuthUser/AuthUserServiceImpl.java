package com.example.Authentication_XetaX.AuthUser;

import com.example.Authentication_XetaX.AuthConstants.AuthPublicUrls;
import com.example.Authentication_XetaX.AuthRole.AuthRoleEntity;
import com.example.Authentication_XetaX.AuthRole.AuthRoleRepository;
import com.example.Authentication_XetaX.AuthToken.AuthTokenEntity.LoginProvider;
import com.example.Authentication_XetaX.Exceptionhandler.ResourceNotFoundException;
import jakarta.transaction.Transactional;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;
@Service
public class AuthUserServiceImpl implements AuthUserService, UserDetailsService {
    @Autowired
    AuthUserRepository userRepository;
    @Autowired
    ModelMapper modelMapper;

    @Autowired
    PasswordEncoder passwordEncoder;
    @Autowired
    AuthRoleRepository roleRepository;

    @Override
    @Transactional
    public AuthUserDto createUser(AuthUserDto userDto) {
        if(userDto.getEmail()==null|| userDto.getEmail().isBlank()){
            throw new IllegalArgumentException("Email is required");
        }
        if (userRepository.existsByEmail(userDto.getEmail())) {
            throw new IllegalArgumentException("Email Already Existed");
        }
        AuthUserEntity user= modelMapper.map(userDto, AuthUserEntity.class);
        user.setId(null);   // MOST IMPORTANT LINE
        user.setParentId(userDto.getParentId()!=null?userDto.getParentId():"#");
        user.setProvider(userDto.getProvider()!=null?userDto.getProvider(): LoginProvider.LOCAL);
        user.setCreateAt(Instant.now());
        user.setPassword(passwordEncoder.encode(userDto.getPassword()));
        //role assign here to user  for authorization
        AuthRoleEntity role = roleRepository.findByName("ROLE_" + AuthPublicUrls.GUEST_ROLE)
                .orElseThrow(() -> new RuntimeException("Role not found"));

        Set<AuthRoleEntity> roles = new HashSet<>();
        roles.add(role);
        AuthUserEntity savedUser=userRepository.save(user);

        return modelMapper.map(savedUser, AuthUserDto.class);
    }

    @Override
    public AuthUserDto getUserByEmail(String email) {
        AuthUserEntity user= userRepository.findByEmail(email).orElseThrow(()->new ResourceNotFoundException("User Not Found with given email id"));
        return modelMapper.map(user, AuthUserDto.class);
    }

    @Override
    public AuthUserDto updateUser(AuthUserDto userDto, String userId) {
        UUID uuid=AuthUserHelper.parseUUID(userId);
        AuthUserEntity existingUser=userRepository.findById(uuid).orElseThrow(()->new ResourceNotFoundException(("User not existing with this id ")));
        // We are not  going to change email id for this project
        if(userDto.getName()!=null){
            existingUser.setName(userDto.getName());
        }
        if(userDto.getProvider()!=null){
            existingUser.setProvider(userDto.getProvider());
        }
        if(userDto.getPhone()!=null){
            existingUser.setPhone(userDto.getPhone());
        }
        if(userDto.getEmail()!=null){
            existingUser.setEmail(userDto.getEmail());
        }
        if(userDto.getPassword()!=null){
            existingUser.setPassword(userDto.getPassword());
        }
        if (userDto.getCompany() != null) {
            existingUser.setCompany(userDto.getCompany());
        }
        //TODO: change password updation logic ...
        existingUser.setEnable(userDto.isEnable());
        existingUser.setUpdateAt(Instant.now());
        AuthUserEntity updatedUser=userRepository.save(existingUser);
        return modelMapper.map(updatedUser,AuthUserDto.class);

    }

    @Override
    @Transactional
    public void deleteUser(String userId) {
        UUID uuid= AuthUserHelper.parseUUID(userId);
        AuthUserEntity user= userRepository.findById(uuid).orElseThrow(()->new ResourceNotFoundException("User Not Found with given id "));
        userRepository.delete(user);

    }

    @Override
    @Transactional
    public Iterable<AuthUserDto> getAllUser() {
        return userRepository.findAll().stream().map(
                user ->modelMapper.map(user,AuthUserDto.class)).toList();
    }

    @Override
    public AuthUserDto getUserById(String userId) {
        UUID uuid = AuthUserHelper.parseUUID(userId);

        AuthUserEntity user = userRepository.findById(uuid).orElseThrow(() -> new ResourceNotFoundException("User Not Found with given id "));
        return modelMapper.map(user, AuthUserDto.class);
    }
//    @Override
//    public AuthUserDto registerUser(AuthUserDto userDto) {
//        userDto.setPassword(passwordEncoder.encode(userDto.getPassword()));
//        userDto.setParentId("0");
//        return userService.createUser(userDto);
//    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        AuthUserEntity user = userRepository.findByEmail(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        return new org.springframework.security.core.userdetails.User(
                user.getEmail(),
                user.getPassword(),
                user.isEnabled(),
                true,
                true,
                true,
                Collections.emptyList()
        );
    }

}
