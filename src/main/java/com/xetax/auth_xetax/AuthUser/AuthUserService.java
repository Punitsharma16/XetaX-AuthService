package com.xetax.auth_xetax.AuthUser;

public interface AuthUserService {
    //create user
    AuthUserDto createUser(AuthUserDto userDto);
    //get User by email id
    AuthUserDto getUserByEmail(String email);
    //update user
    AuthUserDto updateUser(AuthUserDto userDto,String userId);
    //delete user
    void deleteUser(String userId);
    //get All Users
    Iterable<AuthUserDto>getAllUser();
    //get user By id
    AuthUserDto getUserById(String userId);
//    AuthUserDto registerUser(AuthUserDto userDto);

}
