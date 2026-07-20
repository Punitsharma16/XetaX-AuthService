package com.xetax.auth_xetax.AuthToken.AuthTokenDTO;

import com.xetax.auth_xetax.AuthUser.AuthUserDto;

public record TokenResponse(String accessToken, String refreshToken, long expiresIn, String tokenType, AuthUserDto userDto) {
    public static TokenResponse of(String accessToken, String refreshToken, long expiresIn, AuthUserDto userDto){
        return new TokenResponse(accessToken,refreshToken,expiresIn,"Bearer",userDto);
    }
}
