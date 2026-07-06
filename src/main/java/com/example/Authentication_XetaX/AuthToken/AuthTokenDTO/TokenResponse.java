package com.example.Authentication_XetaX.AuthToken.AuthTokenDTO;

import com.example.Authentication_XetaX.AuthUser.AuthUserDto;

public record TokenResponse(String accessToken, String refreshToken, long expiresIn, String tokenType, AuthUserDto userDto) {
    public static TokenResponse of(String accessToken, String refreshToken, long expiresIn, AuthUserDto userDto){
        return new TokenResponse(accessToken,refreshToken,expiresIn,"Bearer",userDto);
    }
}
