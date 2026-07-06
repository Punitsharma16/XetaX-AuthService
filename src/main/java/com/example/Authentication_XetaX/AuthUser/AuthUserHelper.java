package com.example.Authentication_XetaX.AuthUser;

import java.util.UUID;

public class AuthUserHelper {
    public static UUID parseUUID(String userId){
        return UUID.fromString(userId);
    }

}
