package com.xetax.auth_xetax.AuthUser;

import java.util.UUID;

public class AuthUserHelper {
    public static UUID parseUUID(String userId){
        return UUID.fromString(userId);
    }

}
