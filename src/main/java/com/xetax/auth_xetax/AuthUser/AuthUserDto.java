package com.xetax.auth_xetax.AuthUser;


import com.xetax.auth_xetax.AuthRole.AuthRoleDto;
import com.xetax.auth_xetax.AuthToken.AuthTokenEntity.LoginProvider;
import lombok.*;

import java.io.Serializable;
import java.time.Instant;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AuthUserDto implements Serializable {
    private UUID id;
    private String email;
    private String password;
    private String name;
    private String image;
    private boolean isEnable=true;
    private boolean isAdmin;
    private String phone;
    private String company;
    private String parentId;
    private Instant createAt=Instant.now();
    private Instant updateAt=Instant.now();
    private LoginProvider provider;
    private Set<AuthRoleDto> roles= new HashSet<>();
}
