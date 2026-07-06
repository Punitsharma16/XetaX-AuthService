package com.example.Authentication_XetaX.AuthToken.AuthTokenEntity;

import com.example.Authentication_XetaX.AuthUser.AuthUserEntity;
import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;
import java.util.UUID;
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Entity
@Table(name="refresh_tokens",indexes = {
        @Index(name = "refresh_token_jti_index", columnList = "jti",unique = true),
        @Index(name = "refresh_token_jti_index", columnList = "user_id",unique = true)
})
public class RefreshToken {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    UUID id;
    @Column(name = "jti",unique = true,nullable = false,updatable = false)
    private  String jti;
    @ManyToOne(optional = false,fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id",nullable = false,updatable = false)
    private AuthUserEntity user;
    @Column(nullable = false,updatable = false)
    private Instant createAt;
    @Column(nullable = false)

    private Instant expiresAt;
    @Column(nullable = false)
    private boolean revoked;
    private String replacedByToken;
}
