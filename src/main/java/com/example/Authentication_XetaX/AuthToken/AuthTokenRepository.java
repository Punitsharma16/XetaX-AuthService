package com.example.Authentication_XetaX.AuthToken;

import com.example.Authentication_XetaX.AuthToken.AuthTokenEntity.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface AuthTokenRepository extends JpaRepository<RefreshToken, UUID> {
    Optional<RefreshToken> findByJti(String jti);

}
