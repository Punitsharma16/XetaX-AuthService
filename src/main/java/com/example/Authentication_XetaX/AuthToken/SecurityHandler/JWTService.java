package com.example.Authentication_XetaX.AuthToken.SecurityHandler;

import com.example.Authentication_XetaX.AuthUser.AuthUserDto;
import com.example.Authentication_XetaX.AuthUser.AuthUserEntity;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import lombok.Getter;
import lombok.Setter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.sql.Date;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
@Service
@Getter
@Setter
public class JWTService {

    //jwt related dependency add in pom.xml
    //new service: jwt helper service
//     1. perform operations with jwt
//            -> jwt create
//            ->verify
//    ->token get username from token
//    ->expire
//    ->refreshToken Handle: create , operations
//    2. generate jwt authentication filter
//    3.make security config
//    4.Auth Controller,Login


    private final SecretKey secretKey;
    private final long accessTtlSeconds;
    private final long refreshTtlSeconds;
    private final String issuer;


    public JWTService(@Value("${security.jwt.secret}")String secretKey, @Value("${security.jwt.access-ttl-seconds}") long accessTtlSeconds, @Value("${security.jwt.refresh-ttl-seconds}")long refreshTtlSeconds, @Value("${security.jwt.issuer}")String issuer) {
        if(secretKey==null|| secretKey.length()>64){
            throw new IllegalArgumentException("Secret key must be at least 32 characters");
        }
        this.secretKey= Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8));
        this.accessTtlSeconds = accessTtlSeconds;
        this.refreshTtlSeconds = refreshTtlSeconds;
        this.issuer = issuer;
    }
    public  String generateAccessToken(AuthUserEntity user){
        Instant now =Instant.now();
        return Jwts.builder().id(UUID.randomUUID().toString())
                .subject(user.getId().toString())
                .issuer(issuer)
                .issuedAt(Date.from(now))
                .expiration(java.util.Date.from(now.plusSeconds(accessTtlSeconds))).claims(Map.of("user",user.getEmail(),"typ","access"))
                .signWith(secretKey, SignatureAlgorithm.HS256).compact();
    }
    //generateRefreshToken
    //Why we need to store the refresh token in cookie:
//    -> stop the xss theft
//    -> stop csrf
//    ->https only transport
//    -> auto expiration
//    -> auth send refreshToken
    public  String generateRefreshToken(AuthUserEntity user, String jti){
        Instant now =Instant.now();
        return Jwts.builder().id(jti)
                .subject(user.getId().toString())
                .issuer(issuer)
                .issuedAt(Date.from(now))
                .expiration(java.util.Date.from(now.plusSeconds(accessTtlSeconds))).claims(Map.of( "typ","refresh"))
                .signWith(secretKey, SignatureAlgorithm.HS256).compact();
    }
    //parse the token
    public Jws<Claims> parse(String token){
        try {
            return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token);
        } catch (JwtException | IllegalArgumentException e) {
            throw new RuntimeException(e);
        }
    }

    //is it accessToken
    public boolean isAccessToken(String token){
        Claims claims =parse(token).getPayload();
        return "access".equals(claims.get("typ"));
    }
    //is it refreshToken
    public boolean isRefreshToken(String token){
        Claims claims =parse(token).getPayload();
        return "refresh".equals(claims.get("typ"));
    }
    //Fetch User
    public UUID getUserId(String token){
        Claims claims=parse(token).getPayload();
        return UUID.fromString(claims.getSubject());
    }
    //token Id
    public  String getJti(String token){
        return parse(token).getPayload().getId();

    }
    //fetch roles

    public List<String> getRoles(String token){
        Claims claims=  parse(token).getPayload();
        return (List<String>) claims.get("roles");

    }
    //fetch email
    public String  getemail(String token){
        Claims claims=  parse(token).getPayload();
        return claims.get("email").toString();

    }
}
