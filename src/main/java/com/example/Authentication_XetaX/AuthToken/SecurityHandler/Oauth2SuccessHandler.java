package com.example.Authentication_XetaX.AuthToken.SecurityHandler;

import com.example.Authentication_XetaX.AuthToken.AuthTokenEntity.LoginProvider;
import com.example.Authentication_XetaX.AuthToken.AuthTokenEntity.RefreshToken;
import com.example.Authentication_XetaX.AuthToken.AuthTokenRepository;
import com.example.Authentication_XetaX.AuthUser.AuthUserDto;
import com.example.Authentication_XetaX.AuthUser.AuthUserEntity;
import com.example.Authentication_XetaX.AuthUser.AuthUserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.Instant;
import java.util.UUID;
@Component
public class Oauth2SuccessHandler implements AuthenticationSuccessHandler {
    private final Logger logger= (Logger) LoggerFactory.getLogger(this.getClass());
    @Autowired
    AuthUserRepository userRepository;
    @Autowired
    JWTService jwtService;
    @Autowired
    CookieService cookieService;
    @Autowired
    AuthTokenRepository refreshTokenRepository;
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication) throws IOException, ServletException {

    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        logger.info("Successful Authentication");
        logger.info(authentication.toString());
        // username
        //user email
        // new user create
        OAuth2User user= (OAuth2User) authentication.getPrincipal();
        //identify user
        String registrationId="unknown";
        if(authentication instanceof OAuth2AuthenticationToken token){
            registrationId=token.getAuthorizedClientRegistrationId();
        }
        logger.info("registration Id--->",registrationId);
        logger.info("User is :" + user.getAttributes().toString());
        AuthUserEntity user1;
        switch (registrationId) {
            case "google":
                String googleId = user.getAttributes().getOrDefault("sub", "").toString();
                String email = user.getAttributes().getOrDefault("email", "").toString();
                String name = user.getAttributes().getOrDefault("name", "").toString();
                String picture = user.getAttributes().getOrDefault("picture", "").toString();
                logger.info("Google ID: {}", googleId);
                logger.info("Email: {}", email);
                logger.info("Name: {}", name);
                // user1 = User.builder().name(name).email(email).image(picture).provider(Provider.GOOGLE).build();
                user1 = userRepository.findByEmail(email)
                        .map(existingUser -> {
                            logger.info("User already exists in DB");
                            logger.info("Existing User ID: {}", existingUser.getId());
                            return existingUser;   // ✅ DB wala user return
                        })
                        .orElseGet(() -> {
                            logger.info("Creating new user");

                            AuthUserEntity newUser = AuthUserEntity.builder()
                                    .name(name)
                                    .email(email)
                                    .image(picture)
                                    .provider(LoginProvider.GOOGLE)
                                    .build();

                           AuthUserEntity savedUser = userRepository.save(newUser);
                            logger.info("New User Saved with ID: {}", savedUser.getId());

                            return savedUser;   // ✅ saved user return
                        });
                break;
            default:
                throw new RuntimeException("Invalid registration id");

        }
        // jwt token ke saath front pe fir redirect-----
        // making refresh token
        // ===== JWT & Refresh Token Section =====

        logger.info("Generating Refresh Token...");
        String jti= UUID.randomUUID().toString();
        RefreshToken refreshTokenObj= RefreshToken.builder()
                .jti(jti)
                .user(user1)
                .revoked(false)
                .createAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(jwtService.getRefreshTtlSeconds()))
                .build();
        logger.info("Refresh token saved in DB with JTI: {}", refreshTokenObj.getJti());
        refreshTokenRepository.save(refreshTokenObj);
        String accessToken= jwtService.generateAccessToken(user1);
        String refreshToken=jwtService.generateRefreshToken(user1,refreshTokenObj.getJti());
        logger.info("Generated Access Token: {}", accessToken);
        logger.info("Generated Refresh Token: {}", refreshToken);
        cookieService.attachRefreshCookie(response,refreshToken, (int) jwtService.getRefreshTtlSeconds()
        );
        logger.info("Refresh token attached in cookie successfully.");
        response.getWriter().write("Login Successful");


    }
}
