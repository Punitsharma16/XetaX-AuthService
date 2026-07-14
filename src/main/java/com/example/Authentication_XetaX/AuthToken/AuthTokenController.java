package com.example.Authentication_XetaX.AuthToken;

import com.example.Authentication_XetaX.AuthToken.AuthTokenDTO.LoginRequest;
import com.example.Authentication_XetaX.AuthToken.AuthTokenDTO.RefreshTokenReq;
import com.example.Authentication_XetaX.AuthToken.AuthTokenDTO.TokenResponse;
import com.example.Authentication_XetaX.AuthToken.AuthTokenEntity.RefreshToken;
import com.example.Authentication_XetaX.AuthToken.SecurityHandler.CookieService;
import com.example.Authentication_XetaX.AuthToken.SecurityHandler.JWTService;
import com.example.Authentication_XetaX.AuthUser.AuthUserDto;
import com.example.Authentication_XetaX.AuthUser.AuthUserEntity;
import com.example.Authentication_XetaX.AuthUser.AuthUserRepository;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.modelmapper.ModelMapper;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.Arrays;
import java.util.Optional;
import java.util.UUID;
@RestController
@RequestMapping("/auth/v1")
public class AuthTokenController {
    //Controller
//   ↓
//    AuthenticationManager
//   ↓
//    DaoAuthenticationProvider
//   ↓
//    UserDetailsService (loadUserByUsername)
//   ↓
//    UserRepository (DB call)
//   ↓
//    PasswordEncoder (password check)
//   ↓
//    Authentication success
//   ↓
//    JWT generate
        private static final Logger logger = LoggerFactory.getLogger(AuthTokenController.class);

        private final AuthTokenService authService;
        private final AuthUserRepository userRepository;
        private final JWTService jwtService;
        private final ModelMapper mapper;
        private final AuthenticationManager authenticationManager;
        private  final AuthTokenRepository refreshTokenRepository;
        private  final CookieService cookieService;
        public AuthTokenController(
                AuthTokenService authService,
                AuthUserRepository userRepository,
                JWTService jwtService,
                ModelMapper mapper,
                AuthenticationManager authenticationManager ,
                AuthTokenRepository refreshTokenRepository,
                CookieService cookieService
        ) throws Exception {
            this.authService = authService;
            this.userRepository = userRepository;
            this.jwtService = jwtService;
            this.mapper = mapper;
            this.authenticationManager = authenticationManager;
            this.refreshTokenRepository = refreshTokenRepository;
            this.cookieService=cookieService;
        }
        @PostMapping("/login")
        public ResponseEntity<?> login(@RequestBody LoginRequest loginRequest, HttpServletResponse response){
            // authenticate
            logger.info("Login request received for email: {}", loginRequest.email());

            Authentication authentication=  authenticate(loginRequest);
            logger.info("Authentication object returned: {}", authentication);
            AuthUserEntity user=userRepository.findByEmail(loginRequest.email()).orElseThrow(()->new BadCredentialsException("Invalid Username"));
            logger.info("User found in DB: {}", user.getEmail());
            if(!user.isEnabled()){
                logger.warn("User is disabled: {}", user.getEmail());
                throw  new DisabledException("User is disabled");
            }

            String jti= UUID.randomUUID().toString();
            var refreshTokenOb= RefreshToken.builder()
                    .jti(jti).user(user).createAt(Instant.now()).expiresAt(Instant.now().plusSeconds(jwtService.getRefreshTtlSeconds())).revoked(false).build();
            // refresh token information saved
            refreshTokenRepository.save(refreshTokenOb);

            //generate  access Token
            logger.info("Generating JWT token for user: {}", user.getEmail());

            String accesstoken=jwtService.generateAccessToken(user);
            String refreshToken=jwtService.generateRefreshToken(user,refreshTokenOb.getJti());
            logger.info("Access token generated successfully");
            // use cookie service to attach refresh token in cookie
//            cookieService.attachRefreshCookie(response,refreshToken, (int) jwtService.getRefreshTtlSeconds());

            TokenResponse tokenResponse= TokenResponse.of(accesstoken,refreshToken, jwtService.getAccessTtlSeconds(),mapper.map(user, AuthUserDto.class));
            return  ResponseEntity.ok(tokenResponse);

        }

    private Authentication authenticate(LoginRequest loginRequest) {
        try {
            return authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            loginRequest.email(),
                            loginRequest.password()
                    )
            );
        } catch (AuthenticationException e) {
            logger.error("Authentication failed", e);
            throw e;
        }
    }


        //    Client → /refresh (with refresh token)
//       ↓
//    Server:
//            ✔ Validate JWT
//   ✔ Check DB
//   ✔ Check revoked
//   ✔ Check expiry
//   ✔ Check user
//   ✔ Revoke old token
//   ✔ Create new token
//       ↓
//    Client gets:
//            → New Access Token
//   → New Refresh Token
        @PostMapping("/refresh")
        public  ResponseEntity<TokenResponse>refreshToken(@RequestBody (required = false) RefreshTokenReq body, HttpServletResponse response, HttpServletRequest request){
            String refreshToken=readRefreshTokenFromRequest(body,request).orElseThrow(()->new RuntimeException("Invalid Refresh Token"));
            if(!jwtService.isRefreshToken(refreshToken)){
                throw new BadCredentialsException("Invalid Refresh Token type");
            }
            String jti= jwtService.getJti(refreshToken);
            UUID userId=jwtService.getUserId(refreshToken);
            RefreshToken storedRefreshToken =  refreshTokenRepository.findByJti(jti).orElseThrow(()->new BadCredentialsException("Invalid Refresh Token "));
            if(storedRefreshToken.isRevoked()){
                throw  new BadCredentialsException("Token already revoked");
            }
            if(storedRefreshToken.getExpiresAt().isBefore(Instant.now())){
                throw new BadCredentialsException("Referesh Token is expired");
            }
            if(!storedRefreshToken.getUser().getId().equals(userId)){
                throw new BadCredentialsException("Refresh token does not belong to this user");
            }

            // refresh token to rotate
            storedRefreshToken.setRevoked(true);
            String newJti= UUID.randomUUID().toString();
            storedRefreshToken.setReplacedByToken(newJti);
            refreshTokenRepository.save(storedRefreshToken);
            AuthUserEntity user=storedRefreshToken.getUser();
            var newRefreshTokenDb= RefreshToken.builder()
                    .jti(newJti)
                    .user(user)
                    .createAt(Instant.now())
                    .expiresAt(Instant.now().plusSeconds(jwtService.getRefreshTtlSeconds()))
                    .revoked(false)
                    .build();
            refreshTokenRepository.save(newRefreshTokenDb);
            String newAccessToken=jwtService.generateAccessToken(user);
            String newRefreshToken=jwtService.generateRefreshToken(user,newRefreshTokenDb.getJti());
            cookieService.attachRefreshCookie(response,newRefreshToken, (int) jwtService.getRefreshTtlSeconds());
            return ResponseEntity.ok(TokenResponse.of(newAccessToken,newRefreshToken, jwtService.getAccessTtlSeconds(),mapper.map(user, AuthUserDto.class)));

        }
        //this method will read refresh token from request header or body
        private Optional<String> readRefreshTokenFromRequest(RefreshTokenReq body, HttpServletRequest request) {
            // 1. prefer reading refresh token from cookie
            if (request.getCookies() != null) {
                Optional<String> cookies = Arrays.stream(request.getCookies()).filter(c -> cookieService.getRefreshTokenCookieName().equals(c.getName()))
                        .map(Cookie::getValue).filter(v -> !v.isBlank()).findFirst();
                if (cookies.isPresent()) {
                    return cookies;
                }
                // 2. body
                if (body != null && body.refreshToken() != null && !body.refreshToken().isBlank()) {
                    return Optional.of(body.refreshToken());
                }
                // 3. custom header
                String refreshHeader = request.getHeader("X-RefreshToken");
                if (refreshHeader != null && !refreshHeader.isBlank()) {
                    return Optional.of(refreshHeader.trim());
                }
                // 4. Authorization Bearer Token
                String authHeader=request.getHeader(HttpHeaders.AUTHORIZATION);
                if (authHeader != null && authHeader.regionMatches(true, 0, "Bearer", 0, 7)) {

                    String candidate= authHeader.substring(7).trim();
                    if(!candidate.isEmpty()){
                        try {
                            if(jwtService.isRefreshToken(candidate)){
                                return Optional.of(candidate);

                            }

                        } catch (Exception e) {
                            throw new RuntimeException(e);
                        }

                    }
                }
            }
            return Optional.empty();
        }





        @PostMapping("/logoutRefreshToken")
        public ResponseEntity<Void> logout(HttpServletRequest request,
                                           HttpServletResponse response) {

            readRefreshTokenFromRequest(null, request).ifPresent(token -> {
                try {
                    if (jwtService.isRefreshToken(token)) {

                        String jti = jwtService.getJti(token);

                        refreshTokenRepository.findByJti(jti)
                                .ifPresent(refreshToken -> {
                                    refreshToken.setRevoked(true);
                                    refreshTokenRepository.save(refreshToken);
                                });
                    }
                } catch (JwtException ignored) {
                }
            });

            //  Clear Refresh Token Cookie
            Cookie cookie = new Cookie("refreshToken", null);
            cookie.setHttpOnly(true);
            cookie.setSecure(true); // only if HTTPS
            cookie.setPath("/");
            cookie.setMaxAge(0); // important: delete cookie
            response.addCookie(cookie);
            return ResponseEntity.noContent().build();
        }
    }

