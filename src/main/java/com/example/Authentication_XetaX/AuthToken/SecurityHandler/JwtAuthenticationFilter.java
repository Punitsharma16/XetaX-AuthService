package com.example.Authentication_XetaX.AuthToken.SecurityHandler;

import com.example.Authentication_XetaX.AuthUser.AuthUserHelper;
import com.example.Authentication_XetaX.AuthUser.AuthUserRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;
import java.util.UUID;
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    @Autowired
    JWTService jwtService;
    @Autowired
    AuthUserRepository userRepository;
    private Logger logger = LoggerFactory.getLogger(JwtAuthenticationFilter.class);

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String path = request.getServletPath();
        if (path.equals("/auth/api/v1/users/register")
                || path.equals("/auth/v1/login")) {
            filterChain.doFilter(request, response);
            return;
        }
        String header = request.getHeader("Authorization");
        logger.info("Authorization : {}", header);
        if (header != null && header.startsWith("Bearer ")) {
            //token extract validate  then authenticate create and then set in  security context
            String token = header.substring(7);

            try {
                Jws<Claims> parse = jwtService.parse(token);
                Claims payload = parse.getPayload();
                System.out.println("payload: " + payload);
                UUID userUuid = AuthUserHelper.parseUUID(payload.getSubject());
                var userOpt = userRepository.findById(userUuid);
                if (userOpt.isPresent()) {
                    var user = userOpt.get();

                    UsernamePasswordAuthenticationToken auth =
                            new UsernamePasswordAuthenticationToken(user, null, List.of());

                    SecurityContextHolder.getContext().setAuthentication(auth);
                }

            } catch (JwtException e) {
                logger.warn("Invalid JWT token: {}", e.getMessage());
            }
        }
        filterChain.doFilter(request, response);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        return request.getDispatcherType().name().equals("ERROR")
                || request.getRequestURI().startsWith("/auth/v1/");
    }
}
