package com.example.Authentication_XetaX.Exceptionhandler;

import com.example.Authentication_XetaX.Exceptionhandler.ErrorHandler.ApiError;
import com.example.Authentication_XetaX.Exceptionhandler.ErrorHandler.errorResponse;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class GlobalExceptionHandler {
    private  final Logger logger= LoggerFactory.getLogger(GlobalExceptionHandler.class);
        @ExceptionHandler({UsernameNotFoundException.class, BadCredentialsException.class, CredentialsExpiredException.class,  AuthenticationException.class, DisabledException.class})
        public ResponseEntity<ApiError> handleAuthException(Exception e, HttpServletRequest request){
            logger.info("Exception :{}",e.getClass().getName());
            var apiError= ApiError.of(HttpStatus.BAD_REQUEST.value(), e.getMessage(), "Bad Request",request.getRequestURI());
            return ResponseEntity.badRequest().body(apiError);

        }
        @ExceptionHandler(ResourceNotFoundException.class)
        public ResponseEntity<errorResponse> handleResourceNotFoundException(ResourceNotFoundException resourceNotFoundException) {
            errorResponse errorResponse = new errorResponse(resourceNotFoundException.getMessage(), HttpStatus.NOT_FOUND, 404);
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(errorResponse);
        }


        @ExceptionHandler(IllegalArgumentException.class)
        public ResponseEntity<errorResponse> IllegalArgumentException(IllegalArgumentException resourceNotFoundException) {
            errorResponse errorResponse = new errorResponse(resourceNotFoundException.getMessage(), HttpStatus.BAD_REQUEST, 400);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);
        }




}
