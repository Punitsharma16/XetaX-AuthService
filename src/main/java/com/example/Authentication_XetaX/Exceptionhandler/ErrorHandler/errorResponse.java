package com.example.Authentication_XetaX.Exceptionhandler.ErrorHandler;

import org.springframework.http.HttpStatus;

public record errorResponse(String message , HttpStatus status, int code) {
}
