package com.xetax.auth_xetax.Exceptionhandler.ErrorHandler;

import org.springframework.http.HttpStatus;

public record errorResponse(String message , HttpStatus status, int code) {
}
