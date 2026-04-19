package com.authapi.core.common.exception;

import java.time.Instant;
import java.util.Map;

import org.springframework.http.HttpStatus;

public record ApiErrorResponse(
    String code,
    String message,
    int status,
    Instant timestamp,
    String path,
    Map<String, String> fieldErrors
) {

    public ApiErrorResponse {
        fieldErrors = fieldErrors == null ? Map.of() : Map.copyOf(fieldErrors);
    }

    public static ApiErrorResponse of(HttpStatus status, String code, String message, String path) {
        return new ApiErrorResponse(code, message, status.value(), Instant.now(), path, Map.of());
    }

    public static ApiErrorResponse withFieldErrors(
        HttpStatus status,
        String code,
        String message,
        String path,
        Map<String, String> fieldErrors
    ) {
        return new ApiErrorResponse(code, message, status.value(), Instant.now(), path, fieldErrors);
    }
}
