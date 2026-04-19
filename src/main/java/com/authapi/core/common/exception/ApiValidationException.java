package com.authapi.core.common.exception;

import java.util.Map;

public class ApiValidationException extends RuntimeException {

    private final Map<String, String> fieldErrors;

    public ApiValidationException(String message, Map<String, String> fieldErrors) {
        super(message);
        this.fieldErrors = fieldErrors == null ? Map.of() : Map.copyOf(fieldErrors);
    }

    public Map<String, String> getFieldErrors() {
        return fieldErrors;
    }
}
