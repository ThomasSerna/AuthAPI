package com.authapi.core.common.exception;

import java.util.LinkedHashMap;
import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.ConstraintViolationException;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.validation.BindException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(ApiException.class)
    public ResponseEntity<ApiErrorResponse> handleApiException(ApiException exception, HttpServletRequest request) {
        ApiErrorResponse response = ApiErrorResponse.of(
            exception.getStatus(),
            exception.getCode(),
            exception.getMessage(),
            request.getRequestURI()
        );
        return ResponseEntity.status(exception.getStatus()).body(response);
    }

    @ExceptionHandler(ApiValidationException.class)
    public ResponseEntity<ApiErrorResponse> handleApiValidationException(
        ApiValidationException exception,
        HttpServletRequest request
    ) {
        ApiErrorResponse response = ApiErrorResponse.withFieldErrors(
            HttpStatus.BAD_REQUEST,
            "VALIDATION_ERROR",
            exception.getMessage(),
            request.getRequestURI(),
            exception.getFieldErrors()
        );
        return ResponseEntity.badRequest().body(response);
    }

    @ExceptionHandler({MethodArgumentNotValidException.class, BindException.class})
    public ResponseEntity<ApiErrorResponse> handleValidationException(Exception exception, HttpServletRequest request) {
        Map<String, String> fieldErrors = new LinkedHashMap<>();
        if (exception instanceof MethodArgumentNotValidException methodArgumentNotValidException) {
            for (FieldError fieldError : methodArgumentNotValidException.getBindingResult().getFieldErrors()) {
                fieldErrors.putIfAbsent(fieldError.getField(), fieldError.getDefaultMessage());
            }
        } else if (exception instanceof BindException bindException) {
            for (FieldError fieldError : bindException.getBindingResult().getFieldErrors()) {
                fieldErrors.putIfAbsent(fieldError.getField(), fieldError.getDefaultMessage());
            }
        }
        ApiErrorResponse response = ApiErrorResponse.withFieldErrors(
            HttpStatus.BAD_REQUEST,
            "VALIDATION_ERROR",
            "Request validation failed.",
            request.getRequestURI(),
            fieldErrors
        );
        return ResponseEntity.badRequest().body(response);
    }

    @ExceptionHandler(ConstraintViolationException.class)
    public ResponseEntity<ApiErrorResponse> handleConstraintViolation(
        ConstraintViolationException exception,
        HttpServletRequest request
    ) {
        Map<String, String> fieldErrors = new LinkedHashMap<>();
        exception.getConstraintViolations().forEach(violation -> fieldErrors.putIfAbsent(
            violation.getPropertyPath().toString(),
            violation.getMessage()
        ));
        ApiErrorResponse response = ApiErrorResponse.withFieldErrors(
            HttpStatus.BAD_REQUEST,
            "VALIDATION_ERROR",
            "Request validation failed.",
            request.getRequestURI(),
            fieldErrors
        );
        return ResponseEntity.badRequest().body(response);
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ApiErrorResponse> handleUnreadableBody(
        HttpMessageNotReadableException exception,
        HttpServletRequest request
    ) {
        ApiErrorResponse response = ApiErrorResponse.of(
            HttpStatus.BAD_REQUEST,
            "MALFORMED_REQUEST",
            "Request body is malformed or missing required fields.",
            request.getRequestURI()
        );
        return ResponseEntity.badRequest().body(response);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiErrorResponse> handleUnexpectedException(Exception exception, HttpServletRequest request) {
        ApiErrorResponse response = ApiErrorResponse.of(
            HttpStatus.INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "An unexpected error occurred.",
            request.getRequestURI()
        );
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
    }
}
