package com.celcom.user.config;

import java.io.IOException;
import java.io.Serializable;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import com.celcom.user.exception.ErrorResponse;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class UnauthorizedEntryPoint implements AuthenticationEntryPoint, Serializable {

	private static final long serialVersionUID = 1L;

	@Override
	public void commence(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException authException) throws IOException {

		if (response.getHeader("exceptionName") == null) {
			ErrorResponse errorResponse = new ErrorResponse(HttpStatus.UNAUTHORIZED.value(), HttpStatus.UNAUTHORIZED,
					"InvalidAuthenticationHeaderException", "Invalid JWT Token");
			response.setStatus(HttpStatus.UNAUTHORIZED.value());
			response.setContentType("application/json");
			response.getWriter().write(convertObjectToJson(errorResponse));
		}

		else if (response.getHeader("exceptionName").equals("ExpiredJwtTokenException")) {

			ErrorResponse errorResponse = new ErrorResponse(HttpStatus.UNAUTHORIZED.value(), HttpStatus.UNAUTHORIZED,
					"ExpiredJwtTokenException", "Token Expired");
			response.setStatus(HttpStatus.UNAUTHORIZED.value());
			response.setContentType("application/json");
			response.getWriter().write(convertObjectToJson(errorResponse));
		}

		else if (response.getHeader("exceptionName").equals("BadCredentialsException")) {

			ErrorResponse errorResponse = new ErrorResponse(HttpStatus.UNAUTHORIZED.value(), HttpStatus.UNAUTHORIZED,
					"BadCredentialsException", "Authentication Failed. UserName or PassWord is incorrect");
			response.setStatus(HttpStatus.UNAUTHORIZED.value());
			response.setContentType("application/json");
			response.getWriter().write(convertObjectToJson(errorResponse));
		}

		else if (response.getHeader("exceptionName").equals("InvalidAuthenticationHeaderException")) {

			ErrorResponse errorResponse = new ErrorResponse(HttpStatus.UNAUTHORIZED.value(), HttpStatus.UNAUTHORIZED,
					"InvalidAuthenticationHeaderException", "Invalid Authentication Header or incorrect prefix");
			response.setStatus(HttpStatus.UNAUTHORIZED.value());
			response.setContentType("application/json");
			response.getWriter().write(convertObjectToJson(errorResponse));
		}

		else if (response.getHeader("exceptionName").equals("TechnicalException")) {

			ErrorResponse errorResponse = new ErrorResponse(HttpStatus.INTERNAL_SERVER_ERROR.value(),
					HttpStatus.INTERNAL_SERVER_ERROR, "TechnicalException",
					"An error occurred while fetching Username from Token");
			response.setStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
			response.setContentType("application/json");
			response.getWriter().write(convertObjectToJson(errorResponse));
		}

	}

	public String convertObjectToJson(Object object) throws JsonProcessingException {
		if (object == null) {
			return null;
		}
		ObjectMapper mapper = new ObjectMapper();
		return mapper.writeValueAsString(object);
	}

}
