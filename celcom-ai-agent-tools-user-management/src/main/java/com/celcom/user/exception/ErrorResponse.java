package com.celcom.user.exception;

import java.time.LocalDateTime;

import org.springframework.http.HttpStatus;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.fasterxml.jackson.datatype.jsr310.ser.LocalDateTimeSerializer;

import lombok.Data;

@Data
public class ErrorResponse {

	private final int statusCode;

	private final HttpStatus httpStatus;

	private final String exceptionName;

	private final String description;

	@JsonSerialize(using = LocalDateTimeSerializer.class)
	@JsonFormat(pattern = "yyyy-MM-dd'T'HH:mm:ss.SSS")
	private final LocalDateTime timeStamp;

	public ErrorResponse(int statusCode, HttpStatus httpStatus, String exceptionName, String description) {
		this.statusCode = statusCode;
		this.httpStatus = httpStatus;
		this.exceptionName = exceptionName;
		this.description = description;
		this.timeStamp = LocalDateTime.now();
	}
}
