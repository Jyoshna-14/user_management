package com.celcom.user.exception;

import lombok.Getter;

@Getter
public class WrongPasswordException extends RuntimeException {

	private static final long serialVersionUID = 1L;

	private final String description;

	private final String className;

	private final String methodName;

	public WrongPasswordException(String description, String className, String methodName) {
		super();
		this.description = description;
		this.className = className;
		this.methodName = methodName;
	}
}