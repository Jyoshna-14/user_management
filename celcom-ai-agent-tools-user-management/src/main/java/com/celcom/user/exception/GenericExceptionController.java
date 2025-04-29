package com.celcom.user.exception;

import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@ControllerAdvice
public class GenericExceptionController {

	@ResponseStatus(value = HttpStatus.BAD_REQUEST)
	@ExceptionHandler(UserAlreadyExistException.class)
	@ResponseBody
	public ErrorResponse userAlreadyExistException(UserAlreadyExistException ex) {
		log.error("httpStatus: " + HttpStatus.BAD_REQUEST + ", exceptionName: UserAlreadyExistException, description: "
				+ ex.getDescription() + ", javaClassName: " + ex.getClassName() + ", methodName: "
				+ ex.getMethodName());
		return new ErrorResponse(400, HttpStatus.BAD_REQUEST, "UserAlreadyExistException", ex.getDescription());
	}

	@ResponseStatus(value = HttpStatus.BAD_REQUEST)
	@ExceptionHandler(InvalidUserIdException.class)
	@ResponseBody
	public ErrorResponse invalidUserIdException(InvalidUserIdException ex) {
		log.error("httpStatus: " + HttpStatus.BAD_REQUEST + ", exceptionName: InvalidUserIdException, description: "
				+ ex.getDescription() + ", javaClassName: " + ex.getClassName() + ", methodName: "
				+ ex.getMethodName());
		return new ErrorResponse(400, HttpStatus.BAD_REQUEST, "InvalidUserIdException", ex.getDescription());
	}

	@ResponseStatus(value = HttpStatus.BAD_REQUEST)
	@ExceptionHandler(UserNotFoundException.class)
	@ResponseBody
	public ErrorResponse userNotFoundException(UserNotFoundException ex) {
		log.error("httpStatus: " + HttpStatus.BAD_REQUEST + ", exceptionName: InvalidUserIdException, description: "
				+ ex.getDescription() + ", javaClassName: " + ex.getClassName() + ", methodName: "
				+ ex.getMethodName());
		return new ErrorResponse(400, HttpStatus.BAD_REQUEST, "UserNotFoundException", ex.getDescription());
	}

	@ResponseStatus(value = HttpStatus.BAD_REQUEST)
	@ExceptionHandler(WrongPasswordException.class)
	@ResponseBody
	public ErrorResponse wrongPasswordException(WrongPasswordException ex) {
		log.error("httpStatus: " + HttpStatus.BAD_REQUEST + ", exceptionName: WrongPasswordException, description: "
				+ ex.getDescription() + ", javaClassName: " + ex.getClassName() + ", methodName: "
				+ ex.getMethodName());
		return new ErrorResponse(400, HttpStatus.BAD_REQUEST, "WrongPasswordException", ex.getDescription());
	}

	@ResponseStatus(value = HttpStatus.BAD_REQUEST)
	@ExceptionHandler(UserDisabledException.class)
	@ResponseBody
	public ErrorResponse userDisabledException(UserDisabledException ex) {
		log.error("httpStatus: " + HttpStatus.BAD_REQUEST + ", exceptionName: UserDisabledException, description: "
				+ ex.getDescription() + ", javaClassName: " + ex.getClassName() + ", methodName: "
				+ ex.getMethodName());
		return new ErrorResponse(400, HttpStatus.BAD_REQUEST, "UserDisabledException", ex.getDescription());
	}

	@ResponseStatus(value = HttpStatus.BAD_REQUEST)
	@ExceptionHandler(OtpExpiredException.class)
	@ResponseBody
	public ErrorResponse otpExpiredException(OtpExpiredException ex) {
		log.error("httpStatus: " + HttpStatus.BAD_REQUEST + ", exceptionName: OtpExpiredException, description: "
				+ ex.getDescription() + ", javaClassName: " + ex.getClassName() + ", methodName: "
				+ ex.getMethodName());
		return new ErrorResponse(400, HttpStatus.BAD_REQUEST, "OtpExpiredException", ex.getDescription());
	}

	@ResponseStatus(value = HttpStatus.BAD_REQUEST)
	@ExceptionHandler(InvalidOtpException.class)
	@ResponseBody
	public ErrorResponse invalidOtpException(InvalidOtpException ex) {
		log.error("httpStatus: " + HttpStatus.BAD_REQUEST + ", exceptionName: InvalidOtpException, description: "
				+ ex.getDescription() + ", javaClassName: " + ex.getClassName() + ", methodName: "
				+ ex.getMethodName());
		return new ErrorResponse(400, HttpStatus.BAD_REQUEST, "InvalidOtpException", ex.getDescription());
	}

	@ResponseStatus(value = HttpStatus.NOT_FOUND)
	@ExceptionHandler(NoDataAvailableException.class)
	@ResponseBody
	public ErrorResponse noDataAvailableException(NoDataAvailableException ex) {
		log.error("httpStatus: " + HttpStatus.NOT_FOUND + ", exceptionName: NoDataAvailableException, description: "
				+ ex.getDescription() + ", javaClassName: " + ex.getClassName() + ", methodName: "
				+ ex.getMethodName());
		return new ErrorResponse(404, HttpStatus.NOT_FOUND, "NoDataAvailableException", ex.getDescription());
	}

	@ResponseStatus(value = HttpStatus.INTERNAL_SERVER_ERROR)
	@ExceptionHandler(CacheUpdateFailedException.class)
	@ResponseBody
	public ErrorResponse cacheUpdateFailedException(CacheUpdateFailedException ex) {
		log.error("httpStatus: " + HttpStatus.INTERNAL_SERVER_ERROR
				+ ", exceptionName: CacheUpdateFailedException, description: " + ex.getDescription()
				+ ", javaClassName: " + ex.getClassName() + ", methodName: " + ex.getMethodName());
		return new ErrorResponse(500, HttpStatus.INTERNAL_SERVER_ERROR, "CacheUpdateFailedException",
				ex.getDescription());
	}

	@ResponseStatus(value = HttpStatus.INTERNAL_SERVER_ERROR)
	@ExceptionHandler(RuntimeException.class)
	@ResponseBody
	public ErrorResponse technicalException(RuntimeException ex) {
		if (ex instanceof AccessDeniedException) {
			return new ErrorResponse(403, HttpStatus.FORBIDDEN, ex.getClass().toString(), ex.getMessage());
		}

		if (ex instanceof BadCredentialsException) {
			return new ErrorResponse(401, HttpStatus.UNAUTHORIZED, ex.getClass().toString(), ex.getMessage());
		}
		log.error("httpStatus: " + HttpStatus.INTERNAL_SERVER_ERROR + ", exceptionName: " + ex.getClass().toString()
				+ ", description: " + ex.getMessage());
		ex.printStackTrace();
		return new ErrorResponse(500, HttpStatus.INTERNAL_SERVER_ERROR, ex.getClass().toString(), ex.getMessage());
	}

}
