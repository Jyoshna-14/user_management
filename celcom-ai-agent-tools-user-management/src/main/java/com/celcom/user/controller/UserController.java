package com.celcom.user.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.celcom.user.config.TokenProvider;
import com.celcom.user.entity.User;
import com.celcom.user.model.LoginUser;
import com.celcom.user.model.PasswordResetBo;
import com.celcom.user.model.UserBo;
import com.celcom.user.service.UserService;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/users")
public class UserController {

	@Autowired
	private AuthenticationManager authenticationManager;

	@Autowired
	private TokenProvider tokenProvider;

	@Autowired
	UserService userService;

	@GetMapping("/all")
	public ResponseEntity<?> getAllUsers(@RequestParam(required = false) String envName) {
		log.info("Getting all users details");
		try {
			return new ResponseEntity<>(userService.getAllUsers(), HttpStatus.OK);
		} catch (Exception e) {
			log.error("Error while getting all users: {}", e.getMessage());
			return new ResponseEntity<>("Error occurred while fetching users", HttpStatus.INTERNAL_SERVER_ERROR);
		}
	}

	@PostMapping("/create")
	public ResponseEntity<?> createUser(@RequestBody UserBo userBo, @RequestParam(required = false) String envName) {
		log.info("Creating new user with username: {}", userBo.getUserName());
		try {
			return new ResponseEntity<>(userService.createUser(userBo), HttpStatus.CREATED);
		} catch (Exception e) {
			log.error("Error while creating user: {}", e.getMessage());
			return new ResponseEntity<>("Error occurred while creating user", HttpStatus.INTERNAL_SERVER_ERROR);
		}
	}

	@PostMapping(value = "/authenticate")
	public String generateToken(@RequestBody LoginUser loginUser, @RequestParam(required = false) String envName)
			throws AuthenticationException {

		final Authentication authentication = authenticationManager.authenticate(
				new UsernamePasswordAuthenticationToken(loginUser.getUserName(), loginUser.getPassWord()));
		SecurityContextHolder.getContext().setAuthentication(authentication);
		return tokenProvider.generateToken(authentication);
	}
	
	@PutMapping("/update")
	public ResponseEntity<?> updateUser(@RequestBody UserBo userBo, @RequestParam(required = false) String envName) {
		log.info("Updating user details for username: {}", userBo.getUserName());
		try {
			return new ResponseEntity<>(userService.updateUser(userBo), HttpStatus.OK);
		} catch (Exception e) {
			log.error("Error while updating user: {}", e.getMessage());
			return new ResponseEntity<>("Error occurred while updating user", HttpStatus.INTERNAL_SERVER_ERROR);
		}
	}
	
	@PostMapping("/forgot-password")
	public ResponseEntity<?> forgotPassword(@RequestParam String userName, @RequestParam(required = false) String envName) {
		log.info("Initiating password reset for username: {}", userName);
		try {
			String otp = userService.initiatePasswordReset(userName);
			// In a real application, you would send the OTP to the user's email/phone
			return new ResponseEntity<>("Password reset OTP has been sent", HttpStatus.OK);
		} catch (Exception e) {
			log.error("Error while initiating password reset: {}", e.getMessage());
			return new ResponseEntity<>("Error occurred while initiating password reset", HttpStatus.INTERNAL_SERVER_ERROR);
		}
	}

	@PostMapping("/reset-password")
	public ResponseEntity<?> resetPassword(@RequestBody PasswordResetBo passwordResetBo, @RequestParam(required = false) String envName) {
		log.info("Resetting password for username: {}", passwordResetBo.getUserName());
		try {
			User updatedUser = userService.resetPassword(passwordResetBo);
			return new ResponseEntity<>("Password has been reset successfully", HttpStatus.OK);
		} catch (Exception e) {
			log.error("Error while resetting password: {}", e.getMessage());
			return new ResponseEntity<>("Error occurred while resetting password", HttpStatus.INTERNAL_SERVER_ERROR);
		}
	}

}
