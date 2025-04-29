package com.celcom.user.service;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.util.ObjectUtils;

import com.celcom.user.entity.User;
import com.celcom.user.exception.InvalidUserIdException;
import com.celcom.user.exception.UserAlreadyExistException;
import com.celcom.user.exception.UserNotFoundException;
import com.celcom.user.model.PasswordResetBo;
import com.celcom.user.model.UserBo;
import com.celcom.user.repository.UserRepository;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service(value = "userService")
public class UserServiceImpl implements UserDetailsService, UserService {

	@Autowired
	UserRepository userRepository;

	@Autowired
	HttpServletRequest req;

	private final String alphaNumeric = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvxyz";

	private final String otpNumeric = "1234567890";

	public User getUserDetails(String userName) {

		User user = this.userRepository.findByUserName(userName);
		if (user != null) {
			return user;
		} else {
			throw new UserNotFoundException("No data available with this userId: " + userName, "UserServiceImpl",
					"getUserDetails");
		}
	}

	private String generatePassword(int passwordLength) {
		StringBuilder password = new StringBuilder(passwordLength);
		for (int i = 0; i < passwordLength; i++) {
			int index = (int) (alphaNumeric.length() * Math.random());
			password.append(alphaNumeric.charAt(index));
		}
		return password.toString();
	}

	private String generateOtp(int passwordLength) {
		StringBuilder otp = new StringBuilder(passwordLength);
		for (int i = 0; i < passwordLength; i++) {
			int index = (int) (otpNumeric.length() * Math.random());
			otp.append(otpNumeric.charAt(index));
		}
		return otp.toString();
	}

	public UserDetails loadUserByUsername(String username) {
		User user = this.userRepository.findByUserName(username);
		if (user == null) {
			throw new UserNotFoundException("No data available with this userName: " + username, "UserServiceImpl",
					"loadUserByUsername");
		}
		return new org.springframework.security.core.userdetails.User(user.getUserName(), user.getPassWord(),
				getAuthority(user));
	}

	private Set<SimpleGrantedAuthority> getAuthority(User user) {
		Set<SimpleGrantedAuthority> authorities = new HashSet<>();
		String[] roles = user.getRoles().split(",");
		for (String role : roles) {
			authorities.add(new SimpleGrantedAuthority("ROLE_" + role));
		}
		return authorities;
	}

	@Override
	public List<User> getAllUsers() {
		return this.userRepository.findAll();
	}

	@Override
	public String getUserRole(String userName) {
		return String.valueOf(req.getAttribute("userRole"));
	}

	public User createUser(UserBo userBo) {
		if (userBo.getUserName() == null || userBo.getUserName().trim().isEmpty()) {
			throw new InvalidUserIdException("Username cannot be null or empty", "UserServiceImpl", "createUser");
		}

		User existingUser = this.userRepository.findByUserName(userBo.getUserName());
		if (existingUser != null) {
			throw new UserAlreadyExistException("User already exists with username: " + userBo.getUserName(),
					"UserServiceImpl", "createUser");
		}

		User newUser = new User();
//		newUser.setId(1L); // This should be handled by the database auto-increment
		newUser.setUserName(userBo.getUserName());
		
		// Validate and set password
		if (userBo.getPassWord() == null || userBo.getPassWord().trim().isEmpty()) {
			throw new InvalidUserIdException("Password cannot be null or empty", "UserServiceImpl", "createUser");
		}
		newUser.setPassWord(new BCryptPasswordEncoder().encode(userBo.getPassWord()));
		
		// Set roles with validation
		if (userBo.getRoles() == null || userBo.getRoles().trim().isEmpty()) {
			throw new InvalidUserIdException("Roles cannot be null or empty", "UserServiceImpl", "createUser");
		}
		newUser.setRoles(userBo.getRoles());
		
		// Set optional fields
		newUser.setFirstName(userBo.getFirstName());
		newUser.setLastName(userBo.getLastName());
		newUser.setStatus(userBo.isStatus());
		newUser.setNewUser(true);

		return this.userRepository.save(newUser);
	}
	
	public User updateUser(UserBo userBo) {
		if (userBo.getUserName() != null) {
			User existingUser = this.userRepository.findByUserName(userBo.getUserName());
			if (existingUser != null) {
				// Update only the fields that are provided in the request
				if (userBo.getFirstName() != null) {
					existingUser.setFirstName(userBo.getFirstName());
				}
				if (userBo.getLastName() != null) {
					existingUser.setLastName(userBo.getLastName());
				}
				if (userBo.getRoles() != null) {
					existingUser.setRoles(userBo.getRoles());
				}
				if (userBo.getPassWord() != null) {
					existingUser.setPassWord(new BCryptPasswordEncoder().encode(userBo.getPassWord()));
				}
				existingUser.setStatus(userBo.isStatus());
				existingUser.setNewUser(userBo.isNewUser());

				return this.userRepository.save(existingUser);
			} else {
				throw new UserNotFoundException("User not found with username: " + userBo.getUserName(), 
					"UserServiceImpl", "updateUser");
			}
		} else {
			throw new InvalidUserIdException("Username cannot be null", "UserServiceImpl", "updateUser");
		}
	}
	
	@Override
	public String initiatePasswordReset(String userName) {
		if (userName == null || userName.trim().isEmpty()) {
			throw new InvalidUserIdException("Username cannot be null or empty", "UserServiceImpl", "initiatePasswordReset");
		}

		User user = this.userRepository.findByUserName(userName);
		if (user == null) {
			throw new UserNotFoundException("User not found with username: " + userName, 
				"UserServiceImpl", "initiatePasswordReset");
		}

		// Generate OTP for password reset
		String otp = generateOtp(6);
		// In a real application, you would:
		// 1. Store this OTP in the database with an expiration time
		// 2. Send it to the user's email/phone
		// For this example, we'll just return the OTP
		return otp;
	}

	@Override
	public User resetPassword(PasswordResetBo passwordResetBo) {
		if (passwordResetBo.getUserName() == null || passwordResetBo.getUserName().trim().isEmpty()) {
			throw new InvalidUserIdException("Username cannot be null or empty", "UserServiceImpl", "resetPassword");
		}

		if (passwordResetBo.getNewPassword() == null || passwordResetBo.getNewPassword().trim().isEmpty()) {
			throw new InvalidUserIdException("New password cannot be null or empty", "UserServiceImpl", "resetPassword");
		}

		if (!passwordResetBo.getNewPassword().equals(passwordResetBo.getConfirmNewPassword())) {
			throw new InvalidUserIdException("New password and confirm password do not match", 
				"UserServiceImpl", "resetPassword");
		}

		User user = this.userRepository.findByUserName(passwordResetBo.getUserName());
		if (user == null) {
			throw new UserNotFoundException("User not found with username: " + passwordResetBo.getUserName(), 
				"UserServiceImpl", "resetPassword");
		}

		// In a real application, you would:
		// 1. Validate the OTP here
		// 2. Check if the OTP has expired
		// 3. Clear the OTP after successful reset

		// Update the password
		user.setPassWord(new BCryptPasswordEncoder().encode(passwordResetBo.getNewPassword()));
		user.setNewUser(false);

		return this.userRepository.save(user);
	}
}
