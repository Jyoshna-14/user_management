package com.celcom.user.service;

import java.util.List;

import com.celcom.user.entity.User;
import com.celcom.user.model.PasswordResetBo;
import com.celcom.user.model.UserBo;

public interface UserService {

	User getUserDetails(String username);

	List<User> getAllUsers();

	String getUserRole(String userName);

	User createUser(UserBo userBo);
	
	User updateUser(UserBo userBo);
	
	String initiatePasswordReset(String userName);

	User resetPassword(PasswordResetBo passwordResetBo);

}