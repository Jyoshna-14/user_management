package com.celcom.user.model;

import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class PasswordResetBo {
	private String userName;
	private String oldPassword;
	private String newPassword;
	private String confirmNewPassword;
}
