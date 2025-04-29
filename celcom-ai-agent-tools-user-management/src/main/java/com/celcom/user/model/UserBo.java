package com.celcom.user.model;

import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class UserBo {
	private String userName;
	private String passWord;
	private String roles;
	private boolean status;
	private boolean newUser;
	private String firstName;
	private String lastName;
	private String baseUrl;

}