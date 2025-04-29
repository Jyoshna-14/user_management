package com.celcom.user.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
@Entity
@Table(name = "User", schema = "chatbot")
public class User {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "id")
	private Long id;

	@Column(name = "userName")
	private String userName;

	@Column(name = "passWord")
	private String passWord;

	@Column(name = "roles")
	private String roles;

	@Column(name = "status")
	private boolean status;

	@Column(name = "newUser")
	private boolean newUser;

	@Column(name = "firstName")
	private String firstName;

	@Column(name = "lastName")
	private String lastName;

}
