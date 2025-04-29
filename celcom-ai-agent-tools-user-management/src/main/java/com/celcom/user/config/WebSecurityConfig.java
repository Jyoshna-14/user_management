package com.celcom.user.config;

import static org.springframework.security.config.Customizer.withDefaults;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import jakarta.annotation.Resource;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
public class WebSecurityConfig {

	@Resource(name = "userService")
	private UserDetailsService userDetailsService;

	@Autowired
	private UnauthorizedEntryPoint unauthorizedEntryPoint;

	@Bean
	public BCryptPasswordEncoder encoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		http.cors(
				withDefaults()).csrf(
						csrf -> csrf.disable())
				.authorizeHttpRequests(authorize -> authorize
						.requestMatchers(request -> request.getRequestURI().startsWith("/users/authenticate")
								|| request.getRequestURI().startsWith("/users/forgotPassword")
								|| request.getRequestURI().startsWith("/users/create")
								|| request.getRequestURI().startsWith("/users/otpValidate")
								|| request.getRequestURI().startsWith("/swagger-ui")
								|| request.getRequestURI().startsWith("/v3")
								|| request.getRequestURI().startsWith("/createNewPassword")
								|| request.getRequestURI().startsWith("/jobrun/report")
								|| request.getRequestURI().startsWith("/users/createNewPassword"))
						.permitAll().anyRequest().authenticated())
				.exceptionHandling(exception -> exception.authenticationEntryPoint(unauthorizedEntryPoint))
				.sessionManagement(management -> management.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
		http.addFilterBefore(authenticationTokenFilterBean(), UsernamePasswordAuthenticationFilter.class);

		return http.build();
	}

	@Bean
	public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration)
			throws Exception {
		return authenticationConfiguration.getAuthenticationManager();
	}

	@Bean
	public JwtAuthenticationFilter authenticationTokenFilterBean() throws Exception {
		return new JwtAuthenticationFilter();
	}

}
