package com.developer.security.security;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
	
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.inMemoryAuthentication()
		.withUser("user").password("{noop}user").roles("USER")
		.and()
		.withUser("admin").password("{noop}admin").roles("ADMIN").authorities("ACCESS_TEST1", "ACCESS_TEST2")
		.and()
		.withUser("manager").password("{noop}manager").roles("MANAGER").authorities("ACCESS_TEST1")
		
		;
	}
	
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.authorizeRequests()
		.antMatchers("/").permitAll()
		.antMatchers("/blog/**").authenticated()
		.antMatchers("/admin/**").hasAuthority("ACCESS_TEST2")
		.antMatchers("/mng/**").hasAnyAuthority("ACCESS_TEST1", "ACCESS_TEST2")
		.antMatchers("/api/test2").hasAuthority("ACCESS_TEST2")
		.and()
		.httpBasic()
		;
	}

}
