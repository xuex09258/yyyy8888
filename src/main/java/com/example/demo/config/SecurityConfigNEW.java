package com.example.demo.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

//@Configuration
//@EnableWebSecurity
public class SecurityConfigNEW extends WebSecurityConfigurerAdapter {
	
	@Bean
	PasswordEncoder password() {
		return new BCryptPasswordEncoder(); 
		}
	
	@Bean
	public UserDetailsService userDetailsService() {
		
		UserDetails user = 
				User.withDefaultPasswordEncoder()
					.username("john")
			        .password("1234")
			        .roles("admin")
			        .build();
		return new InMemoryUserDetailsManager(user);
	}

	// 配置 HTTP 安全性
	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			
			http.authorizeHttpRequests() // 授權請求
				.anyRequest().authenticated() // 所有請求都要驗證
				.and().formLogin(); // 利用表單來登入
			
			http.rememberMe() // 不會因為瀏覽器關閉而消失登入狀態
				.tokenValiditySeconds(30)
				.key("mykey");
			
			return http.build();			
		}

}
