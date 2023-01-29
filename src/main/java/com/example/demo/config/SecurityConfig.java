package com.example.demo.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
	
	// 配置身份驗證時一定要做的 1111 2:11
	@Bean
	PasswordEncoder password() {
		return new BCryptPasswordEncoder(); // 將密碼進行加密(每次加密資料並不會相同) 強度可以輸入 4~31
	}
	// 配置身份驗證 1111 2:11
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
		String password = passwordEncoder.encode("1234");
		auth.inMemoryAuthentication()
			.withUser("john")
			.password(password)
			.roles("ADMIN");
	}

	@Override
	public void configure(WebSecurity web) throws Exception {
		// TODO Auto-generated method stub
		super.configure(web);
	}

	// 配置 HTTP 安全性
		@Override
		protected void configure(HttpSecurity http) throws Exception {
			//System.out.println("configure(HttpSecurity http)");
			http.authorizeHttpRequests() // 授權請求
				// 設定放行名單
//				//.antMatchers(HttpMethod.GET, "/admin").hasAuthority("ROLE_ADMIN") // ADMIN -> ROLE_ADMIN
//				.antMatchers("/admin").hasRole("ADMIN")
//				.antMatchers("/user").hasAnyRole("USER", "ADMIN")
//				.antMatchers("/jwt").authenticated()
//				.anyRequest().permitAll() // 其他請求皆開放
				.anyRequest().authenticated() // 所有請求都要驗證
				.and().formLogin(); // 利用表單來登入
			
			http.rememberMe() // 不會因為瀏覽器關閉而消失登入狀態
				.tokenValiditySeconds(30)
				.key("mykey");
			
			
		}

}
