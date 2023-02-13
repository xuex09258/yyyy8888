package com.example.demo.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import com.example.demo.filter.PathAndJwtCheckFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
	//2222 1:09
	@Autowired
	private UserDetailsService userDetailsService;
	
	// 配置身份驗證時一定要做的 1111 2:11
	@Bean
	PasswordEncoder password() {
		return new BCryptPasswordEncoder(); // 2222 00:54將密碼進行加密(每次加密資料並不會相同) 強度可以輸入 4~31
	}
	// 配置身份驗證 1111 2:11
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		//2222 0:43 加 log
		System.out.println("配置身份驗證configure(AuthenticationManagerBuilder auth)");
		//--------------------------------------------------------------------
		/*
		BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
		String password = passwordEncoder.encode("1234");
		auth.inMemoryAuthentication()
			.withUser("john")
			.password(password)
			//.roles("ADMIN");
		    .roles("ADMIN", "USER");//2222 00:14
		auth.inMemoryAuthentication()//2222 00:14
			.withUser("mary")
			.password(password)
			.roles("USER");
		*/
		//2222 1:09-------------------------------------------------------------
		auth.userDetailsService(userDetailsService).passwordEncoder(password());
	}

	// 配置 HTTP 安全性
		@Override
		protected void configure(HttpSecurity http) throws Exception {
			System.out.println("配置 HTTP 安全性configure(HttpSecurity http)");
			//------------------------------------------------------------
			http.authorizeHttpRequests() // 授權請求
				// 設定放行名單2222 0:17
			//.antMatchers("/admin").hasRole("ADMIN")  //只有限制 admin 葉面 只有ADMIN角色 能進來
			//.antMatchers("/user").hasRole("USER")    //只有限制 user  葉面
			//.antMatchers("/user").hasAnyRole("USER", "ADMIN") //hasAnyRole("USER", "ADMIN") 有兩個腳色時
			//.anyRequest().permitAll() //-------------- 其他請求皆開放
			//.and().formLogin(); // 利用表單來登入
	//---------------------------------------------------------
//			    //2222 30分 
//				//.antMatchers(HttpMethod.GET, "/admin").hasAuthority("ROLE_ADMIN") // ADMIN -> ROLE_ADMIN
	//----------------------------------------------------------------
			//2222 00:32 css images js  下面要 配置網路安全 2222 00:32
			//.antMatchers("/admin").hasRole("ADMIN")
			//.antMatchers("/user").hasAnyRole("USER", "ADMIN")
			//.anyRequest().authenticated() // *********所有請求都要驗證
			//.and().formLogin(); // 利用表單來登入
	//*******************************************************************************
			//2222 02:45 /jwt 在 controller
			
			    .antMatchers("/admin").hasRole("ADMIN")
				.antMatchers("/user").hasAnyRole("USER", "ADMIN")
				.antMatchers("/jwt").authenticated()
				.anyRequest().permitAll() // 其他請求皆開放
			    .and().formLogin(); // 利用表單來登入
	//-------------------------------------------------------------
		//初3的5 配置身份驗證1111 2:11 時 *所有請求都要驗證
			//.anyRequest().authenticated() // *********所有請求都要驗證
			//.and().formLogin(); // 利用表單來登入
			
			http.rememberMe() // 不會因為瀏覽器關閉而消失登入狀態
				.tokenValiditySeconds(30)
				.key("mykey");
			
			// 加入過濾器 2222 3:27ˋˋˋˋˋˋˋˋˋˋˋˋˋˋˋˋˋˋˋˋˋˋˋˋˋˋˋˋˋˋˋˋˋˋˋˋˋˋˋˋˋˋˋˋˋˋˋˋˋˋˋˋˋˋˋˋˋˋˋˋˋˋˋˋ
			http.addFilterBefore(new PathAndJwtCheckFilter(), BasicAuthenticationFilter.class);
		}
		// 配置網路安全 2222 00:32
		@Override
		public void configure(WebSecurity web) throws Exception {
			
			System.out.println("配置網路安全configure(WebSecurity web)");
			// 不需要驗證的路徑-----------------------------------------------
			web.ignoring().antMatchers("/css/**", "/images/**", "/js/**");
		}

}
