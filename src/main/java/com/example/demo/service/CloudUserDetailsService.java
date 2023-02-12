package com.example.demo.service;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import com.example.demo.dao.CloudUserRepository;
import com.example.demo.model.CloudUser;

@Service("userDetailsService")
public class CloudUserDetailsService implements UserDetailsService {
	//2222 1:45-------------------------------------------------------------
	@Autowired
	private CloudUserRepository cloudUserRepository;

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		Optional<CloudUser> optCloudUser = cloudUserRepository.findByUsername(username);
		// 若無此帳號就拋出例外
		optCloudUser.orElseThrow(() -> new UsernameNotFoundException("Username  not found!"));
		
		CloudUser cloudUser = optCloudUser.get();
		List<GrantedAuthority> auths = Arrays.stream(cloudUser.getRoles().split(","))
				.map(SimpleGrantedAuthority::new)
				//.map(role -> new SimpleGrantedAuthority(role))
				.collect(Collectors.toList());
		//建構子參數: username, password, enabled, accountNonExpired, credentialsNonExpired(證書), accountNonLocked, authorities
				UserDetails userDetails = new User(cloudUser.getUsername(), cloudUser.getPassword(), 
												   true, true, true, cloudUser.isActive(), auths);
		return userDetails;
	}
    
	
	/*2222 0:59
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		// 假設資料庫的 name / pwd 如下
		String name = "john";
		String pwd  = new BCryptPasswordEncoder().encode("1234");
						
		  if(!username.equals(name)) {
			System.out.println("Usename not found");
			throw new UsernameNotFoundException("Usename nnot found");
			}
						
		// 建立 UserDetials
		List<GrantedAuthority> auths = AuthorityUtils.commaSeparatedStringToAuthorityList("ROLE_ADMIN,ROLE_USER");
		//建構子參數: username, password, authorities
		UserDetails userDetails = new User(username, pwd, auths);
		//2222 1:21
		//建構子參數: username, password,**3 enabled,           -----------email驗證後 帳號才會啟動
		                            //**4 accountNonExpired, -----------帳號有沒有過期
		                            //**5 credentialsNonExpired(證書),---證書有沒有過期
		                            //**6 accountNonLocked,-------------帳號有沒有被鎖定
		                            //*7  authorities
		//UserDetails userDetails = new User(username, pwd, true, true, true, false, auths);
		return userDetails;
	}*/

}
