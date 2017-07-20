package com.oncase.security.filter.authentication;


import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.springframework.security.Authentication;
import org.springframework.security.GrantedAuthority;
import org.springframework.security.context.SecurityContext;
//import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.context.SecurityContextHolder;
import org.springframework.web.filter.GenericFilterBean;
import org.springframework.context.EnvironmentAware;

public class AuthenticationIPFilter extends GenericFilterBean {

	private HashMap<String, String[]> rules;

	public void doFilter( ServletRequest request,  ServletResponse response,
			FilterChain chain) throws IOException, ServletException {

		rules = new HashMap<String, String[]>();
		String key="Authenticated";
		String[] value = {"127.0.0.1"};
		rules.put(key, value);

		SecurityContext securityContext = SecurityContextHolder.getContext();
		Authentication existingAuth = securityContext.getAuthentication();
		
		// If there is an authentication
		if(existingAuth != null){
			
			// Client IP
			String remoteAddr = request.getRemoteAddr();

			// Does the current user belong to a certain group?
			boolean containsAdmin = hasAuthority(
					existingAuth.getAuthorities(), "Administrator");
			
			// Does the user IP attend to certain rules?
			boolean isIP = "0:0:0:0:0:0:0:1".equals(remoteAddr);
			
			// Debug logs
			log("Contains Admin?", containsAdmin + "");
			log("IP Correct?", isIP + "");

			// If rules attended, then logout
			if( containsAdmin && isIP ) SecurityContextHolder.clearContext();
			
		}
		
		// Continues the filter chain
		chain.doFilter(request, response);

	}
	
	private boolean hasAuthority (
			GrantedAuthority[] grantedAuthorities, 
			String authority ){
		
		if (grantedAuthorities == null || authority == null) return false;
		List<GrantedAuthority> grantedAuthoritiesList = Arrays.asList(grantedAuthorities);
		Iterator<? extends GrantedAuthority> it = grantedAuthoritiesList.iterator();
		
		while(it.hasNext()){
			if (authority.equals(it.next().toString())) return true;
		}
		
		return false;
	}

	private void log(String msg, String value){
		System.out.println("\n\n " + msg + " ----------------------------");
		System.out.println(value);
		System.out.println(" -------------------------------------------");
	}
}

