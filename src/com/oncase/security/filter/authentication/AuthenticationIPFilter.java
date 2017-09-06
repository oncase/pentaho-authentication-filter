package com.oncase.security.filter.authentication;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
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
import org.springframework.security.context.SecurityContextHolder;
import org.springframework.web.filter.GenericFilterBean;

public class AuthenticationIPFilter extends GenericFilterBean {

	private HashMap<String, ArrayList<String>> rules;
	private String adminRole;
	private boolean debug;

	public void doFilter( ServletRequest request,  ServletResponse response,
			FilterChain chain) throws IOException, ServletException {

		SecurityContext securityContext = SecurityContextHolder.getContext();
		Authentication existingAuth = securityContext.getAuthentication();
		System.out.println("1. Entering Filter");
		
		// //TODO: inspect existingAuth to determine a better entry point to this if
		
		// If there is an authentication
		if(existingAuth != null){
			System.out.println("2. No AUTH");
			// Client IP
			String remoteAddr = request.getRemoteAddr();

			// Does the current user belong to a certain group?
			boolean canAccess = hasAuthority(existingAuth.getAuthorities(), remoteAddr);
		
			// If rules attended, then logout
			if( !canAccess ) {
				System.out.println("3. Can't Access");
				SecurityContextHolder.clearContext();
			}else{
				System.out.println("3. CAN ACCESS");
			}
		}
		
		// Continues the filter chain
		chain.doFilter(request, response);
	}
	
	private boolean hasAuthority (GrantedAuthority[] grantedAuthorities, String remoteAddr){
		
		List<GrantedAuthority> grantedAuthoritiesList = Arrays.asList(grantedAuthorities);
		
		Iterator<? extends GrantedAuthority> it = grantedAuthoritiesList.iterator();
		
		ArrayList<String> ips = new ArrayList<String>();

		while(it.hasNext()){
			
			String role = it.next().toString();
			
			// Short circuit case admin
			if( role.equals(adminRole) ){
				if(debug) log("Short Circuit 01: ADMIN", role);
				return true;
			}

			// Build list with ips that matches roles
			ArrayList<String> currentIPs = rules.get(role);

			if(currentIPs != null){
				ips.addAll(currentIPs);
			}

		}
				
		// Checks IPs
		Iterator<String> itIPs = ips.iterator();
		while(itIPs.hasNext()){
			String ip = itIPs.next();
			if(ip.equals(remoteAddr)){
				if(debug) log("IP Matches", remoteAddr + " - " + ip);
				return true;
			} else if (ip.equals("NOTHING")){
				if(debug) log("Short Circuit 02: no rules", ips + " ");
				return true;
			}
		}

		if(debug) {
			log("Returning FALSE - ROLES:", Arrays.toString(grantedAuthorities));
			log("Returning FALSE - RULES: ", rules.toString());
			log("Returning FALSE - IP: ", remoteAddr);	
		}
		
		return false;
}
	private void log(String msg, String value){
		System.out.println("\n\n " + msg + " ----------------------------");
		System.out.println(value);
		System.out.println(" -------------------------------------------");
	}

	public HashMap<String, ArrayList<String>> getRules() {
		return rules;
	}

	public void setRules(HashMap<String, ArrayList<String>> rules) {
		this.rules = rules;
	}

	public String getAdminRole() {
		return adminRole;
	}

	public void setAdminRole(String adminRole) {
		this.adminRole = adminRole;
	}

	public boolean isDebug() {
		return debug;
	}

	public void setDebug(boolean debug) {
		this.debug = debug;
	}
}

