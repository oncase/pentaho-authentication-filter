package com.oncase.security.filter.authentication;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.swing.JOptionPane;

import org.springframework.security.Authentication;
import org.springframework.security.GrantedAuthority;
import org.springframework.security.context.SecurityContext;
import org.springframework.security.context.SecurityContextHolder;
import org.springframework.web.filter.GenericFilterBean;
import org.springframework.context.EnvironmentAware;

public class AuthenticationIPFilter extends GenericFilterBean {

	private HashMap<String, String[]> rules;
	
	public void doFilter( ServletRequest request,  ServletResponse response,
			FilterChain chain) throws IOException, ServletException {

		SecurityContext securityContext = SecurityContextHolder.getContext();
		Authentication existingAuth = securityContext.getAuthentication();
	
		// If there is an authentication
		if(existingAuth != null){
			
			// Client IP
			String remoteAddr = request.getRemoteAddr();

			// Does the current user belong to a certain group?
			boolean containsAdmin = hasAuthority(existingAuth.getAuthorities(), remoteAddr);
			
			// Debug logs
			log("Contains Admin?", containsAdmin + "");
		
			// If rules attended, then logout
			if( containsAdmin ) {
			} else {
				  response.setContentType("text/html");
	              PrintWriter out = response.getWriter();
	              out.println("<html>");
	              out.println("<meta charset=\"UTF-8\">");
	              out.println("<head>");
	              out.println("<title>Acesso Negado</title>");
	              out.println("<title>Acesso Negado</title>");
	              out.println("<link rel=\"stylesheet\" type=\"text/css\" href=\"/pentaho/content/common-ui/resources/themes/crystal/globalCrystal.css\" />");
	              out.println("</head>");
	              out.println("<body class=\"pentaho-page-background\" >");
	              out.println("<div class=\"warning\" style=\"margin: 10px auto;\">");
	              out.println("<div style=\"padding:0px 0px 0px 50px\">");
	              out.println("<div class=\"warning-header \">Desculpa. Realmente tentamos.</div>");
	              out.println("<div>Seu IP nao tem permissao para acessar!</div>");
	              out.println("<div> Contacte seu administrador .</div>");
	              out.println("</div>");
	              out.println("</div>");
	              out.println("</body>");
	              out.println("</html>");
//				SecurityContextHolder.clearContext();
			}
		}
		// Continues the filter chain
		chain.doFilter(request, response);
	}
	
	private boolean hasAuthority (GrantedAuthority[] grantedAuthorities, String remoteAddr){
		
		rules = new HashMap<String, String[]>();

		// configure sua lista de acesso
		String key01 = "Seguradora";
		String key02 = "Administrator";
		String[] value01 = {"192.123.121.1", "192.168.0.1", "127.0.0.2"};
		String[] value02 = {"192.168.0.2", "127.0.0.2"};
		
		rules.put(key01, value01);
		rules.put(key02, value02);
		
		int index = 0;
		int sizeList = 0;
		boolean cotain = false;
		boolean result = false;
		String[] listIp = {""};
		
		List<GrantedAuthority> grantedAuthoritiesList = Arrays.asList(grantedAuthorities);
		Iterator<? extends GrantedAuthority> it = grantedAuthoritiesList.iterator();
		
		for (String key : rules.keySet()) {
			if(key.equals(it.next().toString())) {
				cotain = true;
				listIp = rules.get(key);
			}
		}
		if (cotain == true ) {
			for (int i = 0; i < listIp.length; i++ ) {
				if(i <= 0) {
				int temp = listIp.length - 1;
				sizeList = temp;
		    }	
				if(listIp[i].equals(remoteAddr)) {
					System.out.println("tem ip");
					result = true;
					System.out.println(remoteAddr);
					break;
				} else if(sizeList == i){
					System.out.println("nao tem ip");
					result = false;
					break;
				}
			}
			System.out.println(cotain + " aqui ");
		} else {			
			result = true;
		}
		return result;
	}

	private void log(String msg, String value){
		System.out.println("\n\n " + msg + " ----------------------------");
		System.out.println(value);
		System.out.println(" -------------------------------------------");
	}
}

