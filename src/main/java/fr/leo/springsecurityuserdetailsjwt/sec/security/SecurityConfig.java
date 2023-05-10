	package fr.leo.springsecurityuserdetailsjwt.sec.security;

import java.util.ArrayList;
import java.util.Collection;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import fr.leo.springsecurityuserdetailsjwt.sec.entities.AppUser;
import fr.leo.springsecurityuserdetailsjwt.sec.filters.JwtAuthenticationFilter;
import fr.leo.springsecurityuserdetailsjwt.sec.filters.JwtAuthorizationFilter;
import fr.leo.springsecurityuserdetailsjwt.sec.service.AccountService;
import fr.leo.springsecurityuserdetailsjwt.sec.service.UserDetailsServiceImpl;
import lombok.AllArgsConstructor;

@Configuration // C'est une classe de configuration
@EnableWebSecurity
@AllArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter { 
	
	private UserDetailsServiceImpl userDetailsService;
	
	// Ici on spécifie quels sont les utilisateurs qui ont le droit d'acceder
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {	
		
		 	/* La méthode ci dessous, attend comme parametre,
			   un objet qui implémente l'interface "UserDetailsService" !!!
			*/
			auth.userDetailsService( userDetailsService );	
	}
	
	// Ici on spécifie les droits d'accés
	@Override
	protected void configure(HttpSecurity http) throws Exception {		
		http.csrf().disable();
		http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
		http.headers().frameOptions().disable();
		http.authorizeRequests().antMatchers("/h2-console/**","/refreshToken/**").permitAll();
		// http.formLogin();
		//http.authorizeRequests().antMatchers(HttpMethod.POST , "/users/**" ).hasAuthority("ADMIN");
		//http.authorizeRequests().antMatchers(HttpMethod.GET , "/users/**" ).hasAuthority("USER"); 
		http.authorizeRequests().anyRequest().authenticated(); 	

		/*
		   Ci dessous, on ajoute les filtres pour JWT
		   La méthode JwtAuthenticationFilter() prend en parametre un objet de type "AuthenticationManager" !		    
		   Or notre classe hérite de la classe "WebSecurityConfigurerAdapter" .
		   Et dans cette classe,
		    il y a une méthode "authenticationManagerBean()" qui retourne un tel objet !	
		    
		     UsernamePasswordAuthenticationFilter.class <= c'est le type du filtre
		 */
		http.addFilter(new JwtAuthenticationFilter(authenticationManagerBean()));
		http.addFilterBefore( new JwtAuthorizationFilter() , UsernamePasswordAuthenticationFilter.class );
	}
	
	@Bean // Maintenant dans le contexte vous avez un objet "authenticationManager".Pas obligatoire !
	@Override 
	public AuthenticationManager authenticationManagerBean() throws Exception {
		return super.authenticationManagerBean();
	} 
}
