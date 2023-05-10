package fr.leo.springsecurityuserdetailsjwt.sec.filters;

import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;

import fr.leo.springsecurityuserdetailsjwt.util.JWTUtil;
import lombok.AllArgsConstructor;

@AllArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
	
	// Objet mis à disposition par SpringSecurity !
	private AuthenticationManager  authenticationManager;
	
	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException {
		System.out.println("attemptAuthentication");
		// Ici les données sont envoyées dans la requete.
		// Si les données sont envoyées au format json, bien sur il faut faire autrement !
		String username = request.getParameter("username");
		String password = request.getParameter("password");
		System.out.println(username);
		System.out.println(password);
		UsernamePasswordAuthenticationToken authenticationToken = 
					new UsernamePasswordAuthenticationToken(username, password);

		// authenticate() c'est elle qui va déclencher l'opération d'authentification.
		// authenticate() c'est elle qui va faire appel à UserDetailService,
		//  il appelle la méthode qui va vers la bdd, recupere le user/passord/role, ...
		return  authenticationManager.authenticate(authenticationToken);
	}
	
	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response,
			FilterChain chain, Authentication authResult) throws IOException, ServletException {
		System.out.println("successfulAuthentication"); 
		
		/* SpringSecurity, il vous transmet un objet "authResult" dans lequel il y a le 
		    résulat de l'authentification, le résultat du 1er flitre !
		  Dans l'objet "authResult", il y a le résultat de l'authentication !			 
		 */
		
		/* Cette méthode retourne un objet de type Object. Ce n'est pas générique !
		   "User" : c'est une classe de Spring !
		   "Principal" : c'est l'utilisateur authentifié, il contient username et le roles,
	          ce sont les informations dont j'ai besoin pour générer le token.	
	        Donc maintenant on a l'utilisateur qui s'est authentifié !	 
		*/		
		User user = (User) authResult.getPrincipal(); 
		
		/* Maintenant on va génerer le JWT !
		   Pour cela il faut intégrer dans le pom.xml, la librairie : "auth0 jwt maven" !
			<dependency>
    			<groupId>com.auth0</groupId>
    			<artifactId>java-jwt</artifactId>
    			<version>3.11.0</version>
			</dependency>
		 */
		
		/* Pour genérer la signature du token , il faut choisir
		    entre hmac(asymetric) et rsa(symetric)
		    Il faut donner en paramètre, la clé
		 */
		Algorithm algo1 = Algorithm.HMAC256( JWTUtil.SECRET );
		/* Maintenant on génère le JWT
		   Le jwt, se compose de 3 parties : le header, le payload, et la signature.
		*/
		String jwtAccesToken = JWT.create()
				.withSubject(user.getUsername())
				.withExpiresAt(new Date(System.currentTimeMillis() +JWTUtil.EXPIRE_ACCESS_TOKEN))// millisecondes : 30 minutes
				.withIssuer(request.getRequestURI().toString()) 
				.withClaim("roles", user.getAuthorities() // ici les claims privés 
						.stream()
						.map(e->e.getAuthority())
						.collect(Collectors.toList()))
				.sign(algo1); // ici on créer la signature ! 
		
		// Maintenant, on envoie jeton jwt au client, dans un header !
		//  response.setHeader("Authorization", jwtAccesToken);	
		
		/* CI DESSOUS JE CREER UN NOUVEAU TOKEN DE RENOUVELLEMENT !
		   Il a une expiration plus longue ! En général : 10 jours, 30 jours ,...
		   Dans ce token on ne met pas les informations relatives à l'acces ,
		    comme par exemple, les 'roles' !
		 */
		String jwtRefreshToken = JWT.create()
				.withSubject(user.getUsername())
				.withExpiresAt(new Date(System.currentTimeMillis() + JWTUtil.EXPIRE_REFRESH_TOKEN ))// millisecondes : 5 minutes
				.withIssuer(request.getRequestURI().toString())				
				.sign(algo1); // ici on créer la signature !
		
		/* On envoit le refresh token dans le corps de la réponse.
		   En fait on met les 2 tokens ( access et refresh ) dans une hashMap,
		     cad un tableau clé-valeur qui sera convertit en un objet json !
		     Et cet objet json sera envoyé dans le corps de la réponse .
		     Mais on aurait également put utiliser 2 headers "authorization"
			  et "refresh-token", mais ce n'est pas pratique !
		 */
		Map<String, String> idToken = new HashMap<>();
		idToken.put("access-token", jwtAccesToken);
		idToken.put("refresh-token", jwtRefreshToken);
		
		// Maintenant on n'envoit plus dans un header,
		//  mais on envoit l'objet au format json dans le corps de la réponse, avec Jackson :
		//  => new ObjectMapper() de jackson !
		response.setContentType("application/json");
		new ObjectMapper().writeValue(response.getOutputStream(), idToken);	

		//super.successfulAuthentication(request, response, chain, authResult);
	}
}
