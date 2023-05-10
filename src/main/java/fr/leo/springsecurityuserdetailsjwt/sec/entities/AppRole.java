package fr.leo.springsecurityuserdetailsjwt.sec.entities;
/*
 * On les nomme AppRole car dans SpringSecurity il y a deja 
 *  une classe Role et une classe User !
 */

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity @Data @AllArgsConstructor @NoArgsConstructor
public class AppRole {
	
	@Id @GeneratedValue(strategy = GenerationType.IDENTITY )
	private Long id;
	private String roleName; // on a une association unidirectionnelle. 
							 // Inutile de connaitre l'ensemble des utilisateur pour un role donné
}
