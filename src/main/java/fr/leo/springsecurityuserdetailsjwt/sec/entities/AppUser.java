package fr.leo.springsecurityuserdetailsjwt.sec.entities;

import java.util.ArrayList;
import java.util.Collection;

import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.ManyToMany;

import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity @Data @AllArgsConstructor @NoArgsConstructor
public class AppUser {

	@Id @ GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;
	private String username;
	@JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
	private String password;
	
	// une 3ème table "user/role" va etre creer !
	// Lorsque on charge un user, on aura ses roles : du coup il est preferable d'instancier la collection
	@ManyToMany(fetch = FetchType.EAGER)
	private Collection<AppRole> appRoles =  new ArrayList<>()  ;
}
